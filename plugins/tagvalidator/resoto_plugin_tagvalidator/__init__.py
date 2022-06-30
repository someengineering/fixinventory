from copy import deepcopy
from resotolib.logger import log
from resotolib.baseplugin import BaseActionPlugin
from resotolib.config import Config
from .config import TagValidatorConfig
from resotolib.core.search import CoreGraph
from resotolib.durations import parse_duration, duration_str
from typing import Dict


class TagValidatorPlugin(BaseActionPlugin):
    action = "pre_cleanup_plan"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = None

    def bootstrap(self) -> bool:
        return Config.plugin_tagvalidator.enabled

    def do_action(self, data: Dict) -> None:
        log.info("Tag Validator called")
        Config.plugin_tagvalidator.validate(Config.plugin_tagvalidator)
        self.config = deepcopy(Config.plugin_tagvalidator.config)

        cg = CoreGraph(tls_data=self.tls_data)

        query_tag = "tagvalidate"
        exclusion_part = "metadata.protected == false and metadata.phantom == false and metadata.cleaned == false"
        tags_part = "has_key(reported.tags, expiration)"
        kinds_part = 'reported.kind in ["' + '", "'.join(self.config["kinds"]) + '"]'
        account_parts = []
        for cloud_id, account in self.config["accounts"].items():
            for account_id in account.keys():
                account_part = (
                    f'(metadata.ancestors.cloud.id == "{cloud_id}" and '
                    f'metadata.ancestors.account.id == "{account_id}")'
                )
                account_parts.append(account_part)
        accounts_part = "(" + " or ".join(account_parts) + ")"
        query = f"{exclusion_part} and {kinds_part} and {tags_part} and {accounts_part} #{query_tag} <-[0:]-"

        graph = cg.graph(query)
        commands = []
        for node in graph.nodes:
            cloud = node.cloud(graph)
            account = node.account(graph)
            region = node.region(graph)
            if node.protected or node._resotocore_query_tag != query_tag:
                continue
            update_node_tag = False
            max_expiration = self.config["accounts"].get(cloud.id, {}).get(account.id, {}).get("expiration")
            max_expiration_str = duration_str(max_expiration, down_to_unit="min")
            node_expiration_str = node.tags.get("expiration")
            try:
                node_expiration = parse_duration(node_expiration_str)
            except (AssertionError, ValueError):
                log_msg = (
                    f"Invalid expiration tag value {node_expiration_str}" f" - updating tag to {max_expiration_str}"
                )
                node.log(log_msg)
                log.error(f"{log_msg} on {node.rtdname} in {cloud.rtdname}" f" {account.rtdname} {region.rtdname}")
                update_node_tag = True
            else:
                if max_expiration < node_expiration:
                    log_msg = (
                        f"Current expiration tag value {node_expiration_str} is larger"
                        f" than {max_expiration_str} - updating tag"
                    )
                    node.log(log_msg)
                    log.error(f"{log_msg} on {node.rtdname}")
                    update_node_tag = True
            if update_node_tag:
                commands.append(
                    f"query id({node._resotocore_id}) | tag update --nowait expiration {max_expiration_str}"
                )
        cg.patch_nodes(graph)
        for command in commands:
            if Config.plugin_tagvalidator.dry_run:
                log.debug(f"Tag validator dry run - not executing: {command}")
                continue
            for response in cg.execute(command):
                log.debug(f"Response: {response}")

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(TagValidatorConfig)
