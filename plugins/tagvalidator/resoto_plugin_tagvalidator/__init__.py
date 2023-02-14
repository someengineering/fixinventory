from copy import deepcopy
from typing import Optional, Any

from resotolib.baseplugin import BaseActionPlugin
from resotolib.baseresources import BaseResource
from resotolib.config import Config
from resotolib.core.search import CoreGraph
from resotolib.durations import parse_duration
from resotolib.graph import Graph
from resotolib.json import value_in_path
from resotolib.logger import log
from resotolib.types import Json
from .config import TagValidatorConfig


class TagValidatorPlugin(BaseActionPlugin):
    action = "pre_cleanup_plan"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def bootstrap(self) -> bool:
        return Config.plugin_tagvalidator.enabled is True

    @staticmethod
    def invalid_expiration(cfg: Json, graph: Graph, node: BaseResource, default_expiration: str) -> Optional[str]:
        """
        Return the expiration value to set on the node if it is invalid, or None if it is valid.
        """
        cloud = node.cloud(graph)
        account = node.account(graph)
        region = node.region(graph)
        max_expiration_str: str = (
            value_in_path(cfg, ["accounts", cloud.id, account.id, "expiration"]) or default_expiration
        )

        max_expiration = parse_duration(max_expiration_str)
        node_expiration_str = node.tags.get("expiration")
        # If the node has no expiration tag - it is fine
        if node_expiration_str is None:
            return None
        try:
            node_expiration = parse_duration(node_expiration_str)
        except Exception:
            log_msg = f"Invalid expiration tag value {node_expiration_str}" f" - updating tag to {max_expiration_str}"
            node.log(log_msg)
            log.error(f"{log_msg} on {node.rtdname} in {cloud.rtdname}" f" {account.rtdname} {region.rtdname}")
            return max_expiration_str
        else:
            if max_expiration < node_expiration:
                log_msg = (
                    f"Current expiration tag value {node_expiration_str} is larger"
                    f" than {max_expiration_str} - updating tag"
                )
                node.log(log_msg)
                log.error(f"{log_msg} on {node.rtdname}")
                return max_expiration_str
        return None

    def do_action(self, data: Json) -> None:
        log.info("Tag Validator called")
        Config.plugin_tagvalidator.validate(Config.plugin_tagvalidator)
        cfg: Json = deepcopy(Config.plugin_tagvalidator.config)
        cg = CoreGraph(tls_data=self.tls_data)
        query_tag = "tagvalidate"
        exclusion_part = "metadata.protected == false and metadata.phantom == false and metadata.cleaned == false"
        tags_part = "has_key(reported.tags, expiration)"
        kinds_part = 'reported.kind in ["' + '", "'.join(cfg["kinds"]) + '"]'

        account_parts = []
        for cloud_id, account in cfg["accounts"].items():
            for account_id in account.keys():
                account_part = (
                    f'(metadata.ancestors.cloud.id == "{cloud_id}" and '
                    f'metadata.ancestors.account.id == "{account_id}")'
                )
                account_parts.append(account_part)
        accounts_part = "(" + " or ".join(account_parts) + ")"
        query = f"{exclusion_part} and {kinds_part} and {tags_part} and {accounts_part} #{query_tag} <-[0:]-"

        default_expiration: str = value_in_path(cfg, ["default", "expiration"]) or "24h"
        graph = cg.graph(query)
        commands = []
        for node in graph.nodes:
            if node.protected or node._resotocore_query_tag != query_tag:
                continue
            if max_expiration := self.invalid_expiration(cfg, graph, node, default_expiration):
                commands.append(f"query id({node._resotocore_id}) | tag update --nowait expiration {max_expiration}")
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
