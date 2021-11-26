from cklib.logging import log
import yaml
from cklib.baseplugin import BaseActionPlugin
from cklib.args import ArgumentParser
from cklib.core.query import CoreGraph
from cklib.utils import parse_delta, delta_to_str
from typing import Dict


class TagValidatorPlugin(BaseActionPlugin):
    action = "pre_cleanup_plan"

    def __init__(self):
        super().__init__()
        if ArgumentParser.args.tagvalidator_config:
            self.config = TagValidatorConfig(
                config_file=ArgumentParser.args.tagvalidator_config
            )
            self.config.read()

    def bootstrap(self) -> bool:
        return ArgumentParser.args.tagvalidator_config is not None

    def do_action(self, data: Dict) -> None:
        log.info("Tag Validator called")
        self.config.read()

        cg = CoreGraph()

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
            if node.protected or node._ckcore_query_tag != query_tag:
                continue
            update_node_tag = False
            max_expiration = (
                self.config["accounts"]
                .get(cloud.id, {})
                .get(account.id, {})
                .get("expiration")
            )
            max_expiration_str = delta_to_str(max_expiration)
            node_expiration_str = node.tags.get("expiration")
            try:
                node_expiration = parse_delta(node_expiration_str)
            except (AssertionError, ValueError):
                log_msg = (
                    f"Invalid expiration tag value {node_expiration_str}"
                    f" - updating tag to {max_expiration_str}"
                )
                node.log(log_msg)
                log.error(
                    f"{log_msg} on {node.rtdname} in {cloud.rtdname}"
                    f" {account.rtdname} {region.rtdname}"
                )
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
                    f"query id({node._ckcore_id}) | tag update --nowait expiration {max_expiration_str}"
                )
        cg.patch_nodes(graph)
        for command in commands:
            if ArgumentParser.args.tagvalidator_dry_run:
                log.debug(f"Tag validator dry run - not executing: {command}")
                continue
            for response in cg.execute(command):
                log.debug(f"Response: {response}")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--tagvalidator-config",
            help="Path to Tag Validator Config",
            default=None,
            dest="tagvalidator_config",
        )
        arg_parser.add_argument(
            "--tagvalidator-dry-run",
            help="Tag Validator Dry Run",
            dest="tagvalidator_dry_run",
            action="store_true",
            default=False,
        )


class TagValidatorConfig(dict):
    def __init__(self, *args, config_file: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.config_file = config_file

    def read(self) -> bool:
        if not self.config_file:
            log.error(
                "Attribute config_file is not set on TagValidatorConfig() instance"
            )
            return False

        with open(self.config_file) as config_file:
            config = yaml.load(config_file, Loader=yaml.FullLoader)
        if self.validate(config):
            self.update(config)
        return True

    @staticmethod
    def validate(config) -> bool:
        required_sections = ["kinds", "accounts"]
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Section '{section}' not found in config")

        if not isinstance(config["kinds"], list) or len(config["kinds"]) == 0:
            raise ValueError("Error in 'kinds' section")

        if not isinstance(config["accounts"], dict) or len(config["accounts"]) == 0:
            raise ValueError("Error in 'accounts' section")

        default_expiration = config.get("default", {}).get("expiration")
        if default_expiration is not None:
            default_expiration = parse_delta(default_expiration)

        for cloud_id, account in config["accounts"].items():
            for account_id, account_data in account.items():
                if "name" not in account_data:
                    raise ValueError(
                        f"Missing 'name' for account '{cloud_id}/{account_id}"
                    )
                if "expiration" in account_data:
                    account_data["expiration"] = parse_delta(account_data["expiration"])
                else:
                    if default_expiration is None:
                        raise ValueError(
                            f"Missing 'expiration' for account '{cloud_id}/{account_id}'"
                            "and no default expiration defined"
                        )
                    account_data["expiration"] = default_expiration
        return True
