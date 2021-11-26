import yaml
from cklib.baseplugin import BaseActionPlugin
from cklib.logging import log
from cklib.core.query import CoreGraph
from cklib.graph.export import node_from_dict
from cklib.args import ArgumentParser
from cklib.utils import parse_delta, delta_to_str
from typing import Dict


class CleanupUntaggedPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def __init__(self):
        super().__init__()
        if ArgumentParser.args.cleanup_untagged_config:
            self.config = CleanupUntaggedConfig(
                config_file=ArgumentParser.args.cleanup_untagged_config
            )
            self.config.read()  # initial read to ensure config format is valid

    def bootstrap(self) -> bool:
        return ArgumentParser.args.cleanup_untagged_config is not None

    def do_action(self, data: Dict) -> None:
        log.debug("Cleanup Untagged called")
        cg = CoreGraph()

        self.config.read()  # runtime read in case config file was updated since last run
        tags_part = (
            'not(has_key(reported.tags, ["' + '", "'.join(self.config["tags"]) + '"]))'
        )
        kinds_part = 'reported.kind in ["' + '", "'.join(self.config["kinds"]) + '"]'
        account_parts = []
        for cloud_id, account in self.config["accounts"].items():
            for account_id, account_data in account.items():
                age = delta_to_str(account_data.get("age"))
                account_part = (
                    f'(metadata.ancestors.cloud.id == "{cloud_id}" and '
                    f'metadata.ancestors.account.id == "{account_id}" and '
                    f"reported.age > {age})"
                )
                account_parts.append(account_part)
        accounts_part = "(" + " or ".join(account_parts) + ")"
        exclusion_part = "metadata.protected == false and metadata.phantom == false and metadata.cleaned == false"
        required_tags = ", ".join(self.config["tags"])
        reason = (
            f"Missing one or more of required tags {required_tags}"
            " and age more than threshold"
        )
        command = f'query {exclusion_part} and {kinds_part} and {tags_part} and {accounts_part} | clean "{reason}"'
        for node_data in cg.execute(command):
            node = node_from_dict(node_data)
            log.debug(
                f"Marking {node.rtdname} with age {node.age} for cleanup for"
                f" missing one or more of tags: {required_tags}"
            )

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup-untagged-config",
            help="Path to Cleanup Untagged Plugin Config",
            default=None,
            dest="cleanup_untagged_config",
        )


class CleanupUntaggedConfig(dict):
    def __init__(self, *args, config_file: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.config_file = config_file

    def read(self) -> bool:
        if not self.config_file:
            log.error(
                "Attribute config_file is not set on CleanupUntaggedConfig() instance"
            )
            return False

        with open(self.config_file) as config_file:
            config = yaml.load(config_file, Loader=yaml.FullLoader)
        if self.validate(config):
            self.update(config)
        return True

    @staticmethod
    def validate(config) -> bool:
        required_sections = ["tags", "kinds", "accounts"]
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Section '{section}' not found in config")

        if not isinstance(config["tags"], list) or len(config["tags"]) == 0:
            raise ValueError("Error in 'tags' section")

        if not isinstance(config["kinds"], list) or len(config["kinds"]) == 0:
            raise ValueError("Error in 'kinds' section")

        if not isinstance(config["accounts"], dict) or len(config["accounts"]) == 0:
            raise ValueError("Error in 'accounts' section")

        default_age = config.get("default", {}).get("age")
        if default_age is not None:
            default_age = parse_delta(default_age)

        for cloud_id, account in config["accounts"].items():
            for account_id, account_data in account.items():
                if "name" not in account_data:
                    raise ValueError(
                        f"Missing 'name' for account '{cloud_id}/{account_id}"
                    )
                if "age" in account_data:
                    account_data["age"] = parse_delta(account_data["age"])
                else:
                    if default_age is None:
                        raise ValueError(
                            f"Missing 'age' for account '{cloud_id}/{account_id}' and no default age defined'"
                        )
                    account_data["age"] = default_age
        return True
