from copy import deepcopy
from resotolib.baseplugin import BaseActionPlugin
from resotolib.durations import duration_str
from resotolib.logger import log
from resotolib.core.search import CoreGraph
from resotolib.core.model_export import node_from_dict
from resotolib.config import Config
from .config import CleanupUntaggedConfig
from typing import Dict


class CleanupUntaggedPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def bootstrap(self) -> bool:
        return Config.plugin_cleanup_untagged.enabled

    def do_action(self, data: Dict) -> None:
        log.debug("Cleanup Untagged called")
        cg = CoreGraph(tls_data=self.tls_data)
        config = deepcopy(Config.plugin_cleanup_untagged.config)

        tags_part = 'not(has_key(tags, ["' + '", "'.join(config["tags"]) + '"]))'
        kinds_part = 'is(["' + '", "'.join(config["kinds"]) + '"])'
        account_parts = []
        for cloud_id, account in config["accounts"].items():
            for account_id, account_data in account.items():
                age = duration_str(account_data.get("age"), down_to_unit="min")
                account_part = (
                    f'(/ancestors.cloud.id == "{cloud_id}" and '
                    f'/ancestors.account.id == "{account_id}" and '
                    f"age > {age})"
                )
                account_parts.append(account_part)
        accounts_part = "(" + " or ".join(account_parts) + ")"
        exclusion_part = "/metadata.protected == false and /metadata.phantom == false and /metadata.cleaned == false"
        required_tags = ", ".join(config["tags"])
        reason = f"Missing one or more of required tags {required_tags}" " and age more than threshold"
        command = f'query {exclusion_part} and {kinds_part} and {tags_part} and {accounts_part} | clean "{reason}"'
        for node_data in cg.execute(command):
            node = node_from_dict(node_data)
            log.debug(
                f"Marking {node.rtdname} with age {node.age} for cleanup for"
                f" missing one or more of tags: {required_tags}"
            )

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(CleanupUntaggedConfig)
