from copy import deepcopy

from resotolib.baseplugin import BaseActionPlugin
from resotolib.config import Config
from resotolib.core.model_export import node_from_dict
from resotolib.core.search import CoreGraph
from resotolib.json import value_in_path
from resotolib.logger import log
from resotolib.types import Json
from .config import CleanupUntaggedConfig


class CleanupUntaggedPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def bootstrap(self) -> bool:
        return Config.plugin_cleanup_untagged.enabled is True

    @staticmethod
    def create_command(cfg: Json) -> str:
        tags_part = 'not(has_key(tags, ["' + '", "'.join(cfg["tags"]) + '"]))'
        kinds_part = 'is(["' + '", "'.join(cfg["kinds"]) + '"])'
        account_parts = []
        default_age: str = value_in_path(cfg, ["default", "age"]) or "2h"
        for cloud_id, account in cfg["accounts"].items():
            for account_id, account_data in account.items():
                age = account_data.get("age", default_age)
                account_part = (
                    f'(/ancestors.cloud.id == "{cloud_id}" and '
                    f'/ancestors.account.id == "{account_id}" and '
                    f"age > {age})"
                )
                account_parts.append(account_part)
        accounts_part = "(" + " or ".join(account_parts) + ")"
        exclusion_part = "/metadata.protected == false and /metadata.phantom == false and /metadata.cleaned == false"
        required_tags = ", ".join(cfg["tags"])
        reason = f"Missing one or more of required tags {required_tags}" " and age more than threshold"
        return f'search {exclusion_part} and {kinds_part} and {tags_part} and {accounts_part} | clean "{reason}"'

    def do_action(self, data: Json) -> None:
        log.debug("Cleanup Untagged called")
        cg = CoreGraph(tls_data=self.tls_data)
        cfg: Json = deepcopy(Config.plugin_cleanup_untagged.config)
        command = self.create_command(cfg)
        required_tags = ", ".join(cfg.get("tags", {}))
        for node_data in cg.execute(command):
            node = node_from_dict(node_data)
            log.debug(
                f"Marking {node.rtdname} with age {node.age} for cleanup for"
                f" missing one or more of tags: {required_tags}"
            )

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(CleanupUntaggedConfig)
