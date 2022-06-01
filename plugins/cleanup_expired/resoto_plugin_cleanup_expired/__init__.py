from resotolib.baseplugin import BaseActionPlugin
from resotolib.logger import log
from resotolib.core.search import CoreGraph
from resotolib.config import Config
from .config import CleanupExpiredConfig
from typing import Dict


class CleanupExpiredPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def bootstrap(self):
        return Config.plugin_cleanup_expired.enabled

    def do_action(self, data: Dict) -> None:
        log.debug("Cleanup Expired called")
        cg = CoreGraph(tls_data=self.tls_data)
        command = 'query /metadata.expires < "@NOW@" | clean "Resource is expired"'
        for response in cg.execute(command):
            if isinstance(response, Dict) and "type" in response and response["type"] == "node":
                reported = response.get("reported", {})
                kind = reported.get("kind")
                node_id = reported.get("id")
                node_name = reported.get("name")
                age = reported.get("age")
                ancestors = response.get("ancestors", {})
                cloud = ancestors.get("cloud", {}).get("id")
                account = ancestors.get("account", {}).get("id")
                region = ancestors.get("region", {}).get("id")
                dname = node_id if node_id == node_name else f"{node_name} ({node_id})"
                log.debug(
                    f"Marking expired {kind} {dname} with age {age}"
                    f" in cloud {cloud} account {account} region {region}"
                    " for cleanup"
                )
            else:
                log.debug(f"Response: {response}")

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(CleanupExpiredConfig)
