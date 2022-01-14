from resotolib.baseplugin import BaseActionPlugin
from resotolib.logging import log
from resotolib.core.query import CoreGraph
from resotolib.args import ArgumentParser
from typing import Dict


class CleanupExpiredPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def bootstrap(self):
        return ArgumentParser.args.cleanup_expired

    def do_action(self, data: Dict) -> None:
        log.debug("Cleanup Expired called")
        cg = CoreGraph()
        command = 'query metadata.expires < "@NOW@" | clean "Resource is expired"'
        for response in cg.execute(command):
            if (
                isinstance(response, Dict)
                and "type" in response
                and response["type"] == "node"
            ):
                reported = response.get("reported", {})
                kind = reported.get("kind")
                node_id = reported.get("id")
                node_name = reported.get("name")
                age = reported.get("age")
                ancestors = response.get("metadata", {}).get("ancestors", {})
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
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup-expired",
            help="Cleanup expired resources (default: False)",
            dest="cleanup_expired",
            action="store_true",
            default=False,
        )
