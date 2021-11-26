from cklib.baseplugin import BaseActionPlugin
from cklib.logging import log
from cklib.core.query import CoreGraph
from cklib.args import ArgumentParser
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
