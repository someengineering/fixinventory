from cklib.baseplugin import BaseActionPlugin
from cklib.logging import log
from cklib.core.query import CoreGraph
from cklib.graph import Graph
from cklib.baseresources import BaseVolume
from cklib.args import ArgumentParser
from cklib.utils import parse_delta
from typing import Dict


class CleanupVolumesPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def bootstrap(self) -> bool:
        if ArgumentParser.args.cleanup_volumes:
            try:
                self.age = parse_delta(ArgumentParser.args.cleanup_volumes_age)
                log.debug(f"Volume Cleanup Plugin Age {self.age}")
            except ValueError:
                log.exception(
                    f"Error while parsing Volume Cleanup Age {ArgumentParser.args.volclean_age}"
                )
            else:
                return True
        return False

    def do_action(self, data: Dict) -> None:
        cg = CoreGraph()

        query = "is(volume) and volume_status == available <-[0:]->"
        graph = cg.graph(query)
        self.vpc_cleanup(graph)
        cg.patch_nodes(graph)

    def volumes_cleanup(self, graph: Graph):
        log.info("Volume Cleanup called")
        for node in graph.nodes:
            if (
                isinstance(node, BaseVolume)
                and node.volume_status == "available"
                and node.age > self.age
                and node.last_access > self.age
                and node.last_update > self.age
            ):
                cloud = node.cloud(graph)
                account = node.account(graph)
                region = node.region(graph)
                log.debug(
                    (
                        f"Found available volume {node.dname} in cloud {cloud.name} account {account.dname} "
                        f"region {region.name} with age {node.age}. Last update was {node.last_update} ago "
                        f"and last access {node.last_access} ago both of which is longer than {self.age} "
                        f"- setting to be cleaned"
                    )
                )
                node.clean = True

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup-volumes",
            help="Cleanup unused Volumes (default: False)",
            dest="cleanup_volumes",
            action="store_true",
            default=False,
        )
        arg_parser.add_argument(
            "--cleanup-volumes-age",
            help="Cleanup unused Volumes Age (default: 14 days)",
            default="14 days",
            dest="cleanup_volumes_age",
        )
