from networkx import DiGraph
from resotolib.args import ArgumentParser
from resotolib.graph import Graph
from resotolib.baseresources import BaseResource, EdgeType
from resotolib.graph.graph_extensions import dependent_node_iterator
from resotolib.utils import ordinal
from concurrent.futures import ThreadPoolExecutor
from prometheus_client import Summary
from resotolib.logging import log

metrics_cleanup = Summary("resoto_cleanup_seconds", "Time it took the cleanup() method")


class Cleaner:
    def __init__(self, graph: Graph) -> None:
        self.graph = graph

    @metrics_cleanup.time()
    def cleanup(self) -> None:
        if not ArgumentParser.args.cleanup:
            log.error(
                (
                    "Cleanup called but --cleanup flag not provided at startup"
                    " - ignoring call"
                )
            )
            return

        log.info("Running cleanup")
        delete_graph = DiGraph(self.graph.edge_type_subgraph(EdgeType.delete))
        for node in list(delete_graph.nodes):
            if not node.clean:
                delete_graph.remove_node(node)
        for node in self.graph.nodes:
            if node.clean and node not in delete_graph:
                delete_graph.add_node(node)
        cleanup_nodes = list(delete_graph.nodes)

        for node in cleanup_nodes:
            log.debug(f"Adding {node.rtdname} to cleanup plan")

        with ThreadPoolExecutor(
            max_workers=ArgumentParser.args.cleanup_pool_size,
            thread_name_prefix="pre_cleaner",
        ) as executor:
            executor.map(self.pre_clean, cleanup_nodes)

        parallel_pass_num = 1
        for nodes in dependent_node_iterator(delete_graph):
            log.debug(
                f"Cleaning {len(nodes)} nodes in {ordinal(parallel_pass_num)} pass"
            )
            with ThreadPoolExecutor(
                max_workers=ArgumentParser.args.cleanup_pool_size,
                thread_name_prefix="cleaner",
            ) as executor:
                executor.map(self.clean, nodes)
            parallel_pass_num += 1

    def pre_clean(self, node: BaseResource) -> None:
        if not hasattr(node, "pre_delete"):
            return

        log_prefix = f"Resource {node.rtdname} is marked for removal"
        if ArgumentParser.args.cleanup_dry_run:
            log.debug(
                f"{log_prefix}, not calling pre cleanup method because of dry run flag"
            )
            return

        log.debug(f"{log_prefix}, calling pre cleanup method")
        try:
            node.pre_cleanup(self.graph)
        except Exception:
            log.exception(
                (
                    "An exception occurred when running resource pre cleanup on"
                    f" {node.rtdname}"
                )
            )

    def clean(self, node: BaseResource) -> None:
        log_prefix = f"Resource {node.rtdname} is marked for removal"
        if ArgumentParser.args.cleanup_dry_run:
            log.debug(
                f"{log_prefix}, not calling cleanup method because of dry run flag"
            )
            return

        log.debug(f"{log_prefix}, calling cleanup method")
        try:
            node.cleanup(self.graph)
        except Exception:
            log.exception(
                f"An exception occurred when running resource cleanup on {node.rtdname}"
            )

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup",
            help="Enable cleanup of resources (default: False)",
            dest="cleanup",
            action="store_true",
            default=False,
        )
        arg_parser.add_argument(
            "--cleanup-pool-size",
            help="Cleanup thread pool size (default: 10)",
            dest="cleanup_pool_size",
            default=10,
            type=int,
        )
        arg_parser.add_argument(
            "--cleanup-dry-run",
            help="Cleanup dry run (default: False)",
            dest="cleanup_dry_run",
            action="store_true",
            default=False,
        )
