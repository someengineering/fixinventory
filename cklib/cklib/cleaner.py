from cklib.args import ArgumentParser
from cklib.graph import Graph
from cklib.baseresources import BaseResource
from cklib.utils import defaultlist
from concurrent.futures import ThreadPoolExecutor
from prometheus_client import Summary
from cklib.logging import log

metrics_cleanup = Summary(
    "cloudkeeper_cleanup_seconds", "Time it took the cleanup() method"
)


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
        cleanup_nodes = [
            node for node in self.graph.nodes() if node.clean and not node.cleaned
        ]
        cleanup_plan = defaultlist(lambda: [])

        for node in cleanup_nodes:
            log.debug(
                (
                    f"Adding {node.rtdname} to cleanup plan with priority"
                    f" {node.max_graph_depth}"
                )
            )
            cleanup_plan[node.max_graph_depth].append(node)

        with ThreadPoolExecutor(
            max_workers=ArgumentParser.args.cleanup_pool_size,
            thread_name_prefix="pre_cleaner",
        ) as executor:
            executor.map(self.pre_clean, cleanup_nodes)

        for nodes in reversed(cleanup_plan):
            with ThreadPoolExecutor(
                max_workers=ArgumentParser.args.cleanup_pool_size,
                thread_name_prefix="cleaner",
            ) as executor:
                executor.map(self.clean, nodes)

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
