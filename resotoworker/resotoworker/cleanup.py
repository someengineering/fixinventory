from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Type, Dict

from networkx import DiGraph  # type: ignore
from prometheus_client import Summary

from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import BaseResource, EdgeType
from resotolib.config import Config
from resotolib.core.actions import CoreFeedback
from resotolib.core.ca import TLSData
from resotolib.core.search import CoreGraph
from resotolib.graph import Graph
from resotolib.graph.graph_extensions import dependent_node_iterator
from resotolib.logger import log
from resotolib.utils import ordinal

metrics_cleanup = Summary("resoto_cleanup_seconds", "Time it took the cleanup() method")


def cleanup(
    config: Config,
    plugins: Dict[str, Type[BaseCollectorPlugin]],
    core_feedback: CoreFeedback,
    tls_data: Optional[TLSData] = None,
) -> None:
    """Run resource cleanup"""

    log.info("Running cleanup")

    cg = CoreGraph(tls_data=tls_data)

    search_filter = ""
    if Config.resotoworker.collector and len(Config.resotoworker.collector) > 0:
        clouds = '["' + '", "'.join(Config.resotoworker.collector) + '"]'
        search_filter = f"and /ancestors.cloud.reported.id in {clouds} "
    search = (
        f"/desired.clean == true and /metadata.cleaned != true"
        f" and /metadata.protected!=true {search_filter}<-default,delete[0:]->"
    )

    graph = cg.graph(search)
    cleaner = Cleaner(graph, core_feedback)
    cleaner.cleanup(config, plugins)
    cg.patch_nodes(graph)


class Cleaner:
    def __init__(self, graph: Graph, feedback: CoreFeedback) -> None:
        self.graph = graph
        self.feedback = feedback

    @metrics_cleanup.time()  # type: ignore
    def cleanup(self, config: Config, plugins: Dict[str, Type[BaseCollectorPlugin]]) -> None:
        if not Config.resotoworker.cleanup:
            log.debug("Cleanup called but resotoworker.cleanup not configured" " - ignoring call")
            return

        log.info("Running cleanup")
        # create a subgraph of all the nodes that have a delete edge
        delete_graph = DiGraph(self.graph.edge_type_subgraph(EdgeType.delete))
        # from that graph delete all the nodes not marked for cleanup
        for node in list(delete_graph.nodes):
            if not node.clean:
                delete_graph.remove_node(node)
        # add all the nodes that are supposed to be cleaned
        # but do not have a delete edge so weren't part of the
        # subgraph
        for node in self.graph.nodes:
            if node.clean and node not in delete_graph:
                delete_graph.add_node(node)
        cleanup_nodes: List[BaseResource] = list(delete_graph.nodes)

        for node in cleanup_nodes:
            log.debug(f"Adding {node.rtdname} to cleanup plan")

        log.debug(f"Sending {len(cleanup_nodes)} nodes to pre-cleanup pool")
        with ThreadPoolExecutor(
            max_workers=Config.resotoworker.cleanup_pool_size,
            thread_name_prefix="pre_cleaner",
        ) as executor:
            executor.map(
                lambda node: self.pre_clean(config, plugins, node),
                cleanup_nodes,
            )

        log.debug(f"Running parallel cleanup on {len(cleanup_nodes)} nodes")
        parallel_pass_num = 1
        for nodes in dependent_node_iterator(delete_graph):
            log.debug(f"Cleaning {len(nodes)} nodes in {ordinal(parallel_pass_num)} pass")
            with ThreadPoolExecutor(
                max_workers=Config.resotoworker.cleanup_pool_size,
                thread_name_prefix="cleaner",
            ) as executor:
                executor.map(lambda node: self.clean(config, plugins, node), nodes)
            parallel_pass_num += 1

    def pre_clean(self, config: Config, plugins: Dict[str, Type[BaseCollectorPlugin]], node: BaseResource) -> None:
        if not hasattr(node, "pre_delete") or not hasattr(node, "pre_delete_resource"):
            return

        log_prefix = f"Resource {node.rtdname} is marked for removal"
        if Config.resotoworker.cleanup_dry_run:
            log.info(f"{log_prefix}, not calling pre cleanup method because of dry run flag")
            return

        plugin = plugins.get(node.cloud().id)
        if plugin is None:
            raise ValueError(f"No plugin found for cloud {node.cloud().id}")

        log.info(f"{log_prefix}, calling pre cleanup method")
        try:
            plugin.pre_cleanup(config, node, self.graph)
        except Exception as ex:
            self.feedback.with_context(plugin.cloud).error(
                f"An exception occurred when running resource pre cleanup on {node.rtdname}: {ex}", log
            )

    def clean(self, config: Config, plugins: Dict[str, Type[BaseCollectorPlugin]], node: BaseResource) -> None:
        log_prefix = f"Resource {node.rtdname} is marked for removal"
        if Config.resotoworker.cleanup_dry_run:
            log.info(f"{log_prefix}, not calling cleanup method because of dry run flag")
            return

        plugin = plugins.get(node.cloud().id)
        if plugin is None:
            raise ValueError(f"No plugin found for cloud {node.cloud().id}")

        log.info(f"{log_prefix}, calling cleanup method")
        try:
            plugin.cleanup(config, node, self.graph)
        except Exception as ex:
            self.feedback.with_context(plugin.cloud).error(
                f"An exception occurred when running resource cleanup on {node.rtdname}: {ex}", log
            )
