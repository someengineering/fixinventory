import multiprocessing
import cklib.signal
from concurrent import futures
from ckworker.ckcore import send_to_ckcore
from networkx.algorithms.dag import is_directed_acyclic_graph
from cklib.args import ArgumentParser
from cklib.baseplugin import BaseCollectorPlugin
from cklib.graph import GraphContainer, Graph, sanitize
from cklib.logging import log
from typing import List, Optional


def collect(collectors: List[BaseCollectorPlugin]) -> None:
    graph_container = GraphContainer(cache_graph=False)
    graph = graph_container.graph
    max_workers = (
        len(collectors)
        if len(collectors) < ArgumentParser.args.pool_size
        else ArgumentParser.args.pool_size
    )
    if max_workers == 0:
        log.error(
            "No workers configured or no collector plugins loaded - skipping collect"
        )
        return
    pool_args = {"max_workers": max_workers}
    if ArgumentParser.args.fork:
        pool_args["mp_context"] = multiprocessing.get_context("spawn")
        pool_args["initializer"] = cklib.signal.initializer
        pool_executor = futures.ProcessPoolExecutor
        collect_args = {"args": ArgumentParser.args}
    else:
        pool_executor = futures.ThreadPoolExecutor
        collect_args = {}

    with pool_executor(**pool_args) as executor:
        wait_for = [
            executor.submit(
                collect_plugin_graph,
                collector,
                **collect_args,
            )
            for collector in collectors
        ]
        for future in futures.as_completed(wait_for):
            cluster_graph = future.result()
            if not isinstance(cluster_graph, Graph):
                log.error(f"Skipping invalid cluster_graph {type(cluster_graph)}")
                continue
            graph.merge(cluster_graph)
    sanitize(graph)
    send_to_ckcore(graph)


def collect_plugin_graph(
    collector_plugin: BaseCollectorPlugin, args=None
) -> Optional[Graph]:
    collector: BaseCollectorPlugin = collector_plugin()
    collector_name = f"collector_{collector.cloud}"
    cklib.signal.set_thread_name(collector_name)

    if args is not None:
        ArgumentParser.args = args

    log.debug(f"Starting new collect process for {collector.cloud}")
    collector.start()
    collector.join(ArgumentParser.args.timeout)
    if not collector.is_alive():  # The plugin has finished its work
        if not collector.finished:
            log.error(
                f"Plugin {collector.cloud} did not finish collection"
                " - ignoring plugin results"
            )
            return None
        if not is_directed_acyclic_graph(collector.graph):
            log.error(
                f"Graph of plugin {collector.cloud} is not acyclic"
                " - ignoring plugin results"
            )
            return None
        log.info(f"Collector of plugin {collector.cloud} finished")
        return collector.graph
    else:
        log.error(f"Plugin {collector.cloud} timed out - discarding Plugin graph")
        return None


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--fork",
        help="Use forked process instead of threads (default: False)",
        dest="fork",
        action="store_true",
    )
    arg_parser.add_argument(
        "--pool-size",
        help="Collector Thread/Process Pool Size (default: 5)",
        dest="pool_size",
        default=5,
        type=int,
    )
