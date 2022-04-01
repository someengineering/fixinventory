import multiprocessing
import resotolib.signal
from time import time
from concurrent import futures
from resotoworker.resotocore import send_to_resotocore
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import GraphRoot
from resotolib.graph import Graph, sanitize
from resotolib.logging import log, setup_logger
from resotolib.args import ArgumentParser
from argparse import Namespace
from typing import List, Optional
from resotolib.config import Config, RunningConfig
from resotolib.core.ca import TLSData


def collect_and_send(
    collectors: List[BaseCollectorPlugin], tls_data: Optional[TLSData] = None
) -> None:
    def collect(collectors: List[BaseCollectorPlugin]) -> Graph:
        graph = Graph(root=GraphRoot("root", {}))

        max_workers = (
            len(collectors)
            if len(collectors) < Config.resotoworker.pool_size
            else Config.resotoworker.pool_size
        )
        if max_workers == 0:
            log.error(
                "No workers configured or no collector plugins loaded - skipping collect"
            )
            return
        pool_args = {"max_workers": max_workers}
        if Config.resotoworker.fork:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = resotolib.signal.initializer
            pool_executor = futures.ProcessPoolExecutor
            collect_args = {
                "args": ArgumentParser.args,
                "running_config": Config.running_config,
            }
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
        return graph

    send_to_resotocore(collect(collectors), tls_data=tls_data)


def collect_plugin_graph(
    collector_plugin: BaseCollectorPlugin,
    args: Namespace = None,
    running_config: RunningConfig = None,
) -> Optional[Graph]:
    collector: BaseCollectorPlugin = collector_plugin()
    collector_name = f"collector_{collector.cloud}"
    resotolib.signal.set_thread_name(collector_name)

    if args is not None:
        ArgumentParser.args = args
        setup_logger("resotoworker")
    if running_config is not None:
        Config.running_config.apply(running_config)

    log.debug(f"Starting new collect process for {collector.cloud}")
    start_time = time()
    collector.start()
    collector.join(Config.resotoworker.timeout)
    elapsed = time() - start_time
    if not collector.is_alive():  # The plugin has finished its work
        if not collector.finished:
            log.error(
                f"Plugin {collector.cloud} did not finish collection"
                " - ignoring plugin results"
            )
            return None
        if not collector.graph.is_dag_per_edge_type():
            log.error(
                f"Graph of plugin {collector.cloud} is not acyclic"
                " - ignoring plugin results"
            )
            return None
        log.info(f"Collector of plugin {collector.cloud} finished in {elapsed:.4f}s")
        return collector.graph
    else:
        log.error(f"Plugin {collector.cloud} timed out - discarding Plugin graph")
        return None
