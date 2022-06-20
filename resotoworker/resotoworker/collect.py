import multiprocessing
import resotolib.proc
from time import time
from concurrent import futures
from resotolib.baseplugin import BaseCollectorPlugin, BasePostCollectPlugin
from resotolib.baseresources import GraphRoot
from resotolib.graph import Graph, sanitize
from resotolib.logger import log, setup_logger
from resotolib.args import ArgumentParser
from argparse import Namespace
from typing import List, Optional, Callable
from resotolib.config import Config, RunningConfig

TaskId = str


class Collector:
    def __init__(self, send_to_resotocore: Callable[[Graph, TaskId], None], config: Config) -> None:
        self._send_to_resotocore = send_to_resotocore
        self._config = config

    def collect_and_send(
        self,
        collectors: List[BaseCollectorPlugin],
        post_collectors: List[BasePostCollectPlugin],
        task_id: str,
    ) -> None:
        def collect(collectors: List[BaseCollectorPlugin]) -> Graph:
            graph = Graph(root=GraphRoot("root", {}))

            max_workers = (
                len(collectors)
                if len(collectors) < self._config.resotoworker.pool_size
                else self._config.resotoworker.pool_size
            )
            if max_workers == 0:
                log.error("No workers configured or no collector plugins loaded - skipping collect")
                return
            pool_args = {"max_workers": max_workers}
            if self._config.resotoworker.fork_process:
                pool_args["mp_context"] = multiprocessing.get_context("spawn")
                pool_args["initializer"] = resotolib.proc.initializer
                pool_executor = futures.ProcessPoolExecutor
                collect_args = {
                    "args": ArgumentParser.args,
                    "running_config": self._config.running_config,
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

        collected = collect(collectors)

        for post_collector_class in post_collectors:
            instance = post_collector_class()
            collected = instance.post_collect(collected)

        self._send_to_resotocore(collected, task_id)


def collect_plugin_graph(
    collector_plugin: BaseCollectorPlugin,
    args: Namespace = None,
    running_config: RunningConfig = None,
) -> Optional[Graph]:
    try:
        collector: BaseCollectorPlugin = collector_plugin()
        collector_name = f"collector_{collector.cloud}"
        resotolib.proc.set_thread_name(collector_name)

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
                log.error(f"Plugin {collector.cloud} did not finish collection" " - ignoring plugin results")
                return None
            if not collector.graph.is_dag_per_edge_type():
                log.error(f"Graph of plugin {collector.cloud} is not acyclic" " - ignoring plugin results")
                return None
            log.info(f"Collector of plugin {collector.cloud} finished in {elapsed:.4f}s")
            return collector.graph
        else:
            log.error(f"Plugin {collector.cloud} timed out - discarding plugin graph")
            return None
    except Exception as e:
        log.exception(f"Unhandled exception in {collector_plugin}: {e} - ignoring plugin")
        return None
