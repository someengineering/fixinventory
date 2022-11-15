import multiprocessing
from queue import Queue

import resotolib.proc
from time import time
from concurrent import futures
from resotolib.baseplugin import BaseCollectorPlugin, BasePostCollectPlugin
from resotolib.baseresources import GraphRoot
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph, sanitize
from resotolib.logger import log, setup_logger
from resotolib.args import ArgumentParser
from argparse import Namespace
from typing import List, Optional, Callable, Type, Dict, Any
from resotolib.config import Config, RunningConfig
from resotolib.types import Json

TaskId = str


class Collector:
    def __init__(
        self, config: Config, send_to_resotocore: Callable[[Graph, TaskId], None], core_messages: Queue[Json]
    ) -> None:
        self._send_to_resotocore = send_to_resotocore
        self._config = config
        self.core_messages = core_messages

    def collect_and_send(
        self,
        collectors: List[Type[BaseCollectorPlugin]],
        post_collectors: List[Type[BasePostCollectPlugin]],
        task_id: str,
        step_name: str,
    ) -> None:
        core_feedback = CoreFeedback(task_id, step_name, "collect", self.core_messages)

        def collect(collectors: List[Type[BaseCollectorPlugin]]) -> Optional[Graph]:
            graph = Graph(root=GraphRoot(id="root", tags={}))

            max_workers = (
                len(collectors)
                if len(collectors) < self._config.resotoworker.pool_size
                else self._config.resotoworker.pool_size
            )
            if max_workers == 0:
                log.error("No workers configured or no collector plugins loaded - skipping collect")
                return None
            pool_args = {"max_workers": max_workers}
            pool_executor: Type[futures.Executor]
            collect_args: Dict[str, Any]
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
                        core_feedback,
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

        def post_collect(graph: Graph, post_collectors: List[Type[BasePostCollectPlugin]]) -> Graph:
            if len(post_collectors) == 0:
                log.info("No post-collect plugins loaded - skipping")
                return graph
            pool_args: Dict[str, Any] = {"max_workers": 1}
            pool_executor: Type[futures.Executor]
            collect_args: Dict[str, Any] = {}
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

            with pool_executor(**pool_args) as executor:
                for post_collector in post_collectors:
                    future = executor.submit(
                        run_post_collect_plugin, post_collector, graph, core_feedback, **collect_args
                    )
                    try:
                        new_graph = future.result(Config.resotoworker.timeout)
                    except TimeoutError as e:
                        log.exception(f"Unhandled exception in {post_collector}: {e} - ignoring plugin")
                        continue
                    except Exception as e:
                        log.exception(f"Unhandled exception in {post_collector}: {e} - ignoring plugin")
                        continue

                    if new_graph is None:
                        continue
                    graph = new_graph

                sanitize(graph)
                return graph

        collected = collect(collectors)

        if collected:
            collected = post_collect(collected, post_collectors)
            self._send_to_resotocore(collected, task_id)


def run_post_collect_plugin(
    post_collector_plugin: Type[BasePostCollectPlugin],
    graph: Graph,
    core_feedback: CoreFeedback,
    args: Optional[Namespace] = None,
    running_config: Optional[RunningConfig] = None,
) -> Optional[Graph]:
    try:
        post_collector: BasePostCollectPlugin = post_collector_plugin()
        if core_feedback and hasattr(post_collector, "core_feedback"):
            setattr(post_collector, "core_feedback", core_feedback)

        if args is not None:
            ArgumentParser.args = args  # type: ignore
            setup_logger("resotoworker")
        if running_config is not None:
            Config.running_config.apply(running_config)

        log.debug(f"starting new post-collect process for {post_collector.name}")
        start_time = time()
        post_collector.post_collect(graph)
        elapsed = time() - start_time
        if not graph.is_dag_per_edge_type():
            log.error(f"Graph of plugin {post_collector.name} is not acyclic - ignoring plugin results")
            return None
        log.info(f"Collector of plugin {post_collector.name} finished in {elapsed:.4f}s")
        return graph
    except Exception as e:
        log.exception(f"Unhandled exception in {post_collector_plugin}: {e} - ignoring plugin")
        return None


def collect_plugin_graph(
    collector_plugin: Type[BaseCollectorPlugin],
    core_feedback: CoreFeedback,
    args: Optional[Namespace] = None,
    running_config: Optional[RunningConfig] = None,
) -> Optional[Graph]:
    try:
        collector: BaseCollectorPlugin = collector_plugin()
        core_feedback.progress_done(collector.cloud, 0, 1)
        if core_feedback and hasattr(collector, "core_feedback"):
            setattr(collector, "core_feedback", core_feedback)
        collector_name = f"collector_{collector.cloud}"
        resotolib.proc.set_thread_name(collector_name)

        if args is not None:
            ArgumentParser.args = args  # type: ignore
            setup_logger("resotoworker")
        if running_config is not None:
            Config.running_config.apply(running_config)

        log.debug(f"Starting new collect process for {collector.cloud}")
        start_time = time()
        collector.start()
        collector.join(Config.resotoworker.timeout)
        core_feedback.progress_done(collector.cloud, 1, 1)
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
