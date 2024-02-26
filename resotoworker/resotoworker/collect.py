from __future__ import annotations

import multiprocessing
import threading
from argparse import Namespace
from concurrent import futures
from concurrent.futures import Executor, Future
from multiprocessing.managers import SyncManager
from queue import Queue
from shutil import rmtree
from tempfile import mkdtemp
from threading import Lock
from time import time
from types import TracebackType
from typing import List, Optional, Type, Set

import resotolib.proc
from resotolib.args import ArgumentParser
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import GraphRoot, BaseCloud, BaseAccount, BaseResource
from resotolib.config import Config, RunningConfig
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph, sanitize, GraphMergeKind
from resotolib.logger import log, setup_logger
from resotolib.types import Json
from resotoworker.exceptions import DuplicateMessageError
from resotoworker.resotocore import Resotocore

TaskId = str


class CollectRun:
    def __init__(
        self,
        config: Config,
        resotocore: Resotocore,
        core_messages: Queue[Json],
        collectors: List[Type[BaseCollectorPlugin]],
        task_data: Json,
    ) -> None:
        self.config = config
        self.resotocore = resotocore
        self.task_data = task_data
        self.collectors = collectors
        self.task_id = task_data["task"]
        self.step_name = task_data["step"]
        self.core_feedback = CoreFeedback(self.task_id, self.step_name, "collect", core_messages)
        self.mp_manager = SyncManager(ctx=multiprocessing.get_context("spawn"))
        self.graph_queue: Optional[Queue[Optional[Graph]]] = None
        self.graph_sender_threads: List[threading.Thread] = []
        self.tempdir = mkdtemp(prefix=f"resoto-{self.task_id}", dir=config.resotoworker.tempdir)
        self.pool_executor: Optional[Executor] = None
        self.futures_to_wait_for: List[Future[bool]] = []

    def __enter__(self) -> CollectRun:
        log.debug("Create multi process manager")
        self.mp_manager.start(initializer=resotolib.proc.increase_limits)
        graph_queue = self.mp_manager.Queue()
        self.graph_queue = graph_queue
        for i in range(self.config.resotoworker.graph_sender_pool_size):
            graph_sender_t = threading.Thread(
                target=self.__graph_sender,
                args=(graph_queue, self.task_id, self.tempdir),
                name=f"graph_sender_{i}",
            )
            graph_sender_t.daemon = True
            graph_sender_t.start()
            self.graph_sender_threads.append(graph_sender_t)
        pool_executor_class: Type[Executor]
        pool_args = {"max_workers": max(len(self.collectors), self.config.resotoworker.pool_size)}
        if self.config.resotoworker.fork_process:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = resotolib.proc.initializer
            pool_executor_class = futures.ProcessPoolExecutor
        else:
            pool_executor_class = futures.ThreadPoolExecutor

        self.pool_executor = pool_executor_class(**pool_args)
        self.pool_executor.__enter__()
        return self

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> Optional[bool]:
        log.debug("Telling graph sender threads to end")
        if self.graph_queue:
            for _ in self.graph_sender_threads:
                self.graph_queue.put(None)
            for t in self.graph_sender_threads:
                t.join(300)
        if self.pool_executor:
            log.debug("Stopping executor")
            self.pool_executor.__exit__(exc_type, exc_val, exc_tb)
        self.mp_manager.shutdown()
        if not self.config.resotoworker.debug_dump_json:
            rmtree(self.tempdir, ignore_errors=True)
        return None

    def collect(self) -> None:
        assert self.graph_queue, "No GraphQueue - CollectRun started?"
        self.__collect_all(self.collectors, self.config.resotoworker.graph_merge_kind)
        while self.futures_to_wait_for or not self.graph_queue.empty():
            for future in futures.as_completed(self.futures_to_wait_for.copy()):
                self.futures_to_wait_for.remove(future)
        log.info("Collect done. tearing down.")

    def __graph_sender(self, graph_queue: Queue[Optional[Graph]], task_id: TaskId, tempdir: str) -> None:
        log.debug("Waiting for collector graphs")
        start_time = time()
        while True:
            # wait for the next element to come in
            collector_graph = graph_queue.get()
            if collector_graph is None:
                run_time = time() - start_time
                log.debug(f"Ending graph sender thread for task id {task_id} after {run_time} seconds")
                break

            # signal to the outside world, that we are busy
            import_graph: Future[bool] = Future()
            self.futures_to_wait_for.append(import_graph)

            # Create and sanitize the graph
            graph = Graph(root=GraphRoot(id="root", tags={}))
            graph.merge(collector_graph)
            del collector_graph
            sanitize(graph)

            # Create a human-readable description of the graph
            graph_info = ""
            assert isinstance(graph.root, BaseResource)
            for cloud in graph.successors(graph.root):
                if isinstance(cloud, BaseCloud):
                    graph_info += f" {cloud.kdname}"
                for account in graph.successors(cloud):
                    if isinstance(account, BaseAccount):
                        graph_info += f" {account.kdname}"
            log.info(f"Received collector graph for{graph_info}")

            # Make sure the graph is not cyclic
            if (cycle := graph.find_cycle()) is not None:
                desc = ", ".join, [f"{key.edge_type}: {key.src.kdname}-->{key.dst.kdname}" for key in cycle]
                log.error(f"Graph of {graph_info} is not acyclic - ignoring. Cycle {desc}")
                continue

            # send it to core
            try:
                self.resotocore.send_to_resotocore(graph, task_id, tempdir)
            except Exception as e:
                log.error(f"Error sending graph of {graph_info} to resotocore: {e}")

            # delete the graph
            del graph

            # mark work as done
            import_graph.set_result(True)

    def __collect_all(self, collectors: List[Type[BaseCollectorPlugin]], merge_kind: GraphMergeKind) -> None:
        assert self.graph_queue, "No GraphQueue - CollectRun started?"
        assert self.pool_executor, "No Executor - CollectRun started?"
        for collector in collectors:
            self.futures_to_wait_for.append(
                self.pool_executor.submit(
                    collect_plugin_graph,
                    collector,
                    self.core_feedback,
                    self.graph_queue,
                    merge_kind,
                    task_data=self.task_data,
                    args=ArgumentParser.args,
                    running_config=self.config.running_config,
                )
            )


class Collector:
    def __init__(self, config: Config, resotocore: Resotocore, core_messages: Queue[Json]) -> None:
        self.resotocore = resotocore
        self.config = config
        self.core_messages = core_messages
        self.processing: Set[str] = set()
        self.processing_lock = Lock()

    def collect_and_send(
        self,
        collectors: List[Type[BaseCollectorPlugin]],
        task_data: Json,
    ) -> None:
        task_id = task_data["task"]
        step_name = task_data["step"]
        processing_id = f"{task_id}:{step_name}"
        try:
            with self.processing_lock:
                if processing_id in self.processing:
                    raise DuplicateMessageError(f"Already processing {processing_id} - ignoring message")
                self.processing.add(processing_id)
            with CollectRun(self.config, self.resotocore, self.core_messages, collectors, task_data) as run:
                self.resotocore.create_graph_and_update_model(tempdir=run.tempdir)
                run.collect()
        finally:
            with self.processing_lock:
                if processing_id in self.processing:
                    self.processing.remove(processing_id)


def collect_plugin_graph(
    collector_plugin: Type[BaseCollectorPlugin],
    core_feedback: CoreFeedback,
    graph_queue: Queue[Optional[Graph]],
    graph_merge_kind: GraphMergeKind,
    task_data: Json,
    args: Optional[Namespace] = None,
    running_config: Optional[RunningConfig] = None,
) -> bool:
    try:
        collector: BaseCollectorPlugin = collector_plugin(
            graph_queue=graph_queue, graph_merge_kind=graph_merge_kind, task_data=task_data
        )
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
                return False
            log.info(f"Collector of plugin {collector.cloud} finished in {elapsed:.4f}s")
            return True
        else:
            log.error(f"Plugin {collector.cloud} timed out - discarding plugin graph")
            return False
    except Exception as e:
        log.exception(f"Unhandled exception in {collector_plugin}: {e} - ignoring plugin")
        return False
