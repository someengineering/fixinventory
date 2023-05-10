import multiprocessing
from resotolib.args import Namespace
from concurrent import futures
from concurrent.futures import Executor
from typing import Optional, Type, Dict, Any

import resotolib.proc
from resotolib.args import ArgumentParser
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import Cloud
from resotolib.config import Config, RunningConfig
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph
from resotolib.logger import log, setup_logger

# from .collector import GCPProjectCollector
from .project_collector import GcpProjectCollector
from .config import GcpConfig

# from .gcp_resources import GCPProject
from .resources.base import GcpProject
from .utils import Credentials


class GCPCollectorPlugin(BaseCollectorPlugin):
    """Google Cloud Platform resoto collector plugin.

    Gets instantiated in resoto's Processor thread. The collect() method
    is run during a resource collection loop.
    """

    cloud = "gcp"

    def __init__(self) -> None:
        super().__init__()
        self.core_feedback: Optional[CoreFeedback] = None

    def collect(self) -> None:
        """Run by resoto during the global collect() run.

        This method kicks off code that adds GCP resources to `self.graph`.
        When collect() finishes the parent thread will take `self.graph` and merge
        it with the global production graph.
        """
        log.debug("plugin: GCP collecting resources")
        assert self.core_feedback, "core_feedback is not set"  # will be set by the outer collector plugin

        cloud = Cloud(id=self.cloud, name="Gcp")

        credentials = Credentials.all()
        if len(Config.gcp.project) > 0:
            for project in list(credentials.keys()):
                if project not in Config.gcp.project:
                    del credentials[project]

        if len(credentials) == 0:
            return

        max_workers = (
            len(credentials) if len(credentials) < Config.gcp.project_pool_size else Config.gcp.project_pool_size
        )
        pool_args = {"max_workers": max_workers}
        if Config.gcp.fork_process:
            #     pool_args["mp_context"] = multiprocessing.get_context("spawn")
            #     pool_args["initializer"] = resotolib.proc.initializer
            #     pool_executor: Type[Executor] = futures.ProcessPoolExecutor
            collect_args = {
                "args": ArgumentParser.args,
                "running_config": Config.running_config,
                "credentials": credentials if all(v is None for v in credentials.values()) else None,
            }
            collect_method = collect_in_process
        else:
            #     pool_executor = futures.ThreadPoolExecutor
            collect_args = {}
            collect_method = self.collect_project
        pool_executor = futures.ThreadPoolExecutor

        with pool_executor(**pool_args) as executor:  # type: ignore
            wait_for = [
                executor.submit(
                    collect_method,
                    project_id,
                    self.core_feedback.with_context("gcp"),
                    cloud,
                    **collect_args,  # type: ignore
                )
                for project_id in credentials.keys()
            ]
            for future in futures.as_completed(wait_for):
                project_graph = future.result()
                if not isinstance(project_graph, Graph):
                    log.error(f"Skipping invalid project_graph {type(project_graph)}")
                    continue
                self.graph.merge(project_graph)

    @staticmethod
    def collect_project(
        project_id: str,
        core_feedback: CoreFeedback,
        cloud: Cloud,
        args: Optional[Namespace] = None,
        running_config: Optional[RunningConfig] = None,
        credentials: Optional[Dict[str, Any]] = None,
    ) -> Optional[Graph]:
        """Collects an individual project.

        Is being called in collect() and either run within a thread or a spawned
        process. Depending on whether `gcp.fork_process` was specified or not.

        Because the spawned process does not inherit any of our memory or file
        descriptors we are passing the already parsed `args` Namespace() to this
        method.
        """
        project = GcpProject(id=project_id, name=project_id)
        collector_name = f"gcp_{project_id}"
        resotolib.proc.set_thread_name(collector_name)

        if args is not None:
            ArgumentParser.args = args
            setup_logger("resotoworker-gcp", force=True, level=getattr(args, "log_level", None))
        if running_config is not None:
            Config.running_config.apply(running_config)

        if credentials is not None:
            Credentials._credentials = credentials
            Credentials._initialized = True

        log.debug(f"Starting new collect process for project {project.dname}")

        try:
            core_feedback.progress_done(project_id, 0, 1)
            gpc = GcpProjectCollector(Config.gcp, cloud, project, core_feedback)
            gpc.collect()
            core_feedback.progress_done(project_id, 1, 1)
        except Exception as ex:
            core_feedback.with_context("gcp", project_id).error(f"Failed to collect project: {ex}", log)
            return None
        else:
            return gpc.graph

    @staticmethod
    def add_config(config: Config) -> None:
        """Called by resoto upon startup to populate the Config store"""
        config.add_config(GcpConfig)


def collect_project_proxy(*args, queue: multiprocessing.Queue, **kwargs) -> None:  # type: ignore
    resotolib.proc.initializer()
    queue.put(GCPCollectorPlugin.collect_project(*args, **kwargs))


def collect_in_process(*args, **kwargs) -> Optional[Graph]:  # type: ignore
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    kwargs["queue"] = queue
    process = ctx.Process(target=collect_project_proxy, args=args, kwargs=kwargs)
    process.start()
    graph = queue.get()
    process.join()
    return graph  # type: ignore
