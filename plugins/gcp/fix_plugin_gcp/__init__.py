import multiprocessing
from concurrent import futures
from typing import Optional, Dict, Any

import fixlib.proc
from fixlib.args import ArgumentParser
from fixlib.args import Namespace
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.baseresources import Cloud
from fixlib.config import Config, RunningConfig
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph
from fixlib.logger import log, setup_logger
from .collector import GcpProjectCollector
from .config import GcpConfig
from .resources.base import GcpProject
from .utils import Credentials


class GCPCollectorPlugin(BaseCollectorPlugin):
    """Google Cloud Platform fix collector plugin.

    Gets instantiated in fix's Processor thread. The collect() method
    is run during a resource collection loop.
    """

    cloud = "gcp"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.core_feedback: Optional[CoreFeedback] = None

    def collect(self) -> None:
        """Run by fix during the global collect() run.

        This method kicks off code that adds GCP resources to `self.graph`.
        When collect() finishes the parent thread will take `self.graph` and merge
        it with the global production graph.
        """
        log.debug("plugin: GCP collecting resources")
        assert self.core_feedback, "core_feedback is not set"  # will be set by the outer collector plugin
        feedback = self.core_feedback.with_context("gcp")

        cloud = Cloud(id=self.cloud, name="Gcp")

        credentials = Credentials.all(feedback)
        log.debug(f"Found {len(credentials)} GCP projects total")
        if len(Config.gcp.project) > 0:
            for project in list(credentials.keys()):
                if project not in Config.gcp.project:
                    log.debug(f"Skipping project {project} because it is not in the configured projects list")
                    del credentials[project]

        if len(credentials) == 0:
            return

        max_workers = (
            len(credentials) if len(credentials) < Config.gcp.project_pool_size else Config.gcp.project_pool_size
        )
        collect_args = {}
        pool_args = {"max_workers": max_workers}
        pool_executor = futures.ThreadPoolExecutor
        if Config.gcp.fork_process:
            collect_args = {
                "args": ArgumentParser.args,
                "running_config": Config.running_config,
                "credentials": credentials if all(v is None for v in credentials.values()) else None,
            }
            collect_method = collect_in_process
        else:
            collect_method = self.collect_project

        with pool_executor(**pool_args) as executor:
            # noinspection PyTypeChecker
            wait_for = [
                executor.submit(collect_method, project_id, feedback, cloud, **collect_args)
                for project_id in credentials.keys()
            ]
            for future in futures.as_completed(wait_for):
                project_graph = future.result()
                if not isinstance(project_graph, Graph):
                    log.error(f"Skipping invalid project_graph {type(project_graph)}")
                    continue
                self.send_account_graph(project_graph)
                del project_graph

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
        fixlib.proc.set_thread_name(collector_name)

        if args is not None:
            ArgumentParser.args = args
            setup_logger("fixworker-gcp", force=True, level=getattr(args, "log_level", None))
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
        """Called by fix upon startup to populate the Config store"""
        config.add_config(GcpConfig)


def collect_project_proxy(*args, queue: multiprocessing.Queue, **kwargs) -> None:  # type: ignore
    fixlib.proc.collector_initializer()
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
