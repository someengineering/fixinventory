import multiprocessing
from resotolib.logging import log, setup_logger
import resotolib.signal
from concurrent import futures
from typing import Dict, Optional
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.graph import Graph
from resotolib.args import ArgumentParser
from .resources import GCPProject
from .utils import Credentials
from .collector import GCPProjectCollector


class GCPCollectorPlugin(BaseCollectorPlugin):
    """Google Cloud Platform Cloudkeeper collector plugin.

    Gets instantiated in Cloudkeeper's Processor thread. The collect() method
    is run during a resource collection loop.
    """

    cloud = "gcp"

    def collect(self) -> None:
        """Run by Cloudkeeper during the global collect() run.

        This method kicks off code that adds GCP resources to `self.graph`.
        When collect() finishes the parent thread will take `self.graph` and merge
        it with the global production graph.
        """
        log.debug("plugin: GCP collecting resources")

        credentials = Credentials.all()
        if len(ArgumentParser.args.gcp_project) > 0:
            for project in list(credentials.keys()):
                if project not in ArgumentParser.args.gcp_project:
                    del credentials[project]

        if len(credentials) == 0:
            return

        max_workers = (
            len(credentials)
            if len(credentials) < ArgumentParser.args.gcp_project_pool_size
            else ArgumentParser.args.gcp_project_pool_size
        )
        pool_args = {"max_workers": max_workers}
        if ArgumentParser.args.gcp_fork:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = resotolib.signal.initializer
            pool_executor = futures.ProcessPoolExecutor
            collect_args = {
                "args": ArgumentParser.args,
                "credentials": credentials
                if all(v is None for v in credentials.values())
                else None,
            }
        else:
            pool_executor = futures.ThreadPoolExecutor
            collect_args = {}

        with pool_executor(**pool_args) as executor:
            wait_for = [
                executor.submit(
                    self.collect_project,
                    project_id,
                    **collect_args,
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
    def collect_project(project_id: str, args=None, credentials=None) -> Optional[Dict]:
        """Collects an individual project.

        Is being called in collect() and either run within a thread or a spawned
        process. Depending on whether `--gcp-fork` was specified or not.

        Because the spawned process does not inherit any of our memory or file
        descriptors we are passing the already parsed `args` Namespace() to this
        method.
        """
        project = GCPProject(project_id, {})
        collector_name = f"gcp_{project.id}"
        resotolib.signal.set_thread_name(collector_name)

        if args is not None:
            ArgumentParser.args = args
            setup_logger("resotoworker-gcp")

        if credentials is not None:
            Credentials._credentials = credentials
            Credentials._initialized = True

        log.debug(f"Starting new collect process for project {project.dname}")

        try:
            gpc = GCPProjectCollector(project)
            gpc.collect()
        except Exception:
            log.exception(
                f"An unhandled error occurred while collecting {project.rtdname}"
            )
        else:
            return gpc.graph

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Called by Cloudkeeper upon startup to populate the ArgumentParser"""
        arg_parser.add_argument(
            "--gcp-service-account",
            help="GCP Service Account File",
            dest="gcp_service_account",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--gcp-project",
            help="GCP Project",
            dest="gcp_project",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--gcp-collect",
            help="GCP services to collect (default: all)",
            dest="gcp_collect",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--gcp-no-collect",
            help="GCP services not to collect",
            dest="gcp_no_collect",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--gcp-project-pool-size",
            help="GCP Project Thread Pool Size (default: 5)",
            dest="gcp_project_pool_size",
            default=5,
            type=int,
        )
        arg_parser.add_argument(
            "--gcp-fork",
            help="GCP use forked process instead of threads (default: False)",
            dest="gcp_fork",
            action="store_true",
        )
