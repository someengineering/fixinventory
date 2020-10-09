import networkx
import multiprocessing
import cloudkeeper.logging
import cloudkeeper.signal
from concurrent import futures
from typing import Dict, Optional
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.args import ArgumentParser
from .resources import GCPProject
from .utils import Credentials
from .collector import GCPProjectCollector

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


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

        projects = Credentials.all()
        if len(ArgumentParser.args.gcp_project) > 0:
            for project in list(projects.keys()):
                if project not in ArgumentParser.args.gcp_project:
                    del projects[project]

        if len(projects) == 0:
            return

        max_workers = (
            len(projects)
            if len(projects) < ArgumentParser.args.gcp_project_pool_size
            else ArgumentParser.args.gcp_project_pool_size
        )
        pool_args = {"max_workers": max_workers}
        if ArgumentParser.args.gcp_fork:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = cloudkeeper.signal.initializer
            pool_executor = futures.ProcessPoolExecutor
            collect_args = {"args": ArgumentParser.args}
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
                for project_id in projects.keys()
            ]
            for future in futures.as_completed(wait_for):
                res = future.result()
                if not isinstance(res, dict):
                    continue
                gpc_root = res.get("root")
                gpc_graph = res.get("graph")
                gpc_project = res.get("project")
                log.debug(
                    (
                        f"Merging graph of project {gpc_project.dname}"
                        f" with {self.cloud} plugin graph"
                    )
                )
                self.graph = networkx.compose(self.graph, gpc_graph)
                self.graph.add_edge(self.root, gpc_root)

    @staticmethod
    def collect_project(project_id: str, args=None) -> Optional[Dict]:
        """Collects an individual project.

        Is being called in collect() and either run within a thread or a spawned
        process. Depending on whether `--gcp-fork` was specified or not.

        Because the spawned process does not inherit any of our memory or file
        descriptors we are passing the already parsed `args` Namespace() to this
        method.
        """
        project = GCPProject(project_id, {})
        collector_name = f"gcp_{project.id}"
        cloudkeeper.signal.set_thread_name(collector_name)

        if args is not None:
            ArgumentParser.args = args

        log.debug(f"Starting new collect process for project {project.dname}")

        try:
            gpc = GCPProjectCollector(project)
            gpc.collect()
        except Exception:
            log.exception(
                f"An unhandled error occurred while collecting {project.rtdname}"
            )
        else:
            return {"root": gpc.root, "graph": gpc.graph, "project": gpc.project}

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
