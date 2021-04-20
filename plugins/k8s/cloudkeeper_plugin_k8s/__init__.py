import cloudkeeper.logging
import multiprocessing
import cloudkeeper.signal
from concurrent import futures
from typing import Optional, Dict
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.args import ArgumentParser
from cloudkeeper.graph import Graph
from kubernetes import client
from .utils import k8s_config
from .collector import KubernetesCollector
from .resources.cluster import KubernetesCluster


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KubernetesCollectorPlugin(BaseCollectorPlugin):
    cloud = "k8s"

    def collect(self) -> None:
        log.debug("plugin: Kubernetes collecting resources")

        clusters = k8s_config()
        if len(clusters) == 0:
            return

        max_workers = (
            len(clusters)
            if len(clusters) < ArgumentParser.args.k8s_pool_size
            else ArgumentParser.args.k8s_pool_size
        )
        pool_args = {"max_workers": max_workers}
        if ArgumentParser.args.k8s_fork:
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
                    self.collect_cluster,
                    cluster_id,
                    cluster_config,
                    **collect_args,
                )
                for cluster_id, cluster_config in clusters.items()
            ]
            for future in futures.as_completed(wait_for):
                cluster_graph = future.result()
                if not isinstance(cluster_graph, Graph):
                    log.error(f"Skipping invalid cluster_graph {type(cluster_graph)}")
                    continue
                self.graph.merge(cluster_graph)

    @staticmethod
    def collect_cluster(
        cluster_id: str, cluster_config: client.Configuration, args=None
    ) -> Optional[Dict]:
        """Collects an individual Kubernetes Cluster.

        Is being called in collect() and either run within a thread or a spawned
        process. Depending on whether `--k8s-fork` was specified or not.

        Because the spawned process does not inherit any of our memory or file
        descriptors we are passing the already parsed `args` Namespace() to this
        method.
        """
        cluster = KubernetesCluster(cluster_id, {})
        collector_name = f"k8s_{cluster.id}"
        cloudkeeper.signal.set_thread_name(collector_name)

        if args is not None:
            ArgumentParser.args = args

        log.debug(f"Starting new collect process for {cluster.rtdname}")

        try:
            kc = KubernetesCollector(cluster, cluster_config)
            kc.collect()
        except Exception:
            log.exception(
                f"An unhandled error occurred while collecting {cluster.rtdname}"
            )
        else:
            return kc.graph

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--k8s-context",
            help="Kubernetes Context Name",
            dest="k8s_context",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--k8s-config",
            help="Kubernetes Config File",
            dest="k8s_config",
            type=str,
            default=None,
        )
        arg_parser.add_argument(
            "--k8s-cluster",
            help="Kubernetes Cluster Name",
            dest="k8s_cluster",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--k8s-apiserver",
            help="Kubernetes API server",
            dest="k8s_apiserver",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--k8s-token",
            help="Kubernetes Token",
            dest="k8s_token",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--k8s-cacert",
            help="Kubernetes CA Certificate",
            dest="k8s_cacert",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--k8s-collect",
            help="Kubernetes objects to collect (default: all)",
            dest="k8s_collect",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--k8s-no-collect",
            help="Kubernetes objects not to collect",
            dest="k8s_no_collect",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--k8s-pool-size",
            help="Kubernetes Thread Pool Size (default: 5)",
            dest="k8s_pool_size",
            default=5,
            type=int,
        )
        arg_parser.add_argument(
            "--k8s-fork",
            help="Kubernetes use forked process instead of threads (default: False)",
            dest="k8s_fork",
            action="store_true",
        )
