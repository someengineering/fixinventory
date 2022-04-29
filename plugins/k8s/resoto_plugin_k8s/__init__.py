import resotolib.logger
import multiprocessing
import resotolib.proc
from concurrent import futures
from typing import Optional, Dict
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.args import ArgumentParser
from argparse import Namespace
from resotolib.config import Config, RunningConfig
from resotolib.graph import Graph
from kubernetes import client
from .config import K8sConfig
from .utils import k8s_config
from .collector import KubernetesCollector
from .resources.cluster import KubernetesCluster


log = resotolib.logger.getLogger("resoto." + __name__)


class KubernetesCollectorPlugin(BaseCollectorPlugin):
    cloud = "k8s"

    def collect(self) -> None:
        log.debug("plugin: Kubernetes collecting resources")

        clusters = k8s_config()
        if len(clusters) == 0:
            return

        max_workers = (
            len(clusters)
            if len(clusters) < Config.k8s.pool_size
            else Config.k8s.pool_size
        )
        pool_args = {"max_workers": max_workers}
        if Config.k8s.fork_process:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = resotolib.proc.initializer
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
        cluster_id: str,
        cluster_config: client.Configuration,
        args: Namespace = None,
        running_config: RunningConfig = None,
    ) -> Optional[Dict]:
        """Collects an individual Kubernetes Cluster.

        Is being called in collect() and either run within a thread or a spawned
        process. Depending on whether `k8s.fork_process` was specified or not.

        Because the spawned process does not inherit any of our memory or file
        descriptors we are passing the already parsed `args` Namespace() to this
        method.
        """
        cluster = KubernetesCluster(cluster_id, {})
        collector_name = f"k8s_{cluster.id}"
        resotolib.proc.set_thread_name(collector_name)

        if args is not None:
            ArgumentParser.args = args
        if running_config is not None:
            Config.running_config.apply(running_config)

        log.debug(f"Starting new collect process for {cluster.rtdname}")

        try:
            kc = KubernetesCollector(cluster, cluster_config)
            kc.collect()
        except client.exceptions.ApiException as e:
            if e.reason == "Unauthorized":
                log.error(f"Unable to authenticate with {cluster.rtdname}")
            else:
                log.exception(
                    f"An unhandled error occurred while collecting {cluster.rtdname}"
                )
        except Exception:
            log.exception(
                f"An unhandled error occurred while collecting {cluster.rtdname}"
            )
        else:
            return kc.graph

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(K8sConfig)
