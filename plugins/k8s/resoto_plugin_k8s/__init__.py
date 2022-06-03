import logging
import multiprocessing
from argparse import Namespace
from concurrent import futures
from typing import Optional, Dict

import resotolib.logger
import resotolib.proc
from kubernetes.client import ApiException
from kubernetes.client import Configuration
from resoto_plugin_k8s.collector import KubernetesCollector
from resoto_plugin_k8s.config import K8sConfig
from resoto_plugin_k8s.resources import KubernetesCluster
from resotolib.args import ArgumentParser
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config, RunningConfig
from resotolib.graph import Graph

log = logging.getLogger("resoto.plugins.k8s")


class KubernetesCollectorPlugin(BaseCollectorPlugin):
    cloud = "k8s"

    def collect(self) -> None:
        log.debug("plugin: Kubernetes collecting resources")

        k8s: K8sConfig = Config.k8s
        cluster_access = k8s.cluster_access_configs()

        if len(cluster_access) == 0:
            return

        max_workers = len(cluster_access) if len(cluster_access) < k8s.pool_size else k8s.pool_size
        pool_args = {"max_workers": max_workers}
        if k8s.fork_process:
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
                for cluster_id, cluster_config in cluster_access.items()
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
        cluster_config: Configuration,
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
        resotolib.proc.set_thread_name(f"k8s_{cluster_id}")

        if args is not None:
            ArgumentParser.args = args
        if running_config is not None:
            Config.running_config.apply(running_config)

        log.debug(f"Starting new collect process for {cluster_id}")

        try:
            kc = KubernetesCollector(Config.k8s, cluster_id, cluster_config)
            kc.collect()
        except ApiException as e:
            if e.reason == "Unauthorized":
                log.error(f"Unable to authenticate with {cluster_id}")
            else:
                log.exception(f"An unhandled error occurred while collecting {cluster_id}")
            # TODO: remove raise
            raise
        except Exception as e:
            log.exception(f"An unhandled error occurred while collecting {cluster_id}")
            # TODO: remove raise
            raise
        else:
            return kc.graph

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(K8sConfig)
