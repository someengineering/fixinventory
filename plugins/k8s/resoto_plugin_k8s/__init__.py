import logging
import multiprocessing
from concurrent import futures
from concurrent.futures import Executor
from tempfile import TemporaryDirectory
from typing import Dict, Any, Type, Optional

import resotolib.logger
import resotolib.proc
from kubernetes.client import ApiException
from kubernetes.client import Configuration

from resoto_plugin_k8s.base import K8sApiClient, K8sClient
from resoto_plugin_k8s.collector import KubernetesCollector
from resoto_plugin_k8s.base import K8sConfig
from resotolib.args import ArgumentParser, Namespace
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config, RunningConfig
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph

log = logging.getLogger("resoto.plugins.k8s")


class KubernetesCollectorPlugin(BaseCollectorPlugin):
    cloud = "k8s"

    def __init__(self) -> None:
        super().__init__()
        # once defined, it will be set by the worker
        self.core_feedback: Optional[CoreFeedback] = None

    def collect(self, **kwargs: Any) -> None:
        log.debug("plugin: Kubernetes collecting resources")
        assert self.core_feedback, "core_feedback is not set"

        k8s: K8sConfig = Config.k8s
        with TemporaryDirectory() as tmpdir:
            cluster_access = k8s.cluster_access_configs(tmpdir, self.core_feedback)

            if len(cluster_access) == 0:
                log.warning("Kubernetes plugin enabled, but no clusters configured. Ignore.")
                return

            max_workers = len(cluster_access) if len(cluster_access) < k8s.pool_size else k8s.pool_size
            pool_args: Dict[str, Any] = {"max_workers": max_workers}
            if k8s.fork_process:
                pool_args["mp_context"] = multiprocessing.get_context("spawn")
                pool_args["initializer"] = resotolib.proc.initializer
                pool_executor: Type[Executor] = futures.ProcessPoolExecutor
            else:
                pool_executor = futures.ThreadPoolExecutor

            with pool_executor(**pool_args) as executor:
                wait_for = [
                    executor.submit(
                        self.collect_cluster,
                        cluster_id,
                        cluster_config,
                        ArgumentParser.args,
                        Config.running_config,
                        self.core_feedback.with_context("k8s", cluster_id),
                        **kwargs,
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
        args: Namespace,
        running_config: RunningConfig,
        core_feedback: CoreFeedback,
        **kwargs: Any,
    ) -> Graph:
        """
        Collects an individual Kubernetes Cluster.
        """
        resotolib.proc.set_thread_name(f"k8s_{cluster_id}")

        if args is not None:
            ArgumentParser.args = args
        if running_config is not None:
            Config.running_config.apply(running_config)

        log.debug(f"Starting new collect process for {cluster_id}")

        try:
            k8s_client: K8sClient = kwargs.get("client_factory", K8sApiClient.from_config)(
                cluster_id, cluster_config
            ).with_feedback(core_feedback)
            kc = KubernetesCollector(Config.k8s, k8s_client)
            kc.collect()
        except ApiException as e:
            if e.reason == "Unauthorized":
                core_feedback.error(f"Unable to authenticate with {cluster_id}", log)
            else:
                core_feedback.error(f"An unhandled error occurred while collecting {cluster_id}: {e}", log)
            raise
        except Exception as e:
            core_feedback.error(f"An unhandled error occurred while collecting {cluster_id}: {e}", log)
            raise
        else:
            return kc.graph

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(K8sConfig)
