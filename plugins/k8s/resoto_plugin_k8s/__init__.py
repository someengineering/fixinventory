import logging
import multiprocessing
from concurrent import futures
from concurrent.futures import Executor
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, Any, Type, Optional, List, Iterator, Tuple

import resotolib.logger
import resotolib.proc
from kubernetes.client import ApiException
from kubernetes.client import Configuration

from resoto_plugin_k8s.base import K8sApiClient, K8sClient, K8sConfigFile
from resoto_plugin_k8s.collector import KubernetesCollector
from resoto_plugin_k8s.base import K8sConfig
from resoto_plugin_k8s.deferred_edges import create_deferred_edges
from resotolib.args import ArgumentParser, Namespace
from resotolib.baseplugin import BaseCollectorPlugin, BaseDetectCollectorPlugin
from resotolib.baseresources import BaseManagedKubernetesCluster
from resotolib.config import Config, RunningConfig
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph

log = logging.getLogger("resoto.plugins.k8s")


class KubernetesCollectorPlugin(BaseDetectCollectorPlugin):
    cloud = "k8s"

    def __init__(self, k8s_config: Optional[K8sConfig] = None, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.k8s_config = k8s_config
        # once defined, it will be set by the worker
        self.core_feedback: Optional[CoreFeedback] = None

    def collect(self, **kwargs: Any) -> None:
        log.debug("plugin: Kubernetes collecting resources")
        assert self.core_feedback, "core_feedback is not set"

        if self.k8s_config:
            log.info("Do not use the worker configuration, but the dynamically passed config!")
        k8s: K8sConfig = self.k8s_config or Config.k8s
        with TemporaryDirectory() as tmpdir:
            cluster_access = k8s.cluster_access_configs(tmpdir, self.core_feedback)

            if len(cluster_access) == 0:
                log.warning("Kubernetes plugin enabled, but no clusters configured. Ignore.")
                return

            max_workers = len(cluster_access) if len(cluster_access) < k8s.pool_size else k8s.pool_size
            pool_args: Dict[str, Any] = {"max_workers": max_workers}
            if k8s.fork_process:
                pool_args["mp_context"] = multiprocessing.get_context("spawn")
                pool_args["initializer"] = resotolib.proc.collector_initializer
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
                    self.send_account_graph(cluster_graph)

    @staticmethod
    def detect_collects(graph: Graph, temp_dir: Path) -> Iterator[Tuple[Type[BaseCollectorPlugin], Dict[str, Any]]]:
        configs: List[K8sConfigFile] = []
        for node in graph.nodes:
            if isinstance(node, BaseManagedKubernetesCluster) and node.kubeconfig is not None:
                path = temp_dir / node.chksum
                with open(path, "w") as f:
                    f.write(node.kubeconfig)
                configs.append(K8sConfigFile(str(path.resolve().absolute())))
        if len(configs) > 0:
            yield KubernetesCollectorPlugin, dict(k8s_config=K8sConfig(config_files=configs))

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
            create_deferred_edges(kc.graph)
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
