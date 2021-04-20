import cloudkeeper.logging
from cloudkeeper.graph import Graph
from cloudkeeper.args import ArgumentParser

from kubernetes import client
from .resources.cluster import KubernetesCluster
from .resources import (
    all_collectors,
    mandatory_collectors,
    global_collectors,
)


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KubernetesCollector:
    """Collects a single Kubernetes Cluster.

    Responsible for collecting all the resources of an individual cluster.
    Builds up its own local graph which is then taken by collect_cluster()
    and merged with the plugin graph.

    This way we can have many instances of KubernetesCollector running in parallel.
    All building up individual graphs which in the end are merged to a final graph
    containing all K8S resources.
    """

    def __init__(
        self, cluster: KubernetesCluster, cluster_config: client.Configuration
    ) -> None:
        """
        Args:
            cluster: The K8S cluster resource object this cluster collector
                is going to collect.
        """
        self.cluster = cluster
        self.config = cluster_config
        self.api_client = client.ApiClient(self.config)
        self.graph = Graph(root=self.cluster)

    def collect(self) -> None:
        """Runs the actual resource collection across all resource collectors.

        Resource collectors add their resources to the local `self.graph` graph.
        """
        collectors = set(all_collectors.keys())
        if len(ArgumentParser.args.k8s_collect) > 0:
            collectors = set(ArgumentParser.args.k8s_collect).intersection(collectors)
        if len(ArgumentParser.args.k8s_no_collect) > 0:
            collectors = collectors - set(ArgumentParser.args.k8s_no_collect)
        collectors = collectors.union(set(mandatory_collectors.keys()))

        log.debug(
            (
                f"Running the following collectors in {self.cluster.rtdname}:"
                f" {', '.join(collectors)}"
            )
        )
        for collector_name, collector in mandatory_collectors.items():
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.cluster.rtdname}")
                collector(self.api_client, self.graph)

        for collector_name, collector in global_collectors.items():
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.cluster.rtdname}")
                collector(self.api_client, self.graph)
