import cloudkeeper.logging
from cloudkeeper.graph import Graph
from cloudkeeper.args import ArgumentParser
from cloudkeeper.utils import get_resource_attributes
from prometheus_client import Summary
from kubernetes import client
from .resources import KubernetesCluster, KubernetesNamespace, KubernetesPod


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


metrics_collect_namespaces = Summary(
    "cloudkeeper_plugin_k8s_collect_namespaces_seconds",
    "Time it took the collect_namespaces() method",
)
metrics_collect_pods = Summary(
    "cloudkeeper_plugin_k8s_collect_pods_seconds",
    "Time it took the collect_pods() method",
)


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
        self.client = client.CoreV1Api(client.ApiClient(self.config))
        self.root = self.cluster
        self.graph = Graph()
        resource_attr = get_resource_attributes(self.root)
        self.graph.add_node(self.root, label=self.root.name, **resource_attr)

        # Mandatory collectors are always collected regardless of whether
        # they were included by --k8s-collect or excluded by --k8s-no-collect
        self.mandatory_collectors = {
            "namespaces": self.collect_namespaces,
        }

        self.global_collectors = {
            "pods": self.collect_pods,
        }
        self.all_collectors = dict(self.mandatory_collectors)
        self.all_collectors.update(self.global_collectors)

    def collect(self) -> None:
        """Runs the actual resource collection across all resource collectors.

        Resource collectors add their resources to the local `self.graph` graph.
        """
        collectors = set(self.all_collectors.keys())
        if len(ArgumentParser.args.k8s_collect) > 0:
            collectors = set(ArgumentParser.args.k8s_collect).intersection(collectors)
        if len(ArgumentParser.args.k8s_no_collect) > 0:
            collectors = collectors - set(ArgumentParser.args.k8s_no_collect)
        collectors = collectors.union(set(self.mandatory_collectors.keys()))

        log.debug(
            (
                f"Running the following collectors in {self.cluster.rtdname}:"
                f" {', '.join(collectors)}"
            )
        )
        for collector_name, collector in self.mandatory_collectors.items():
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.cluster.rtdname}")
                collector()

        for collector_name, collector in self.global_collectors.items():
            if collector_name in collectors:
                log.info(f"Collecting {collector_name} in {self.cluster.rtdname}")
                collector()

    @metrics_collect_namespaces.time()
    def collect_namespaces(self) -> None:
        ret = self.client.list_namespace(watch=False)
        for r in ret.items:
            namespace = KubernetesNamespace(r.metadata.name, {}, api_response=r)
            self.graph.add_resource(self.root, namespace)

    @metrics_collect_pods.time()
    def collect_pods(self) -> None:
        ret = self.client.list_pod_for_all_namespaces(watch=False)
        for r in ret.items:
            name = r.metadata.name
            namespace = r.metadata.namespace
            status = r.status.phase
            pod = KubernetesPod(name, {}, instance_status=status, api_response=r)
            ns = self.graph.search_first_all(
                {"resource_type": "kubernetes_namespace", "id": namespace}
            )
            parent = self.root
            if ns:
                parent = ns
            self.graph.add_resource(parent, pod)
