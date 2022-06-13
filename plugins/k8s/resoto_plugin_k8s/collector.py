import logging

from kubernetes.client import Configuration

from resoto_plugin_k8s.client import K8sClient
from resoto_plugin_k8s.config import K8sConfig
from resoto_plugin_k8s.resources import (
    KubernetesCluster,
    KubernetesNode,
    KubernetesResource,
    KubernetesService,
    all_k8s_resources_by_k8s_name,
    KubernetesClusterInfo,
    KubernetesNamespace,
    GraphBuilder,
)
from resotolib.baseresources import EdgeType
from resotolib.graph import ByNodeId, BySearchCriteria, Graph

log = logging.getLogger("resoto." + __name__)


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
        self, k8s_config: K8sConfig, cluster_id: str, cluster_config: Configuration, client: K8sClient
    ) -> None:
        self.k8s_config = k8s_config
        self.cluster_id = cluster_id
        self.config = cluster_config
        self.client = client
        self.graph = Graph(root=self.cluster())
        self.builder = GraphBuilder(self.graph)

    def cluster(self) -> KubernetesCluster:
        v = self.client.version()
        return KubernetesCluster(
            id=self.cluster_id,
            name=self.config.host,
            cluster_info=KubernetesClusterInfo(v.get("major", ""), v.get("minor", ""), v.get("platform", "")),
        )

    def do_droplet_to_node(self, resource: KubernetesResource) -> None:
        if isinstance(resource, KubernetesNode):
            if (ns := resource.node_spec) and (pid := ns.provider_id) and (pid.startswith("digitalocean://")):
                _, droplet_id = pid.split("digitalocean://")
                self.graph.add_deferred_edge(
                    BySearchCriteria(f"is(digitalocean_droplet) and reported.id={droplet_id}"),
                    ByNodeId(resource.chksum),
                )

    def do_lb_to_service(self, resource: KubernetesResource) -> None:
        if isinstance(resource, KubernetesService):
            if lb_id := resource.tags.get("kubernetes.digitalocean.com/load-balancer-id"):
                self.graph.add_deferred_edge(
                    BySearchCriteria(f"is(digitalocean_load_balancer) and reported.id=s{lb_id}"),
                    ByNodeId(resource.chksum),
                )

    def collect(self) -> None:
        kind_to_handler = {"Node": self.do_droplet_to_node, "Service": self.do_lb_to_service}
        # collect all resources
        for resource in self.client.apis():
            known = all_k8s_resources_by_k8s_name.get(resource.kind)
            if known and self.k8s_config.is_allowed(resource.kind):
                for res, source in self.client.list_resources(resource, known):
                    self.graph.add_node(res, source=source)
                    if handler := kind_to_handler.get(resource.kind):
                        handler(res)
            else:
                log.debug("Don't know how to collect %s", resource.kind)

        # connect all resources
        namespaces = {node.name: node for node in self.graph.nodes if isinstance(node, KubernetesNamespace)}
        for node, data in list(self.graph.nodes(data=True)):
            # connects resource to either namespace or cluster.
            if isinstance(node, KubernetesCluster):  # ignore the root
                continue
            elif isinstance(node, KubernetesNamespace):  # connect to cluster
                self.graph.add_edge(self.graph.root, node, edge_type=EdgeType.default)  # type: ignore
            else:  # namespaces resources get linked to the namespace, otherwise the cluster
                base = namespaces[node.namespace] if node.namespace else self.graph.root
                self.graph.add_edge(base, node, edge_type=EdgeType.default)  # type: ignore
            # resource specific connects
            node.connect_in_graph(self.builder, data["source"])

        log.info("Kubernetes collector finished.")
