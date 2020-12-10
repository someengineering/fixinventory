import cloudkeeper.logging
import kubernetes
from prometheus_client import Summary
from .common import KubernetesResource
from cloudkeeper.graph import Graph
from cloudkeeper.baseresources import BaseRegion


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)
metrics_collect_namespaces = Summary(
    "cloudkeeper_plugin_k8s_collect_namespaces_seconds",
    "Time it took the collect_namespaces() method",
)


class KubernetesNamespace(KubernetesResource, BaseRegion):
    resource_type = "kubernetes_namespace"


@metrics_collect_namespaces.time()
def collect(client: kubernetes.client, graph: Graph):
    ret = client.list_namespace(watch=False)
    for r in ret.items:
        namespace = KubernetesNamespace(r.metadata.name, {}, api_response=r)
        graph.add_resource(graph.root, namespace)
