import cloudkeeper.logging
from kubernetes import client
from prometheus_client import Summary
from .common import KubernetesResource
from cloudkeeper.graph import Graph
from cloudkeeper.baseresources import BaseRegion


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)
metrics_collect = Summary(
    "cloudkeeper_plugin_k8s_collect_namespaces_seconds",
    "Time it took the namespaces collect() method",
)


class KubernetesNamespace(KubernetesResource, BaseRegion):
    resource_type = "kubernetes_namespace"


@metrics_collect.time()
def collect(api_client: client.ApiClient, graph: Graph):
    api = client.CoreV1Api(api_client)
    ret = api.list_namespace(watch=False)
    for r in ret.items:
        namespace = KubernetesNamespace(r.metadata.name, {}, api_response=r)
        graph.add_resource(graph.root, namespace)
