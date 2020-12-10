import cloudkeeper.logging
from kubernetes import client
from prometheus_client import Summary
from .common import KubernetesResource
from cloudkeeper.graph import Graph
from cloudkeeper.baseresources import (
    BaseResource,
)


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)
metrics_collect = Summary(
    "cloudkeeper_plugin_k8s_collect_deployments_seconds",
    "Time it took the deployments collect() method",
)


class KubernetesDeployment(KubernetesResource, BaseResource):
    resource_type = "kubernetes_deployment"


@metrics_collect.time()
def collect(api_client: client.ApiClient, graph: Graph):
    api = client.CoreV1Api(api_client)
    ret = api.list_pod_for_all_namespaces(watch=False)
    for r in ret.items:
        name = r.metadata.name
        namespace = r.metadata.namespace
        deployment = KubernetesDeployment(name, {}, api_response=r)
        ns = graph.search_first_all(
            {"resource_type": "kubernetes_namespace", "id": namespace}
        )
        parent = graph.root
        if ns:
            parent = ns
        graph.add_resource(parent, deployment)
