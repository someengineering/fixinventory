import cloudkeeper.logging
import kubernetes
from prometheus_client import Summary
from .common import KubernetesResource
from cloudkeeper.graph import Graph
from cloudkeeper.baseresources import (
    BaseInstance,
    InstanceStatus,
)


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)
metrics_collect_pods = Summary(
    "cloudkeeper_plugin_k8s_collect_pods_seconds",
    "Time it took the collect_pods() method",
)


class KubernetesPod(KubernetesResource, BaseInstance):
    resource_type = "kubernetes_pod"

    instance_status_map = {
        "Pending": InstanceStatus.BUSY,
        "Running": InstanceStatus.RUNNING,
        "Failed": InstanceStatus.TERMINATED,
        "Succeeded": InstanceStatus.BUSY,
    }

    @BaseInstance.instance_status.setter
    def instance_status(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )


@metrics_collect_pods.time()
def collect(client: kubernetes.client, graph: Graph):
    ret = client.list_pod_for_all_namespaces(watch=False)
    for r in ret.items:
        name = r.metadata.name
        namespace = r.metadata.namespace
        status = r.status.phase
        pod = KubernetesPod(name, {}, instance_status=status, api_response=r)
        ns = graph.search_first_all(
            {"resource_type": "kubernetes_namespace", "id": namespace}
        )
        parent = graph.root
        if ns:
            parent = ns
        graph.add_resource(parent, pod)
