import cloudkeeper.logging
from cloudkeeper.graph import Graph
from cloudkeeper.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseInstance,
    InstanceStatus,
)
from pprint import pformat


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KubernetesResource:
    def __init__(self, *args, api_response=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._api_response = pformat(api_response)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented

    def update_tag(self, key, value) -> bool:
        return NotImplemented

    def delete_tag(self, key) -> bool:
        return NotImplemented


class KubernetesCluster(KubernetesResource, BaseAccount):
    resource_type = "kubernetes_cluster"


class KubernetesNamespace(KubernetesResource, BaseRegion):
    resource_type = "kubernetes_namespace"


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
