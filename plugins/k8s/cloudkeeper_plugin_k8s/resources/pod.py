import cloudkeeper.logging
from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseInstance,
    InstanceStatus,
)


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KubernetesPod(KubernetesResource, BaseInstance):
    resource_type = "kubernetes_pod"
    api = client.CoreV1Api
    list_method = "list_pod_for_all_namespaces"

    attr_map = {"instance_status": lambda r: r.status.phase}

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
