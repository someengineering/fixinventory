import cloudkeeper.logging
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseInstance,
    InstanceStatus,
)


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


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
