from kubernetes import client
from .common import KubernetesResource
from cklib.baseresources import (
    BaseInstance,
    InstanceStatus,
)
from typing import ClassVar, Dict
from dataclasses import dataclass


@dataclass(eq=False)
class KubernetesPod(KubernetesResource, BaseInstance):
    kind: ClassVar[str] = "kubernetes_pod"
    api: ClassVar[object] = client.CoreV1Api
    list_method: ClassVar[str] = "list_pod_for_all_namespaces"

    attr_map: ClassVar[Dict] = {"instance_status": lambda r: r.status.phase}

    instance_status_map: ClassVar[Dict[str, InstanceStatus]] = {
        "Pending": InstanceStatus.BUSY,
        "Running": InstanceStatus.RUNNING,
        "Failed": InstanceStatus.TERMINATED,
        "Succeeded": InstanceStatus.BUSY,
    }

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )


KubernetesPod.instance_status = property(
    KubernetesPod._instance_status_getter, KubernetesPod._instance_status_setter
)
