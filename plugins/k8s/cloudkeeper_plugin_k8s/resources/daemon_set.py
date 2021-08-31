from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseResource,
)
from typing import ClassVar
from dataclasses import dataclass


@dataclass(eq=False)
class KubernetesDaemonSet(KubernetesResource, BaseResource):
    kind: ClassVar[str] = "kubernetes_daemon_set"
    api: ClassVar[object] = client.AppsV1Api
    list_method: ClassVar[str] = "list_daemon_set_for_all_namespaces"
