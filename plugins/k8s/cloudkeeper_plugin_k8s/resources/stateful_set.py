from kubernetes import client
from .common import KubernetesResource
from resotolib.baseresources import (
    BaseResource,
)
from typing import ClassVar
from dataclasses import dataclass


@dataclass(eq=False)
class KubernetesStatefulSet(KubernetesResource, BaseResource):
    kind: ClassVar[str] = "kubernetes_stateful_set"
    api: ClassVar[object] = client.AppsV1Api
    list_method: ClassVar[str] = "list_stateful_set_for_all_namespaces"
