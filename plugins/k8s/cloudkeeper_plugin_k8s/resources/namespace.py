from kubernetes import client
from .common import KubernetesResource
from resotolib.baseresources import BaseRegion
from typing import ClassVar
from dataclasses import dataclass


@dataclass(eq=False)
class KubernetesNamespace(KubernetesResource, BaseRegion):
    kind: ClassVar[str] = "kubernetes_namespace"
    api: ClassVar[object] = client.CoreV1Api
    list_method: ClassVar[str] = "list_namespace"
