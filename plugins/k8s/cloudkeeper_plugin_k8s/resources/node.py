from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import BaseResource
from typing import ClassVar
from dataclasses import dataclass


@dataclass(eq=False)
class KubernetesNode(KubernetesResource, BaseResource):
    resource_type: ClassVar[str] = "kubernetes_node"
    api: ClassVar[object] = client.CoreV1Api
    list_method: ClassVar[str] = "list_node"
