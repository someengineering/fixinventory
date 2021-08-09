from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseResource,
)
from typing import ClassVar
from dataclasses import dataclass


@dataclass(eq=False)
class KubernetesControllerRevision(KubernetesResource, BaseResource):
    resource_type: ClassVar[str] = "kubernetes_controller_revision"
    api: ClassVar[str] = client.AppsV1Api
    list_method: ClassVar[str] = "list_controller_revision_for_all_namespaces"
