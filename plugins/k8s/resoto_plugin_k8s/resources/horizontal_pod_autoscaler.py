from kubernetes import client
from .common import KubernetesResource
from resotolib.baseresources import (
    BaseResource,
)
from typing import ClassVar, Dict
from dataclasses import dataclass


@dataclass(eq=False)
class KubernetesHorizontalPodAutoscaler(KubernetesResource, BaseResource):
    kind: ClassVar[str] = "kubernetes_horizontal_pod_autoscaler"
    api: ClassVar[object] = client.AutoscalingV1Api
    list_method: ClassVar[str] = "list_horizontal_pod_autoscaler_for_all_namespaces"

    attr_map: ClassVar[Dict] = {
        "max_replicas": lambda r: r.spec.max_replicas,
        "min_replicas": lambda r: r.spec.min_replicas,
    }

    max_replicas: int = 0
    min_replicas: int = 0
