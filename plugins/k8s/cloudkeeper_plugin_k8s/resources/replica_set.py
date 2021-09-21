from kubernetes import client
from .common import KubernetesResource
from cklib.baseresources import (
    BaseResource,
)
from typing import ClassVar, Dict
from dataclasses import dataclass


@dataclass(eq=False)
class KubernetesReplicaSet(KubernetesResource, BaseResource):
    kind: ClassVar[str] = "kubernetes_replica_set"
    api: ClassVar[object] = client.AppsV1Api
    list_method: ClassVar[str] = "list_replica_set_for_all_namespaces"
    attr_map: ClassVar[Dict] = {"replicas": lambda r: r.spec.replicas}

    replicas: int = 0
