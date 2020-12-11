from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseResource,
)


class KubernetesReplicaSet(KubernetesResource, BaseResource):
    resource_type = "kubernetes_replica_set"
    api = client.AppsV1Api
    list_method = "list_replica_set_for_all_namespaces"

    attr_map = {"replicas": lambda r: r.spec.replicas}

    def __init__(self, *args, replicas: int = 0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.replicas = int(replicas)
