from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseResource,
)


class KubernetesStatefulSet(KubernetesResource, BaseResource):
    resource_type = "kubernetes_stateful_set"
    api = client.AppsV1Api
    list_method = "list_stateful_set_for_all_namespaces"
