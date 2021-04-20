from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseResource,
)


class KubernetesDaemonSet(KubernetesResource, BaseResource):
    resource_type = "kubernetes_daemon_set"
    api = client.AppsV1Api
    list_method = "list_daemon_set_for_all_namespaces"
