from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseResource,
)


class KubernetesControllerRevision(KubernetesResource, BaseResource):
    resource_type = "kubernetes_controller_revision"
    api = client.AppsV1Api
    list_method = "list_controller_revision_for_all_namespaces"
