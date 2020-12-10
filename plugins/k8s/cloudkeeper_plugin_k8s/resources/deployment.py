from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import (
    BaseResource,
)


class KubernetesDeployment(KubernetesResource, BaseResource):
    resource_type = "kubernetes_deployment"
    api = client.AppsV1Api
    list_method = "list_deployment_for_all_namespaces"
