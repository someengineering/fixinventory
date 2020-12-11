import cloudkeeper.logging
from kubernetes import client
from .common import KubernetesResource
from cloudkeeper.baseresources import BaseInstance


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KubernetesNode(KubernetesResource, BaseInstance):
    resource_type = "kubernetes_node"
    api = client.CoreV1Api
    list_method = "list_node"
