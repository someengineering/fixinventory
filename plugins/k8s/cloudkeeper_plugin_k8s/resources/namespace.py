import cloudkeeper.logging
from .common import KubernetesResource
from cloudkeeper.baseresources import BaseRegion


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KubernetesNamespace(KubernetesResource, BaseRegion):
    resource_type = "kubernetes_namespace"
