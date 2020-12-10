import cloudkeeper.logging
from .common import KubernetesResource
from cloudkeeper.baseresources import BaseAccount

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KubernetesCluster(KubernetesResource, BaseAccount):
    resource_type = "kubernetes_cluster"
