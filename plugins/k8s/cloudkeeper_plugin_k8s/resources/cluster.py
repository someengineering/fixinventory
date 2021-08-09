import cloudkeeper.logging
from .common import KubernetesResource
from cloudkeeper.baseresources import BaseAccount
from dataclasses import dataclass

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


@dataclass(eq=False)
class KubernetesCluster(KubernetesResource, BaseAccount):
    resource_type = "kubernetes_cluster"
