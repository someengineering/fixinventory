from .cluster import KubernetesCluster
from .namespace import KubernetesNamespace
from .deployment import KubernetesDeployment
from .replica_set import KubernetesReplicaSet
from .pod import KubernetesPod

mandatory_collectors = {
    "namespaces": KubernetesNamespace.collect,
}

global_collectors = {
    "deployments": KubernetesDeployment.collect,
    "replica_set": KubernetesReplicaSet.collect,
    "pods": KubernetesPod.collect,
}

all_collectors = dict(mandatory_collectors)
all_collectors.update(global_collectors)
