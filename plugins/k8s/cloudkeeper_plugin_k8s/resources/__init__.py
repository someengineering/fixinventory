from .cluster import KubernetesCluster
from .namespace import collect as collect_namespaces
from .deployment import collect as collect_deployments
from .pod import collect as collect_pods

mandatory_collectors = {
    "namespaces": collect_namespaces,
}

global_collectors = {
    "deployments": collect_deployments,
    "pods": collect_pods,
}

all_collectors = dict(mandatory_collectors)
all_collectors.update(global_collectors)
