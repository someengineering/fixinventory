from dataclasses import dataclass
from typing import List, Type, TypeVar

import jsons
import resotolib.logger
from kubernetes.client import Configuration, ApiClient
from resoto_plugin_k8s.config import K8sConfig
from resoto_plugin_k8s.resources import KubernetesCluster, all_k8s_resources_by_k8s_name
from resotolib.graph import Graph
from resotolib.types import Json

log = resotolib.logger.getLogger("resoto." + __name__)

T = TypeVar("T")


@dataclass
class K8sResource:
    path: str
    kind: str
    namespaced: bool
    verbs: List[str]


class K8sClient:
    def __init__(self, api_client: ApiClient):
        self.api_client = api_client

    def get(self, path: str) -> Json:
        result, code, header = self.api_client.call_api(
            path, "GET", auth_settings=["BearerToken"], response_type="object"
        )
        return result

    def apis(self) -> List[K8sResource]:
        result: List[K8sResource] = []

        def add_resource(part: str, js: Json):
            name = js["name"]
            verbs = js["verbs"]
            if "/" not in name and "list" in verbs:
                result.append(K8sResource(part + "/" + name, js["kind"], js["namespaced"], verbs))

        old_apis = self.get("/api/v1")
        for resource in old_apis["resources"]:
            add_resource("/api/v1", resource)

        apis = self.get("/apis")
        for group in apis["groups"]:
            part = f'/apis/{group["preferredVersion"]["groupVersion"]}'
            resources = self.get(part)
            for resource in resources["resources"]:
                add_resource(part, resource)

        return result

    def list_resources(self, resource: K8sResource, clazz: Type[T]) -> List[T]:
        result = self.get(resource.path)
        return [jsons.loads(r, clazz) for r in result["resources"]]


class KubernetesCollector:
    """Collects a single Kubernetes Cluster.

    Responsible for collecting all the resources of an individual cluster.
    Builds up its own local graph which is then taken by collect_cluster()
    and merged with the plugin graph.

    This way we can have many instances of KubernetesCollector running in parallel.
    All building up individual graphs which in the end are merged to a final graph
    containing all K8S resources.
    """

    def __init__(self, k8s_config: K8sConfig, cluster: KubernetesCluster, cluster_config: Configuration) -> None:
        """
        Args:
            cluster: The K8S cluster resource object this cluster collector
                is going to collect.
        """
        self.k8s_config = k8s_config
        self.cluster = cluster
        self.config = cluster_config
        self.client = K8sClient(ApiClient(self.config))
        self.graph = Graph(root=self.cluster)

    def collect(self) -> None:
        for resource in self.client.apis():
            known = all_k8s_resources_by_k8s_name.get(resource.kind)
            if known and self.k8s_config.is_allowed(resource.kind):
                resources = self.client.list_resources(resource, known)
