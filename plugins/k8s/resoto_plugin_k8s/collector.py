import logging
from dataclasses import dataclass
from typing import List, Type, Optional, Tuple

from kubernetes.client import Configuration, ApiClient
from resoto_plugin_k8s.config import K8sConfig
from resoto_plugin_k8s.resources import (
    KubernetesCluster,
    all_k8s_resources_by_k8s_name,
    KubernetesClusterInfo,
    KubernetesNamespace,
    GraphBuilder,
    KubernetesResourceType,
)
from resotolib.baseresources import EdgeType
from resotolib.graph import Graph
from resotolib.types import Json

log = logging.getLogger("resoto." + __name__)


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
        return result  # type: ignore

    def version(self) -> Json:
        return self.get("/version")

    def apis(self) -> List[K8sResource]:
        result: List[K8sResource] = []

        def add_resource(base: str, js: Json) -> None:
            name = js["name"]
            verbs = js["verbs"]
            if "/" not in name and "list" in verbs:
                result.append(K8sResource(base + "/" + name, js["kind"], js["namespaced"], verbs))

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

    def list_resources(
        self, resource: K8sResource, clazz: Type[KubernetesResourceType], path: Optional[str] = None
    ) -> List[Tuple[KubernetesResourceType, Json]]:
        result = self.get(path or resource.path)
        return [(clazz.from_json(r), r) for r in result.get("items", [])]  # type: ignore


class KubernetesCollector:
    """Collects a single Kubernetes Cluster.

    Responsible for collecting all the resources of an individual cluster.
    Builds up its own local graph which is then taken by collect_cluster()
    and merged with the plugin graph.

    This way we can have many instances of KubernetesCollector running in parallel.
    All building up individual graphs which in the end are merged to a final graph
    containing all K8S resources.
    """

    def __init__(self, k8s_config: K8sConfig, cluster_id: str, cluster_config: Configuration) -> None:
        self.k8s_config = k8s_config
        self.cluster_id = cluster_id
        self.config = cluster_config
        self.client = K8sClient(ApiClient(self.config))
        self.graph = Graph(root=self.cluster())
        self.builder = GraphBuilder(self.graph)

    def cluster(self) -> KubernetesCluster:
        v = self.client.version()
        return KubernetesCluster(
            id=self.cluster_id,
            name=self.config.host,
            cluster_info=KubernetesClusterInfo(v.get("major", ""), v.get("minor", ""), v.get("platform", "")),
        )

    def collect(self) -> None:
        # collect all resources
        for resource in self.client.apis():
            known = all_k8s_resources_by_k8s_name.get(resource.kind)
            if known and self.k8s_config.is_allowed(resource.kind):
                for res, source in self.client.list_resources(resource, known):
                    self.graph.add_node(res, source=source)
            else:
                log.debug("Don't know how to collect %s", resource.kind)

        # connect all resources
        namespaces = {node.name: node for node in self.graph.nodes if isinstance(node, KubernetesNamespace)}
        for node, data in list(self.graph.nodes(data=True)):
            # connects resource to either namespace or cluster.
            if isinstance(node, KubernetesCluster):  # ignore the root
                continue
            elif isinstance(node, KubernetesNamespace):  # connect to cluster
                self.graph.add_edge(self.graph.root, node, edge_type=EdgeType.default)  # type: ignore
            else:  # namespaces resources get linked to the namespace, otherwise the cluster
                base = namespaces[node.namespace] if node.namespace else self.graph.root
                self.graph.add_edge(base, node, edge_type=EdgeType.default)  # type: ignore
            # resource specific connects
            node.connect_in_graph(self.builder, data["source"])
