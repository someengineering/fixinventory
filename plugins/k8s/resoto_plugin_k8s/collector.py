from dataclasses import dataclass
from typing import List, Type, TypeVar, Optional

import resotolib.logger
from kubernetes.client import Configuration, ApiClient
from resoto_plugin_k8s.config import K8sConfig
from resoto_plugin_k8s.resources import (
    KubernetesCluster,
    all_k8s_resources_by_k8s_name,
    KubernetesClusterInfo,
    KubernetesResource,
    KubernetesNamespace,
    GraphBuilder,
)
from resotolib.baseresources import EdgeType
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

    def version(self) -> Json:
        return self.get("/version")

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

    def list_resources(
        self, resource: K8sResource, clazz: Type[KubernetesResource], path: Optional[str] = None
    ) -> List[T]:
        result = self.get(path or resource.path)
        return [clazz.from_json(r) for r in result.get("items", [])]


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
                resources = self.client.list_resources(resource, known)
                for r in resources:
                    self.graph.add_node(r)
            else:
                log.debug("Don't know how to collect %s", resource.kind)

        # connect all resources
        namespaces = {node.name: node for node in self.graph.nodes if isinstance(node, KubernetesNamespace)}
        for node in list(self.graph.nodes):
            # connects resource to either namespace or cluster.
            if isinstance(node, KubernetesCluster):  # ignore the root
                continue
            elif isinstance(node, KubernetesNamespace):  # connect to cluster
                self.graph.add_edge(self.graph.root, node, edge_type=EdgeType.default)
            else:  # namespaces resources get linked to the namespace, otherwise the cluster
                base = namespaces[node.namespace] if node.namespace else self.graph.root
                self.graph.add_edge(base, node, edge_type=EdgeType.default)
            # connect owner references
            # https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
            for owner_ref in node.owner_references():
                owner = self.builder.node(id=owner_ref["uid"])
                block_owner_deletion = owner_ref.get("blockOwnerDeletion", False)
                if owner:
                    self.graph.add_edge(owner, node, edge_type=EdgeType.default)
                    if block_owner_deletion:
                        self.graph.add_edge(node, owner, edge_type=EdgeType.delete)
            # resource specific connects
            if (fn := getattr(node, "connect_in_graph", None)) and callable(fn):
                fn(self.builder)
