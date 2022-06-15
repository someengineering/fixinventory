import json
import os
from functools import cached_property
from typing import Type, Optional, List, Tuple, Dict, Any

import jsons
import pytest
from _pytest.fixtures import SubRequest
from kubernetes.client import Configuration
from resoto_plugin_k8s.base import K8sApiResource, K8sClient
from resoto_plugin_k8s.base import KubernetesResourceType
from resotolib.types import Json


def from_file(name: str) -> Optional[Json]:
    path = os.path.abspath(os.path.dirname(__file__) + "/files/" + name)
    if os.path.exists(path):
        with open(path) as f:
            content = f.read()
            ks = json.loads(content)
            return ks  # type: ignore
    return None


@pytest.fixture
def json_file(request: SubRequest) -> Json:
    for mark in request.node.iter_markers("json_file"):
        result = from_file(mark.args[0])
        if result is None:
            Exception("No file with this path: " + mark.args[0])
        else:
            return result
    raise Exception("No json_file mark found")


class StaticFileClient(K8sClient):
    def __init__(self, cluster_id: str, config: Any = None):
        self._cluster_id = cluster_id
        self._config = config
        self.patches: List[Tuple[type, Optional[str], Optional[str], Json]] = []
        self.deletes: List[Tuple[type, Optional[str], Optional[str]]] = []

    def call_api(
        self, method: str, path: str, body: Optional[Json] = None, headers: Optional[Dict[str, str]] = None
    ) -> Json:
        if method != "GET":
            raise AttributeError("Only GET is supported")
        return from_file(path.lstrip("/").replace("/", "_") + ".json") or {}

    def patch_resource(
        self, clazz: Type[KubernetesResourceType], namespace: Optional[str], name: Optional[str], patch: Json
    ) -> Optional[KubernetesResourceType]:
        self.patches.append((clazz, namespace, name, patch))
        return None

    def delete_resource(
        self, clazz: Type[KubernetesResourceType], namespace: Optional[str], name: Optional[str]
    ) -> None:
        self.deletes.append((clazz, namespace, name))
        return None

    @property
    def cluster_id(self) -> str:
        return self._cluster_id

    @property
    def host(self) -> str:
        return "http://localhost:8080"

    def version(self) -> Json:
        return {"buildDate": "2022-03-16T14:02:06Z", "major": "1", "minor": "21", "platform": "linux/amd64"}

    @cached_property
    def apis(self) -> List[K8sApiResource]:
        js = self.get("apis")
        return self.filter_apis(jsons.load(js, List[K8sApiResource]))

    def list_resources(
        self, resource: K8sApiResource, clazz: Type[KubernetesResourceType], path: Optional[str] = None
    ) -> List[Tuple[KubernetesResourceType, Json]]:
        result = self.get(path or resource.list_path)
        if result:
            return [(clazz.from_json(r), r) for r in result.get("items", [])]  # type: ignore
        else:
            return []

    @staticmethod
    def static(cluster_id: str, config: Configuration) -> K8sClient:
        return StaticFileClient(cluster_id, config)
