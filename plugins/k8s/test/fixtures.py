import json
import os
from typing import Type, Optional, List, Tuple

import jsons
import pytest
from _pytest.fixtures import SubRequest
from kubernetes.client import Configuration

from resoto_plugin_k8s.client import K8sResource, K8sClient
from resoto_plugin_k8s.resources import KubernetesResourceType
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
    def get(self, path: str) -> Json:
        return from_file(path.lstrip("/").replace("/", "_") + ".json") or {}

    def version(self) -> Json:
        return {"buildDate": "2022-03-16T14:02:06Z", "major": "1", "minor": "21", "platform": "linux/amd64"}

    def apis(self) -> List[K8sResource]:
        js = self.get("apis")
        return jsons.load(js, List[K8sResource])  # type: ignore

    def list_resources(
        self, resource: K8sResource, clazz: Type[KubernetesResourceType], path: Optional[str] = None
    ) -> List[Tuple[KubernetesResourceType, Json]]:
        result = self.get(path or resource.path)
        if result:
            return [(clazz.from_json(r), r) for r in result.get("items", [])]  # type: ignore
        else:
            return []

    @staticmethod
    def static(_: Configuration) -> K8sClient:
        return StaticFileClient()
