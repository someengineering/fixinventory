from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Type, Optional, Tuple

from kubernetes.client import ApiClient, Configuration

from resoto_plugin_k8s.resources import (
    KubernetesResourceType,
)
from resotolib.types import Json

log = logging.getLogger("resoto." + __name__)


@dataclass
class K8sResource:
    path: str
    kind: str
    namespaced: bool
    verbs: List[str]


class K8sClient(ABC):
    @abstractmethod
    def get(self, path: str) -> Json:
        pass

    @abstractmethod
    def version(self) -> Json:
        pass

    @abstractmethod
    def apis(self) -> List[K8sResource]:
        pass

    @abstractmethod
    def list_resources(
        self, resource: K8sResource, clazz: Type[KubernetesResourceType], path: Optional[str] = None
    ) -> List[Tuple[KubernetesResourceType, Json]]:
        pass


class K8sApiClient(K8sClient):
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

    @staticmethod
    def from_config(cluster_config: Configuration) -> K8sApiClient:
        return K8sApiClient(ApiClient(cluster_config))
