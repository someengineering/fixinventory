import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from dataclasses import field
from functools import cached_property
from tempfile import TemporaryDirectory
from textwrap import dedent
from typing import ClassVar, TypeVar, Any
from typing import List, Type, Optional, Tuple, Dict

import jsons
from kubernetes.client import ApiClient, Configuration
from kubernetes.config import load_kube_config, list_kube_config_contexts
from resotolib.baseresources import BaseResource, EdgeType
from resotolib.config import Config
from resotolib.graph import Graph
from resotolib.json_bender import S, bend, Bender
from resotolib.types import Json
from resotolib.utils import num_default_threads

log = logging.getLogger("resoto.plugins.k8s")


@dataclass(eq=False)
class KubernetesResource(BaseResource):
    kind: ClassVar[str] = "kubernetes_resource"

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("metadata", "uid"),
        "tags": S("metadata", "annotations", default={}),
        "name": S("metadata", "name"),
        "ctime": S("metadata", "creationTimestamp"),
        "mtime": S("status", "conditions")[-1]["lastTransitionTime"],
        "resource_version": S("metadata", "resourceVersion"),
        "namespace": S("metadata", "namespace"),
        "labels": S("metadata", "labels", default={}),
    }

    resource_version: Optional[str] = None
    namespace: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)

    def to_json(self) -> Json:
        return jsons.dump(  # type: ignore
            self,
            strip_privates=True,
            strip_nulls=True,
            strip_attr=(
                "k8s_name",
                "mapping",
                "phantom",
                "successor_kinds",
                "parent_resource",
                "usage_percentage",
                "dname",
                "kdname",
                "rtdname",
                "changes",
                "event_log",
                "str_event_log",
                "chksum",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "_graph",
                "graph",
                "max_graph_depth",
                "resource_type",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "uuid",
                "kind",
            ),
        )

    @classmethod
    def from_json(cls: Type["KubernetesResource"], json: Json) -> "KubernetesResource":
        mapped = bend(cls.mapping, json)
        return jsons.load(mapped, cls)  # type: ignore

    @classmethod
    def k8s_name(cls: Type["KubernetesResource"]) -> str:
        return cls.__name__.removeprefix("Kubernetes")

    def api_client(self) -> "K8sClient":
        if account := self.account():
            account_id = account.id
            if cfg := K8sConfig.current_config():
                return cfg.client_for(account_id)
        raise AttributeError(f"No API client for account: {account} or no client for account.")

    def update_tag(self, key: str, value: str) -> bool:
        try:
            self.api_client().patch_resource(
                self.__class__, self.namespace, self.name, {"metadata": {"annotations": {key: value}}}
            )
            return True
        except Exception:
            return False

    def delete_tag(self, key: str) -> bool:
        try:
            self.api_client().patch_resource(
                self.__class__, self.namespace, self.name, {"metadata": {"annotations": {key: None}}}
            )
            return True
        except Exception:
            return False

    def delete(self, graph: Graph) -> bool:
        try:
            self.api_client().delete_resource(self.__class__, self.namespace, self.name)
            return True
        except Exception:
            return False

    def connect_in_graph(self, builder: Any, source: Json) -> None:
        # https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
        for ref in bend(S("metadata", "ownerReferences", default=[]), source):
            owner = builder.node(id=ref["uid"])
            block_owner_deletion = ref.get("blockOwnerDeletion", False)
            if owner:
                log.debug(f"Add owner reference from {owner} -> {self}")
                builder.graph.add_edge(owner, self, edge_type=EdgeType.default)
                if block_owner_deletion:
                    builder.graph.add_edge(self, owner, edge_type=EdgeType.delete)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}[{self.name}]"


KubernetesResourceType = TypeVar("KubernetesResourceType", bound=KubernetesResource)


@dataclass
class K8sAccess:
    kind: ClassVar[str] = "k8s_access"
    name: str = field(metadata={"description": "The name of the kubernetes cluster."})
    certificate_authority_data: str = field(metadata={"description": "The CA certificate string."})
    server: str = field(metadata={"description": "The url of the server to connect to."})
    token: str = field(metadata={"description": "The user access token to use to access this cluster."})

    def to_yaml(self) -> str:
        return dedent(
            f"""
             apiVersion: v1
             clusters:
             - cluster:
                 certificate-authority-data: {self.certificate_authority_data}
                 server: {self.server}
               name: {self.name}
             contexts:
             - context:
                 cluster: {self.name}
                 user: access-{self.name}
                 namespace: resoto
               name: {self.name}
             current-context: {self.name}
             kind: Config
             preferences: {{}}
             users:
             - name: access-{self.name}
               user:
                 token: {self.token}
        """
        )


@dataclass
class K8sConfigFile:
    kind: ClassVar[str] = "k8s_config_file"
    path: str = field(metadata={"description": "Path to the kubeconfig file."})
    contexts: List[str] = field(
        default_factory=list,
        metadata={
            "description": "The contexts to use in the specified config file.\n"
            "You can also set all_contexts to true to use all contexts."
        },
    )
    all_contexts: bool = field(
        default=True,
        metadata={"description": "Collect all contexts found in the kubeconfig file."},
    )


@dataclass
class K8sConfig:
    kind: ClassVar[str] = "k8s"
    configs: List[K8sAccess] = field(
        default_factory=list,
        metadata={
            "description": dedent(
                """
                Configure access to k8s clusters.
                Structure:
                - name: 'k8s-cluster-name'
                  certificate_authority_data: 'CERT'
                  server: 'https://k8s-cluster-server.example.com'
                  token: 'TOKEN'
                """
            ).strip()
        },
    )
    config_files: List[K8sConfigFile] = field(
        default_factory=list,
        metadata={
            "description": dedent(
                """
                Configure access via kubeconfig files.
                Structure:
                  - path: "/path/to/kubeconfig"
                    all_contexts: false
                    contexts: ["context1", "context2"]
                """
            ).strip()
        },
    )
    _clients: Dict[str, "K8sClient"] = field(default_factory=dict)
    _temp_dir: Optional[TemporaryDirectory[str]] = None

    collect: List[str] = field(
        default_factory=list,
        metadata={"description": "Objects to collect (default: all)"},
    )
    no_collect: List[str] = field(
        default_factory=list,
        metadata={"description": "Objects to exclude (default: none)"},
    )
    pool_size: int = field(
        default_factory=num_default_threads,
        metadata={"description": "Thread/process pool size"},
    )
    fork_process: bool = field(
        default=False,
        metadata={"description": "Fork collector process instead of using threads"},
    )

    def is_allowed(self, kind: str) -> bool:
        return (not self.collect or kind in self.collect) and kind not in self.no_collect

    def cluster_access_configs(self, tmp_dir: str) -> Dict[str, Configuration]:
        result = {}
        cfg_files = self.config_files

        # write all access configs as kubeconfig file and let the loader handle it
        for ca in self.configs:
            filename = tmp_dir + "/" + ca.name + ".yaml"
            with open(filename, "w") as f:
                f.write(ca.to_yaml())
            cfg_files.append(K8sConfigFile(path=filename))

        # load all kubeconfig files
        for cf in cfg_files:
            all_contexts, active_context = list_kube_config_contexts(cf.path)
            contexts = all_contexts if cf.all_contexts else [a for a in all_contexts if a["name"] in cf.contexts]
            for ctx in contexts:
                name = ctx["name"]
                config = Configuration()
                load_kube_config(cf.path, name, client_configuration=config)
                result[name] = config

        return result

    def client_for(self, cluster_id: str, **kwargs: Any) -> "K8sClient":
        if cluster_id not in self._clients:
            if self._temp_dir is None:
                self._temp_dir = TemporaryDirectory()
            configs = self.cluster_access_configs(self._temp_dir.name)
            if cluster_id not in configs:
                raise ValueError(f"No access config for cluster {cluster_id}")
            config = configs[cluster_id]
            api_client = kwargs.get("client_factory", K8sApiClient.from_config)(cluster_id, config)
            self._clients[cluster_id] = api_client
        return self._clients[cluster_id]

    @staticmethod
    def current_config() -> Optional["K8sConfig"]:
        cfg = Config.running_config.data.get(K8sConfig.kind)
        if isinstance(cfg, K8sConfig):
            return cfg
        return None


@dataclass
class K8sApiResource:
    base: str
    name: str
    kind: str
    namespaced: bool
    verbs: List[str]

    @property
    def list_path(self) -> str:
        return self.base + "/" + self.name


class K8sClient(ABC):
    @abstractmethod
    def call_api(
        self, method: str, path: str, body: Optional[Json] = None, headers: Optional[Dict[str, str]] = None
    ) -> Json:
        pass

    @property
    @abstractmethod
    def cluster_id(self) -> str:
        pass

    @property
    @abstractmethod
    def host(self) -> str:
        pass

    def get(self, path: str) -> Json:
        return self.call_api("GET", path)

    def patch(self, path: str, js: Json) -> Json:
        return self.call_api("PATCH", path, js, {"Content-Type": "application/strategic-merge-patch+json"})

    def delete(self, path: str) -> Json:
        return self.call_api("DELETE", path)

    def __api_for_kind(self, kind: str) -> Optional[K8sApiResource]:
        for api in self.apis:
            if api.kind == kind:
                return api
        return None

    def __resource_path(
        self, clazz: Type[KubernetesResourceType], namespace: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[str]:
        if api := self.__api_for_kind(clazz.k8s_name()):
            if api.namespaced:
                assert namespace is not None, "No namespace provided, but resource is namespaced"
            assert name is not None, "No name given for resource"
            ns = f"/namespaces/{namespace}/" if namespace else "/"
            return f"{api.base}{ns}{api.name}/{name}"
        return None

    def patch_resource(
        self, clazz: Type[KubernetesResourceType], namespace: Optional[str], name: Optional[str], patch: Json
    ) -> Optional[KubernetesResourceType]:
        if path := self.__resource_path(clazz, namespace, name):
            patched = self.patch(path, patch)
            return clazz.from_json(patched)  # type: ignore
        raise AttributeError(f"No api available for this resource type: {clazz}")

    def get_resource(
        self, clazz: Type[KubernetesResourceType], namespace: Optional[str], name: Optional[str]
    ) -> Optional[KubernetesResourceType]:
        if path := self.__resource_path(clazz, namespace, name):
            return clazz.from_json(self.get(path))  # type: ignore
        return None

    def delete_resource(
        self, clazz: Type[KubernetesResourceType], namespace: Optional[str], name: Optional[str]
    ) -> None:
        if path := self.__resource_path(clazz, namespace, name):
            self.delete(path)

    @abstractmethod
    def version(self) -> Json:
        pass

    @property
    @abstractmethod
    def apis(self) -> List[K8sApiResource]:
        pass

    @abstractmethod
    def list_resources(
        self, resource: K8sApiResource, clazz: Type[KubernetesResourceType], path: Optional[str] = None
    ) -> List[Tuple[KubernetesResourceType, Json]]:
        pass


class K8sApiClient(K8sClient):
    def __init__(self, cluster_id: str, api_client: ApiClient):
        self._cluster_id = cluster_id
        self.api_client = api_client

    def call_api(
        self, method: str, path: str, body: Optional[Json] = None, headers: Optional[Dict[str, str]] = None
    ) -> Json:
        result, code, header = self.api_client.call_api(
            path,
            method,
            auth_settings=["BearerToken"],
            response_type="object",
            body=body,
            header_params=headers,
        )
        return result  # type: ignore

    @property
    def cluster_id(self) -> str:
        return self._cluster_id

    @property
    def host(self) -> str:
        return self.api_client.configuration.host  # type: ignore

    def version(self) -> Json:
        return self.get("/version")

    @cached_property
    def apis(self) -> List[K8sApiResource]:
        result: List[K8sApiResource] = []

        def add_resource(base: str, js: Json) -> None:
            name = js["name"]
            verbs = js["verbs"]
            if "/" not in name and "list" in verbs:
                result.append(K8sApiResource(base, name, js["kind"], js["namespaced"], verbs))

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
        self, resource: K8sApiResource, clazz: Type[KubernetesResourceType], path: Optional[str] = None
    ) -> List[Tuple[KubernetesResourceType, Json]]:
        result = self.get(path or resource.list_path)
        return [(clazz.from_json(r), r) for r in result.get("items", [])]  # type: ignore

    @staticmethod
    def from_config(cluster_id: str, cluster_config: Configuration) -> "K8sApiClient":
        return K8sApiClient(cluster_id, ApiClient(cluster_config))
