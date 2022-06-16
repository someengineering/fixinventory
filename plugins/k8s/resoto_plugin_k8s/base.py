import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from dataclasses import field
from functools import cached_property
from tempfile import TemporaryDirectory
from textwrap import dedent
from threading import RLock
from typing import ClassVar, TypeVar, Any, Callable
from typing import List, Type, Optional, Tuple, Dict

import jsons
from kubernetes.client import ApiClient, Configuration, ApiException
from kubernetes.config import load_kube_config, list_kube_config_contexts

from resotolib.baseresources import BaseResource, EdgeType
from resotolib.config import Config
from resotolib.graph import Graph
from resotolib.json_bender import S, bend, Bender
from resotolib.types import Json
from resotolib.utils import num_default_threads, rnd_str

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
        self.api_client().patch_resource(
            self.__class__, self.namespace, self.name, {"metadata": {"annotations": {key: value}}}
        )
        return True

    def delete_tag(self, key: str) -> bool:
        self.api_client().patch_resource(
            self.__class__, self.namespace, self.name, {"metadata": {"annotations": {key: None}}}
        )
        return True

    def delete(self, graph: Graph) -> bool:
        self.api_client().delete_resource(self.__class__, self.namespace, self.name)
        return True

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
    _clients: Optional[Dict[str, "K8sClient"]] = None
    _temp_dir: Optional[TemporaryDirectory[str]] = None
    _lock: RLock = field(default_factory=RLock)

    def __getstate__(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        del d["_lock"]
        del d["_temp_dir"]
        del d["_clients"]
        return d

    def __setstate__(self, d: Dict[str, Any]) -> None:
        d["_lock"] = RLock()
        self.__dict__.update(d)

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
        with self._lock:
            result = {}
            cfg_files = self.config_files

            # write all access configs as kubeconfig file and let the loader handle it
            for ca in self.configs:
                filename = tmp_dir + "/" + ca.name + rnd_str() + ".yaml"
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
        # check if clients are already initialized
        if not self._clients:
            with self._lock:
                if not self._clients:
                    if self._temp_dir is None:
                        self._temp_dir = TemporaryDirectory()
                    cfgs = self.cluster_access_configs(self._temp_dir.name)
                    factory = kwargs.get("client_factory", K8sApiClient.from_config)
                    self._clients = {name: factory(cluster_id, config) for name, config in cfgs.items()}

        if cluster_id not in self._clients:
            raise ValueError(f"No access config for cluster {cluster_id}")

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

    @staticmethod
    def filter_apis(apis: List[K8sApiResource]) -> List[K8sApiResource]:
        """
        K8s serves multiple apis for the same resource.
        Example:
          Ingress: served via '/apis/networking.k8s.io/v1' and '/apis/extensions/v1beta1' -> use the former
          Event: served via '/api/v1' and '/apis/events.k8s.io/v1' -> use the latter
        """
        known: Dict[str, K8sApiResource] = {}

        def choose(
            left: K8sApiResource, right: K8sApiResource, fns: List[Callable[[K8sApiResource], int]]
        ) -> K8sApiResource:
            for fn in fns:
                rl = fn(left)
                rr = fn(right)
                if res := right if rl > rr else left if rl < rr else None:
                    return res
            # left and right match
            log.warning(
                "Multiple apis available for the same k8s resource type."
                f"Kind: {left.kind} Left: {left.base} <-> {right.base}. Use {left.base}."
            )
            return left

        for api in apis:
            if api.kind in known and "beta" not in known[api.kind].base:
                known[api.kind] = choose(
                    api, known[api.kind], [lambda x: 1 if "beta" in x.base else 0, lambda x: -len(x.base)]
                )
            else:
                known[api.kind] = api
        return list(known.values())


class K8sApiClient(K8sClient):
    def __init__(self, cluster_id: str, api_client: ApiClient):
        self._cluster_id = cluster_id
        self.api_client = api_client

    def call_api(
        self, method: str, path: str, body: Optional[Json] = None, headers: Optional[Dict[str, str]] = None
    ) -> Json:
        log.debug(f"Send request to k8s {method} {path}. body={body}")
        result, code, header = self.api_client.call_api(
            path,
            method,
            auth_settings=["BearerToken"],
            response_type="object",
            body=body,
            header_params=headers,
        )
        log.debug(f"Response from {method} {path} is: {result}")
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
            try:
                resources = self.get(part)
                for resource in resources["resources"]:
                    add_resource(part, resource)
            except ApiException as ex:
                log.warning(f"Failed to retrieve resource APIs for {part}. Reason: {ex}. Ignore.")

        return self.filter_apis(result)

    def list_resources(
        self, resource: K8sApiResource, clazz: Type[KubernetesResourceType], path: Optional[str] = None
    ) -> List[Tuple[KubernetesResourceType, Json]]:
        try:
            result = self.get(path or resource.list_path)
            return [(clazz.from_json(r), r) for r in result.get("items", [])]  # type: ignore
        except ApiException as ex:
            log.warning(f"Failed to list resources: {resource.kind} on {resource.base}. Reason: {ex}. Ignore.")

    @staticmethod
    def from_config(cluster_id: str, cluster_config: Configuration) -> "K8sApiClient":
        return K8sApiClient(cluster_id, ApiClient(cluster_config))
