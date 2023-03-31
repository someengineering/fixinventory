from __future__ import annotations

import concurrent
import logging
from concurrent.futures import Executor, Future
from threading import Lock
from typing import Callable, List, ClassVar, Optional, TypeVar, Type, Any, Dict

from attr import define, field
from google.auth.credentials import Credentials

from resoto_plugin_gcp.gcp_client import GcpClient, GcpApiSpec, InternalZoneProp, RegionProp
from resoto_plugin_gcp.utils import delete_resource, update_label
from resotolib.baseresources import BaseResource, BaseAccount, Cloud, EdgeType, BaseRegion, BaseZone, BaseQuota
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph, EdgeKey
from resotolib.json import from_json as from_js, to_json as to_js
from resotolib.json_bender import bend, Bender, S, Bend
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.gcp")


T = TypeVar("T")


class CancelOnFirstError(Exception):
    pass


@define
class ExecutorQueue:
    executor: Executor
    name: str
    fail_on_first_exception: bool = False
    futures: List[Future[Any]] = field(factory=list)
    _lock: Lock = Lock()
    _exception: Optional[Exception] = None

    def submit_work(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        def do_work() -> T:
            # in case of exception let's fail fast and do not execute the function
            if self._exception is None:
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    # only store the first exception if we should fail on first future
                    if self._exception is None:
                        self._exception = e
                    raise e
            else:
                raise CancelOnFirstError(
                    "Exception happened in another thread. Do not start work."
                ) from self._exception

        future = (
            self.executor.submit(do_work) if self.fail_on_first_exception else self.executor.submit(fn, *args, **kwargs)
        )

        with self._lock:
            self.futures.append(future)
        return future

    def wait_for_submitted_work(self) -> None:
        def _wait_for_current_batch() -> None:
            # wait until all futures are complete
            with self._lock:
                to_wait = self.futures
                self.futures = []
            for future in concurrent.futures.as_completed(to_wait):
                try:
                    future.result()
                except CancelOnFirstError:
                    pass
                except Exception as ex:
                    log.exception(f"Unhandled exception in project {self.name}: {ex}")
                    raise

        # Wait until all submitted work and their potential "children" work is done
        with self._lock:
            remaining = len(self.futures)

        while not remaining == 0:
            _wait_for_current_batch()
            with self._lock:
                remaining = len(self.futures)


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        project: GcpProject,
        credentials: Credentials,
        executor: ExecutorQueue,
        core_feedback: CoreFeedback,
        region: Optional[GcpRegion] = None,
        graph_nodes_access: Optional[Lock] = None,
        graph_edges_access: Optional[Lock] = None,
    ) -> None:
        self.graph = graph
        self.cloud = cloud
        self.region = region
        self.project = project
        self.client = GcpClient(
            credentials, project_id=project.id, region=region.name if region else None, core_feedback=core_feedback
        )
        self.executor = executor
        self.name = f"GCP:{project.name}"
        self.core_feedback = core_feedback
        self.region_by_name: Dict[str, GcpRegion] = {}
        self.region_by_zone_name: Dict[str, GcpRegion] = {}
        self.zone_by_name: Dict[str, GcpZone] = {}
        self.graph_nodes_access = graph_nodes_access or Lock()
        self.graph_edges_access = graph_edges_access or Lock()

    def submit_work(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        """
        Use this method for work that can be done in parallel.
        Example: fetching tags of a resource.
        """
        return self.executor.submit_work(fn, *args, **kwargs)

    def prepare_region_zone_lookup(self) -> None:
        regions = self.resources_of(GcpRegion)
        zns = self.resources_of(GcpZone)
        self.region_by_name = {r.safe_name: r for r in regions}
        self.region_by_zone_name = {z.safe_name: self.region_by_name[z.safe_name.rsplit("-", 1)[0]] for z in zns}
        self.zone_by_name = {z.safe_name: z for z in zns}

    def node(
        self, clazz: Optional[Type[GcpResourceType]] = None, filter: Optional[Callable[[Any], bool]] = None, **node: Any
    ) -> Optional[GcpResourceType]:
        """
        Returns first node on the graph that is of given `clazz`
        and/or conforms to the `filter` and matches attributes given in `**node`.
        """
        if isinstance(nd := node.get("node"), GcpResource):
            return nd  # type: ignore
        with self.graph_nodes_access:
            for n in self.graph:
                if clazz and not isinstance(n, clazz):
                    continue
                if (filter(n) if filter else True) and all(getattr(n, k, None) == v for k, v in node.items()):
                    return n  # type: ignore
        return None

    def nodes(
        self, clazz: Optional[Type[GcpResourceType]] = None, filter: Optional[Callable[[Any], bool]] = None, **node: Any
    ) -> List[GcpResourceType]:
        """
        Returns list of all nodes on the graph that are of given `clazz`
        and/or conform to the `filter` and match attributes given in `**node`.
        """
        result: List[GcpResourceType] = []
        if isinstance(nd := node.get("node"), GcpResource):
            result.append(nd)  # type: ignore
        with self.graph_nodes_access:
            for n in self.graph:
                if clazz and not isinstance(n, clazz):
                    continue
                if (filter(n) if filter else True) and all(getattr(n, k, None) == v for k, v in node.items()):
                    result.append(n)
        return result

    def add_node(self, node: GcpResourceType, source: Optional[Json] = None) -> Optional[GcpResourceType]:
        log.debug(f"{self.name}: add node {node}")
        node._cloud = self.cloud
        node._account = self.project

        self._standard_edges(node, source)

        with self.graph_nodes_access:
            self.graph.add_node(node, source=source or {})
        return node

    def _standard_edges(self, node: GcpResourceType, source: Optional[Json] = None) -> None:
        if isinstance(node, GcpRegion):
            self.add_edge(node, node=self.project, reverse=True)
            return
        if node._zone:
            self.add_edge(node, node=node._zone, reverse=True)
            return
        if node._region:
            self.add_edge(node, node=node._region, reverse=True)
            return

        if source is not None:
            if InternalZoneProp in source:
                if zone := self.zone_by_name.get(source[InternalZoneProp]):
                    node._zone = zone
                    node._region = self.region_by_zone_name[source[InternalZoneProp]]
                    self.add_edge(node, node=zone, reverse=True)
                    return
                else:
                    log.debug(f"Zone {source[InternalZoneProp]} not found for node: {node}.")

            if RegionProp in source:
                region_name = source[RegionProp].rsplit("/", 1)[-1]
                if region := self.region_by_name.get(region_name):
                    node._region = region
                    self.add_edge(node, node=region, reverse=True)
                    return
                else:
                    log.debug(f"Region {region_name} not found for node: {node}.")

        # Fallback to GraphBuilder region, i.e. regional collection
        if self.region is not None:
            node._region = self.region
            self.add_edge(node, node=self.region, reverse=True)
            return

        # Fallback to project, i.e. for non-regional resources
        self.add_edge(node, node=self.project, reverse=True)
        return

    def add_edge(
        self,
        from_node: BaseResource,
        edge_type: EdgeType = EdgeType.default,
        reverse: bool = False,
        filter: Optional[Callable[[Any], bool]] = None,
        **to_node: Any,
    ) -> None:
        """
        Creates edge between `from_node` and another node using `GraphBuilder.node(filter, **to_node)`.
        """
        to_n = self.node(filter=filter, **to_node)
        if isinstance(from_node, GcpResource) and isinstance(to_n, GcpResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [{edge_type}]")
            with self.graph_edges_access:
                self.graph.add_edge(start, end, edge_type=edge_type)

    def add_edges(
        self,
        from_node: BaseResource,
        edge_type: EdgeType = EdgeType.default,
        reverse: bool = False,
        filter: Optional[Callable[[Any], bool]] = None,
        **to_nodes: Any,
    ) -> None:
        """
        Creates edges between `from_node` and all nodes found with `GraphBuilder.nodes(filter, **to_node)`.
        """
        node: Type[GcpResource]
        for node in self.nodes(filter=filter, **to_nodes):
            self.add_edge(from_node, edge_type, reverse, node=node)

    def dependant_node(
        self, from_node: BaseResource, reverse: bool = False, delete_same_as_default: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, GcpResource) and isinstance(to_n, GcpResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [default]")
            with self.graph_edges_access:
                self.graph.add_edge(start, end, edge_type=EdgeType.default)
                if delete_same_as_default:
                    start, end = end, start
                log.debug(f"{self.name}: add edge: {end} -> {start} [delete]")
                self.graph.add_edge(end, start, edge_type=EdgeType.delete)

    def resources_of(self, resource_type: Type[GcpResourceType]) -> List[GcpResourceType]:
        with self.graph_nodes_access:
            return [n for n in self.graph.nodes if isinstance(n, resource_type)]

    def edges_of(
        self, from_type: Type[GcpResource], to_type: Type[GcpResource], edge_type: EdgeType = EdgeType.default
    ) -> List[EdgeKey]:
        with self.graph_edges_access:
            return [
                key
                for (from_node, to_node, key) in self.graph.edges
                if isinstance(from_node, from_type) and isinstance(to_node, to_type) and key.edge_type == edge_type
            ]

    def for_region(self, region: GcpRegion) -> GraphBuilder:
        return GraphBuilder(
            self.graph,
            self.cloud,
            self.project,
            self.client.credentials,
            self.executor,
            self.core_feedback,
            region,
            self.graph_nodes_access,
            self.graph_edges_access,
        )


@define(eq=False, slots=False)
class GcpResource(BaseResource):
    kind: ClassVar[str] = "gcp_resource"
    api_spec: ClassVar[Optional[GcpApiSpec]] = None
    mapping: ClassVar[Dict[str, Bender]] = {}

    description: Optional[str] = None
    deprecation_status: Optional[GcpDeprecationStatus] = None
    link: Optional[str] = None
    label_fingerprint: Optional[str] = None

    def delete(self, graph: Graph) -> bool:
        return delete_resource(self)

    def update_tag(self, key: str, value: str) -> bool:
        return update_label(self, key, value)

    def delete_tag(self, key: str) -> bool:
        return update_label(self, key, None)

    def adjust_from_api(self, graph_builder: GraphBuilder, source: Json) -> GcpResource:
        """
        Hook method to adjust the resource before it is added to the graph.
        Default: do not change the resource.
        """
        return self

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        """
        Hook method to post process the resource after it is added to the graph.
        Default: do nothing.
        """
        pass

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        """
        Hook method which is called when all resources have been collected.
        Connect the resource to other resources in the graph.
        """
        pass

    def to_json(self) -> Json:
        return to_js(self)

    @classmethod
    def collect_resources(cls: Type[GcpResource], builder: GraphBuilder, **kwargs: Any) -> List[GcpResource]:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.info(f"[Gcp:{builder.project.id}] Collecting {cls.__name__} with ({kwargs})")
        if spec := cls.api_spec:
            items = builder.client.list(spec, **kwargs)
            return cls.collect(items, builder)
        return []

    @classmethod
    def collect(cls: Type[GcpResource], raw: List[Json], builder: GraphBuilder) -> List[GcpResource]:
        # Default behavior: iterate over json snippets and for each:
        # - bend the json
        # - transform the result into a resource
        # - add the resource to the graph
        # In case additional work needs to be done, override this method.
        result: List[GcpResource] = []
        for js in raw:
            # map from api
            instance = cls.from_api(js)
            # allow the instance to adjust itself
            adjusted = instance.adjust_from_api(builder, js)
            # add to graph
            if (added := builder.add_node(adjusted, js)) is not None:
                # post process
                added.post_process(builder, js)
                result.append(added)
        return result

    @classmethod
    def from_json(cls: Type[GcpResourceType], json: Json) -> GcpResourceType:
        return from_js(json, cls)

    @classmethod
    def from_api(cls: Type[GcpResourceType], json: Json) -> GcpResourceType:
        mapped = bend(cls.mapping, json)
        return cls.from_json(mapped)


GcpResourceType = TypeVar("GcpResourceType", bound=GcpResource)


@define(eq=False, slots=False)
class GcpProject(GcpResource, BaseAccount):
    kind: ClassVar[str] = "gcp_project"


@define(eq=False, slots=False)
class GcpDeprecationStatus:
    kind: ClassVar[str] = "gcp_deprecation_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "deleted": S("deleted"),
        "deprecated": S("deprecated"),
        "obsolete": S("obsolete"),
        "replacement": S("replacement"),
        "state": S("state"),
    }
    deleted: Optional[str] = field(default=None)
    deprecated: Optional[str] = field(default=None)
    obsolete: Optional[str] = field(default=None)
    replacement: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpQuota(GcpResource, BaseQuota):
    kind: ClassVar[str] = "gcp_quota"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("metric"),
        "limit": S("limit"),
        "owner": S("owner"),
        "usage": S("usage"),
    }
    limit: Optional[float] = field(default=None)
    owner: Optional[str] = field(default=None)
    usage: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpRegion(GcpResource, BaseRegion):
    kind: ClassVar[str] = "gcp_region"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["regions"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "description": S("description"),
        "status": S("status"),
        "region_deprecated": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "region_supports_pzs": S("supportsPzs"),
    }
    description: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    region_deprecated: Optional[GcpDeprecationStatus] = field(default=None)
    region_supports_pzs: Optional[bool] = field(default=None)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        for quota_js in source.get("quotas", []):
            quota = GcpQuota.from_api(quota_js)
            quota._region = self
            graph_builder.add_node(quota, quota_js)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for zone_link in source.get("zones", []):
            builder.add_edge(self, clazz=GcpZone, link=zone_link)


@define(eq=False, slots=False)
class GcpZone(GcpResource, BaseZone):
    kind: ClassVar[str] = "gcp_zone"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="compute",
        version="v1",
        accessors=["zones"],
        action="list",
        request_parameter={"project": "{project}"},
        request_parameter_in={"project"},
        response_path="items",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "description": S("description"),
        "status": S("status"),
        "zone_available_cpu_platforms": S("availableCpuPlatforms", default=[]),
        "zone_deprecated": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "zone_supports_pzs": S("supportsPzs"),
    }
    description: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    zone_available_cpu_platforms: Optional[List[str]] = field(default=None)
    zone_deprecated: Optional[GcpDeprecationStatus] = field(default=None)
    zone_supports_pzs: Optional[bool] = field(default=None)
