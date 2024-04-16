from __future__ import annotations

import json
import logging
from concurrent.futures import Future
from threading import Lock
from types import TracebackType
from typing import Callable, List, ClassVar, Optional, TypeVar, Type, Any, Dict, Set, Tuple

from attr import define, field
from google.auth.credentials import Credentials as GoogleAuthCredentials
from googleapiclient.errors import HttpError

from fix_plugin_gcp.gcp_client import GcpClient, GcpApiSpec, InternalZoneProp, RegionProp
from fix_plugin_gcp.utils import Credentials
from fixlib.baseresources import (
    BaseResource,
    BaseAccount,
    Cloud,
    EdgeType,
    BaseRegion,
    BaseZone,
    ModelReference,
)
from fixlib.config import Config
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph, EdgeKey
from fixlib.json import from_json as from_js, value_in_path
from fixlib.json_bender import bend, Bender, S, Bend, MapDict, F
from fixlib.threading import ExecutorQueue
from fixlib.types import Json
from fixinventorydata.cloud import regions as cloud_region_data

log = logging.getLogger("fix.plugins.gcp")


T = TypeVar("T")


def get_client(resource: BaseResource) -> GcpClient:
    project = resource.account()
    assert isinstance(project, GcpProject)
    return GcpClient(
        Credentials.get(project.id),
        project_id=project.id,
        region=resource.region().name if resource.region() else None,
    )


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        project: GcpProject,
        credentials: GoogleAuthCredentials,
        executor: ExecutorQueue,
        core_feedback: CoreFeedback,
        fallback_global_region: GcpRegion,
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
        self.fallback_global_region = fallback_global_region
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
        return self.executor.submit_work(self.project.id, fn, *args, **kwargs)

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

        if self._standard_edges(node, source):
            with self.graph_nodes_access:
                self.graph.add_node(node, source=source or {})
            return node
        return None

    def _standard_edges(self, node: GcpResourceType, source: Optional[Json] = None) -> bool:
        if isinstance(node, GcpRegion):
            self.add_edge(node, node=self.project, reverse=True)
            return True
        if node._zone:
            self.add_edge(node, node=node._zone, reverse=True)
            return True
        if node._region:
            self.add_edge(node, node=node._region, reverse=True)
            return True

        if source is not None:
            if InternalZoneProp in source:
                if zone := self.zone_by_name.get(source[InternalZoneProp]):
                    node._zone = zone
                    node._region = self.region_by_zone_name[source[InternalZoneProp]]
                    self.add_edge(node, node=zone, reverse=True)
                    return True
                else:
                    log.debug(f"Zone {source[InternalZoneProp]} not found for node: {node}. Ignore resource.")
                    return False

            if RegionProp in source:
                region_name = source[RegionProp].rsplit("/", 1)[-1]
                if region := self.region_by_name.get(region_name):
                    node._region = region
                    self.add_edge(node, node=region, reverse=True)
                    return True
                else:
                    log.debug(f"Region {region_name} not found for node: {node}. Ignore resource.")
                    return False

        # Fallback to GraphBuilder region, i.e. regional collection
        if self.region is not None:
            node._region = self.region
            self.add_edge(node, node=self.region, reverse=True)
            return True

        # Fallback to global region
        node._region = self.fallback_global_region
        self.add_edge(node, node=self.fallback_global_region, reverse=True)
        return True

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
            self.fallback_global_region,
            region,
            self.graph_nodes_access,
            self.graph_edges_access,
        )


@define(eq=False, slots=False)
class GcpResource(BaseResource):
    kind: ClassVar[str] = "gcp_resource"
    kind_display: ClassVar[str] = "GCP Resource"
    kind_description: ClassVar[str] = (
        "GCP Resource refers to any resource or service available on the Google Cloud"
        " Platform, such as virtual machines, databases, storage buckets, and"
        " networking components."
    )
    api_spec: ClassVar[Optional[GcpApiSpec]] = None
    mapping: ClassVar[Dict[str, Bender]] = {}

    description: Optional[str] = None
    deprecation_status: Optional[GcpDeprecationStatus] = None
    link: Optional[str] = None
    label_fingerprint: Optional[str] = None

    def _keys(self) -> Tuple[Any, ...]:
        if self.link is not None:
            return tuple(list(super()._keys()) + [self.link])
        return super()._keys()

    def delete(self, graph: Graph) -> bool:
        if not self.api_spec:
            return False
        client = get_client(self)
        client.delete(
            self.api_spec.for_delete(),
            zone=self.zone().name,
            resource=self.name,
        )
        return True

    def update_tag(self, key: str, value: Optional[str]) -> bool:
        if not self.api_spec:
            return False
        client = get_client(self)

        labels = dict(self.tags)
        if value is None:
            if key in labels:
                del labels[key]
            else:
                return False
        else:
            labels.update({key: value})
        try:
            client.set_labels(
                self.api_spec.for_set_labels(),
                body={"labels": labels, "labelFingerprint": self.label_fingerprint},
                zone=self.zone().name,
                resource=self.name,
            )
        except AttributeError:
            log.debug(f"resources of type {self.kind} cannot be labeled.")
            return False
        # Retrieve updated label fingerprint
        result = client.get(
            self.api_spec.for_get(),
            zone=self.zone().name,
            resource=self.name,
        )
        self.label_fingerprint = result.get("labelFingerprint")
        return True

    def delete_tag(self, key: str) -> bool:
        return self.update_tag(key, None)

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

    def post_process_instance(self, builder: GraphBuilder, source: Json) -> None:
        """
        Hook method to post process the resource after all connections are done.
        Default: do nothing.
        """
        pass

    @classmethod
    def collect_resources(cls: Type[GcpResource], builder: GraphBuilder, **kwargs: Any) -> List[GcpResource]:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"[Gcp:{builder.project.id}] Collecting {cls.__name__} with ({kwargs})")
        if spec := cls.api_spec:
            expected_errors = GcpExpectedErrorCodes | (spec.expected_errors or set())
            with GcpErrorHandler(builder.core_feedback, expected_errors, f" in {builder.project.id} kind {cls.kind}"):
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

    @classmethod
    def called_collect_apis(cls) -> List[GcpApiSpec]:
        # The default implementation will return the defined api_spec if defined, otherwise an empty list.
        # In case your resource needs more than this api call, please override this method and return the proper list.
        if spec := cls.api_spec:
            return [spec]
        else:
            return []

    @classmethod
    def called_mutator_apis(cls) -> List[GcpApiSpec]:
        # The default implementation will return the defined api_spec for delete, set_labels and get if defined.
        # delete: spec.for_delete()
        # update_tag/delete_tag: spec.for_set_labels(), spec.for_get()
        if spec := cls.api_spec:
            return [spec.for_delete(), spec.for_set_labels(), spec.for_get()]
        else:
            return []


GcpResourceType = TypeVar("GcpResourceType", bound=GcpResource)


@define(eq=False, slots=False)
class GcpProject(GcpResource, BaseAccount):
    kind: ClassVar[str] = "gcp_project"
    kind_display: ClassVar[str] = "GCP Project"
    kind_description: ClassVar[str] = (
        "A GCP Project is a container for resources in the Google Cloud Platform,"
        " allowing users to organize and manage their cloud resources."
    )


@define(eq=False, slots=False)
class GcpDeprecationStatus:
    kind: ClassVar[str] = "gcp_deprecation_status"
    kind_display: ClassVar[str] = "GCP Deprecation Status"
    kind_description: ClassVar[str] = (
        "GCP Deprecation Status is a feature in Google Cloud Platform that provides"
        " information about the deprecation status of various resources and services,"
        " helping users stay updated on any upcoming changes or removals."
    )
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
class GcpLimit:
    kind: ClassVar[str] = "gcp_quota"
    kind_display: ClassVar[str] = "GCP Quota"
    kind_description: ClassVar[str] = (
        "Quota in GCP (Google Cloud Platform) represents the maximum limit of"
        " resources that can be used for a particular service, such as compute"
        " instances, storage, or API calls. It ensures resource availability and helps"
        " manage usage and costs."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "limit": S("limit"),
        "usage": S("usage"),
        "percentage": F(lambda x: round(x.get("usage", 0) / max(x.get("limit", 1), 1) * 100, 2)),
    }
    limit: Optional[float] = field(default=None)
    usage: Optional[float] = field(default=None)
    percentage: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpRegionQuota(GcpResource):
    kind: ClassVar[str] = "gcp_region_quota"
    kind_display: ClassVar[str] = "GCP Region Quota"
    kind_description: ClassVar[str] = (
        "Region Quota in GCP refers to the maximum limits of resources that can be"
        " provisioned in a specific region, such as compute instances, storage, or"
        " networking resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "description": S("description"),
        "quotas": S("quotas", default=[]) >> MapDict(S("metric") >> F(lambda x: x.lower()), Bend(GcpLimit.mapping)),
    }
    quotas: Optional[Dict[str, GcpLimit]] = field(default=None)


@define(eq=False, slots=False)
class GcpRegion(GcpResource, BaseRegion):
    kind: ClassVar[str] = "gcp_region"
    kind_display: ClassVar[str] = "GCP Region"
    kind_description: ClassVar[str] = (
        "A GCP Region is a specific geographical location where Google Cloud Platform"
        " resources are deployed and run."
    )
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
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
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
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["gcp_zone"]}}
    description: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    region_deprecated: Optional[GcpDeprecationStatus] = field(default=None)
    region_supports_pzs: Optional[bool] = field(default=None)

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.long_name = cloud_region_data.get("gcp", {}).get(self.id, {}).get("long_name")
        self.latitude = cloud_region_data.get("gcp", {}).get(self.id, {}).get("latitude")
        self.longitude = cloud_region_data.get("gcp", {}).get(self.id, {}).get("longitude")

    @classmethod
    def fallback_global_region(cls: Type[GcpRegion], project: GcpProject) -> GcpRegion:
        return cls(id="global", tags={}, name="global", account=project)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        region_quota = GcpRegionQuota.from_api(source)
        graph_builder.add_node(region_quota, source)
        graph_builder.add_edge(self, node=region_quota)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for zone_link in source.get("zones", []):
            builder.add_edge(self, clazz=GcpZone, link=zone_link)


@define(eq=False, slots=False)
class GcpZone(GcpResource, BaseZone):
    kind: ClassVar[str] = "gcp_zone"
    kind_display: ClassVar[str] = "GCP Zone"
    kind_description: ClassVar[str] = (
        "A GCP Zone is a specific geographic location where Google Cloud Platform"
        " resources can be deployed. Zones are isolated from each other within a"
        " region, providing fault tolerance and high availability for applications and"
        " services."
    )
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
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
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


GcpExpectedErrorCodes = {
    "PERMISSION_DENIED:usageLimits:accessNotConfigured"  # resource not enabled - no resources to expect
}


class GcpErrorHandler:
    def __init__(self, core_feedback: CoreFeedback, expected_errors: Set[str], extra_info: str = "") -> None:
        self.core_feedback = core_feedback
        self.extra_info = extra_info
        self.expected_errors = expected_errors

    def __enter__(self) -> "GcpErrorHandler":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[Exception]],
        exc_value: Optional[Exception],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        if exc_type is None:
            return None

        error_details = str(exc_value)
        errors: Set[str] = set()
        if exc_type is HttpError and isinstance(exc_value, HttpError):
            try:
                exc_content: Json = json.loads(exc_value.content.decode())
                status = value_in_path(exc_content, ["error", "status"])
                errors = {
                    f'{status}:{error.get("domain", "none")}:{error.get("reason", "none")}'
                    for error in (value_in_path(exc_content, ["error", "errors"]) or [])
                }
                error_details = str(exc_content.get("error", {}).get("message", exc_value))
            except Exception as ex:
                errors = {f"ParseError:unknown:{ex}"}
                pass
        error_summary = ", ".join(errors)

        if errors and errors.issubset(self.expected_errors):
            log.info(
                f"Expected Exception while collecting{self.extra_info} ({exc_type.__name__}): "
                f"{error_details} Error Codes: {error_summary}. Ignore."
            )
            return True

        if not Config.gcp.discard_account_on_resource_error:
            self.core_feedback.error(
                f"Error while collecting{self.extra_info} ({exc_type.__name__}): "
                f"{error_details} Error Codes: {error_summary}",
                log,
            )
            return True

        if exc_type is HttpError and isinstance(exc_value, HttpError):
            if exc_value.resp.status == 403:
                self.core_feedback.error(
                    f"Access denied{self.extra_info}: {error_details} Error Codes: {error_summary}", log
                )
                return True

        return False
