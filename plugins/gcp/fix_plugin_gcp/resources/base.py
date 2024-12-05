from __future__ import annotations

from datetime import datetime, timedelta
import json
import logging
from concurrent.futures import Future
from threading import Lock
from types import TracebackType
from typing import Callable, List, ClassVar, Optional, TypeVar, Type, Any, Dict, Set, Tuple

from attr import define, field
from attrs import frozen
from frozendict import frozendict
from google.auth.credentials import Credentials as GoogleAuthCredentials
from googleapiclient.errors import HttpError

from fix_plugin_gcp.config import GcpConfig
from fix_plugin_gcp.gcp_client import GcpClient, GcpApiSpec, InternalZoneProp, ZoneProp, RegionProp
from fix_plugin_gcp.utils import Credentials
from fixlib.baseresources import (
    BaseResource,
    BaseAccount,
    Cloud,
    EdgeType,
    BaseRegion,
    BaseZone,
    ModelReference,
    PhantomBaseResource,
    MetricName,
    MetricUnit,
    StatName,
)
from fixlib.config import Config
from fixlib.core.actions import CoreFeedback, ErrorAccumulator
from fixlib.graph import Graph, EdgeKey
from fixlib.json import from_json as from_js, value_in_path
from fixlib.json_bender import bend, Bender, S, Bend, MapDict, F
from fixlib.threading import ExecutorQueue
from fixlib.types import Json
from fixlib.utils import utc
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


def parse_json(
    json: Json, clazz: Type[T], builder: Optional[GraphBuilder] = None, mapping: Optional[Dict[str, Bender]] = None
) -> Optional[T]:
    """
    Use this method to parse json into a class. If the json can not be parsed, the error is reported to the core.
    Based on configuration, either the exception is raised or None is returned.
    :param json: the json to parse.
    :param clazz: the class to parse into.
    :param builder: the graph builder.
    :param mapping: the optional mapping to apply before parsing.
    :return: The parsed object or None.
    """
    try:
        mapped = bend(mapping, json) if mapping is not None else json
        return from_js(mapped, clazz)
    except Exception as e:
        if builder:
            # report and log the error
            builder.core_feedback.error(f"Failed to parse json into {clazz.__name__}: {e}. Source: {json}", log)
        return None


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        project: GcpProject,
        credentials: GoogleAuthCredentials,
        executor: ExecutorQueue,
        core_feedback: CoreFeedback,
        error_accumulator: ErrorAccumulator,
        fallback_global_region: GcpRegion,
        config: GcpConfig,
        region: Optional[GcpRegion] = None,
        last_run_started_at: Optional[datetime] = None,
        graph_nodes_access: Optional[Lock] = None,
        graph_edges_access: Optional[Lock] = None,
        after_collect_actions: Optional[List[Callable[[], Any]]] = None,
    ) -> None:
        self.graph = graph
        self.cloud = cloud
        self.region = region
        self.project = project
        self.client = GcpClient(credentials, project_id=project.id, region=region.name if region else None)
        self.executor = executor
        self.name = f"GCP:{project.name}"
        self.core_feedback = core_feedback
        self.error_accumulator = error_accumulator
        self.fallback_global_region = fallback_global_region
        self.config = config
        self.created_at = utc()
        self.last_run_started_at = last_run_started_at
        self.region_by_name: Dict[str, GcpRegion] = {}
        self.region_by_zone_name: Dict[str, GcpRegion] = {}
        self.zone_by_name: Dict[str, GcpZone] = {}
        self.graph_nodes_access = graph_nodes_access or Lock()
        self.graph_edges_access = graph_edges_access or Lock()
        self.after_collect_actions = after_collect_actions if after_collect_actions is not None else []

        if last_run_started_at:
            now = utc()

            # limit the metrics to the last 2 hours
            if now - last_run_started_at > timedelta(hours=2):
                start = now - timedelta(hours=2)
            else:
                start = last_run_started_at

            delta = now - start

            min_delta = max(delta, timedelta(seconds=60))
            # in case the last collection happened too quickly, raise the metrics timedelta to 60s,
            if min_delta != delta:
                start = now - min_delta
                delta = min_delta
        else:
            now = utc()
            delta = timedelta(hours=1)
            start = now - delta

        self.metrics_start = start
        self.metrics_delta = delta

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

    def add_node(self, node: GcpResourceType, source: Optional[Json] = None) -> GcpResourceType:
        log.debug(f"{self.name}: add node {node}")
        node._cloud = self.cloud
        node._account = self.project

        self.add_region_to_node(node, source)
        with self.graph_nodes_access:
            self.graph.add_node(node, source=source or {})
        return node

    def add_region_to_node(self, node: GcpResourceType, source: Optional[Json] = None) -> None:
        if isinstance(node, GcpRegion):
            self.add_edge(node, node=self.project, reverse=True)
            return
        if node._zone:
            self.add_edge(node, node=node._zone, reverse=True)
            return
        if node._region:
            self.add_edge(node, node=node._region, reverse=True)
            return

        parts = node.id.split("/", maxsplit=4)
        if len(parts) > 3 and parts[0] == "projects":
            if parts[2] in ["locations", "zones", "regions"]:
                location_name = parts[3]
                # Check for zone first
                if zone := self.zone_by_name.get(location_name):
                    node._zone = zone
                    node._region = self.region_by_zone_name.get(zone.id)
                    self.add_edge(zone, node=node)
                    return

                # Then check for region
                if region := self.region_by_name.get(location_name):
                    node._region = region
                    self.add_edge(region, node=node)
                    return

        if source is not None:
            if ZoneProp in source:
                zone_name = source[ZoneProp].rsplit("/", 1)[-1]
                if zone := self.zone_by_name.get(zone_name):
                    node._zone = zone
                    node._region = self.region_by_zone_name[zone_name]
                    self.add_edge(node, node=zone, reverse=True)
                    return
                else:
                    log.debug(
                        "Zone property '%s' found in the source but no corresponding zone object is available to associate with the node.",
                        zone_name,
                    )

            if InternalZoneProp in source:
                if zone := self.zone_by_name.get(source[InternalZoneProp]):
                    node._zone = zone
                    node._region = self.region_by_zone_name[source[InternalZoneProp]]
                    self.add_edge(node, node=zone, reverse=True)
                    return
                else:
                    log.debug(
                        "Internal zone property '%s' exists in the source but no corresponding zone object is available to associate with the node.",
                        source[InternalZoneProp],
                    )

            if RegionProp in source:
                region_name = source[RegionProp].rsplit("/", 1)[-1]
                if region := self.region_by_name.get(region_name):
                    node._region = region
                    self.add_edge(node, node=region, reverse=True)
                    return
                else:
                    log.debug(
                        "Region property '%s' found in the source but no corresponding region object is available to associate with the node.",
                        region_name,
                    )

        # Fallback to GraphBuilder region, i.e. regional collection
        if self.region is not None:
            node._region = self.region
            self.add_edge(node, node=self.region, reverse=True)
            return

        # Fallback to global region
        node._region = self.fallback_global_region
        self.add_edge(node, node=self.fallback_global_region, reverse=True)

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
            self.error_accumulator,
            self.fallback_global_region,
            self.config,
            region,
            self.last_run_started_at,
            self.graph_nodes_access,
            self.graph_edges_access,
            after_collect_actions=self.after_collect_actions,
        )


@frozen(kw_only=True)
class MetricNormalization:
    unit: MetricUnit
    normalize_value: Callable[[float], float] = lambda x: x
    compute_stats: Callable[[List[float]], List[Tuple[float, Optional[StatName]]]] = lambda x: [(sum(x) / len(x), None)]


@define(hash=True, frozen=True)
class GcpMonitoringQuery:
    metric_name: MetricName  # final name of the metric
    query_name: str  # name of the metric (e.g., GCP metric type)
    period: timedelta  # period of the metric
    ref_id: str  # unique id of the resource
    metric_id: str  # unique metric identifier
    stat: str  # aggregation type, supports ALIGN_MEAN, ALIGN_MAX, ALIGN_MIN
    project_id: str  # GCP project name
    normalization: MetricNormalization  # normalization info
    metric_filters: frozendict[str, str]  # filters for the metric

    @staticmethod
    def create(
        *,
        query_name: str,
        period: timedelta,
        ref_id: str,
        metric_name: MetricName,
        stat: str,
        project_id: str,
        metric_filters: Dict[str, str],
        normalization: MetricNormalization,
    ) -> "GcpMonitoringQuery":
        filter_suffix = "/" + "/".join(f"{key}={value}" for key, value in sorted(metric_filters.items()))
        metric_id = f"{query_name}/{ref_id}/{stat}{filter_suffix}"
        return GcpMonitoringQuery(
            metric_name=metric_name,
            query_name=query_name,
            period=period,
            ref_id=ref_id,
            metric_id=metric_id,
            stat=stat,
            normalization=normalization,
            project_id=project_id,
            metric_filters=frozendict(metric_filters),
        )


@define(eq=False, slots=False)
class GcpResource(BaseResource):
    kind: ClassVar[str] = "gcp_resource"
    _kind_display: ClassVar[str] = "GCP Resource"
    _kind_description: ClassVar[str] = "A GCP Resource is a specific instance of a service or component within Google Cloud Platform. It represents a unit of cloud infrastructure or functionality, such as a virtual machine, storage bucket, or database. GCP Resources are created, managed, and organized to build and operate cloud-based applications and services on the Google Cloud Platform."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/docs"
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

    @property
    def resource_raw_name(self) -> str:
        """
        Extracts the last segment of the GCP resource ID.

        Returns:
            str: The last segment of the resource ID (e.g., "function-1" from "projects/{project}/locations/{location}/functions/function-1").
        """
        return self.id.rsplit("/", maxsplit=1)[-1]

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

    def collect_usage_metrics(self, builder: GraphBuilder) -> List[GcpMonitoringQuery]:
        # Default behavior: do nothing
        return []

    @classmethod
    def collect_resources(cls: Type[GcpResource], builder: GraphBuilder, **kwargs: Any) -> List[GcpResource]:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        if spec := cls.api_spec:
            expected_errors = GcpExpectedErrorCodes | (spec.expected_errors or set())
            with GcpErrorHandler(
                spec.action,
                builder.error_accumulator,
                spec.service,
                builder.region.safe_name if builder.region else None,
                expected_errors,
                f" in {builder.project.id} kind {cls.kind}",
            ):
                items = builder.client.list(spec, **kwargs)
                resources = cls.collect(items, builder)
                log.info(
                    f"[GCP:{builder.project.id}:{builder.region.safe_name if builder.region else "global"}] finished collecting: {cls.kind}"
                )
                return resources
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
            if instance := cls.from_api(js, builder):
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
    def from_api(
        cls: Type[GcpResourceType], json: Json, builder: Optional[GraphBuilder] = None
    ) -> Optional[GcpResourceType]:
        return parse_json(json, cls, builder, cls.mapping)

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
    _kind_display: ClassVar[str] = "GCP Project"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "access_control", "group": "networking"}
    _kind_description: ClassVar[str] = "A GCP Project is a container for organizing and managing resources on Google Cloud Platform. It groups related services, applications, and configurations under a single entity. Projects provide access control, billing, and resource allocation mechanisms. Users can create, modify, and delete resources within projects, ensuring separation and organization of cloud assets across different initiatives or teams."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/resource-manager/docs/creating-managing-projects"


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
class GcpRegionQuota(GcpResource, PhantomBaseResource):
    kind: ClassVar[str] = "gcp_region_quota"
    _kind_display: ClassVar[str] = "GCP Region Quota"
    _kind_description: ClassVar[str] = "GCP Region Quota is a Google Cloud Platform feature that limits resource usage within specific geographic regions. It controls the number of resources, such as virtual machines or storage capacity, that can be created in a given region. This helps manage costs, ensure resource availability, and comply with regional regulations or organizational policies."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/compute/quotas#region_quotas"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "quota", "group": "misc"}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "description": S("description"),
        "quotas": S("quotas", default=[]) >> MapDict(S("metric") >> F(lambda x: x.lower()), Bend(GcpLimit.mapping)),
    }
    quotas: Optional[Dict[str, GcpLimit]] = field(default=None, metadata=dict(ignore_history=True))


@define(eq=False, slots=False)
class GcpRegion(GcpResource, BaseRegion):
    kind: ClassVar[str] = "gcp_region"
    _kind_display: ClassVar[str] = "GCP Region"
    _kind_description: ClassVar[str] = "A GCP Region is a geographic area where Google Cloud Platform resources are hosted. It consists of multiple data centers called zones. Regions provide redundancy and reduced latency for cloud services. Users can deploy applications and store data in specific regions to meet performance, compliance, or data residency requirements."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/compute/docs/regions-zones"
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
    _reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["gcp_zone"]}}
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
        if region_quota := GcpRegionQuota.from_api(source, graph_builder):
            graph_builder.add_node(region_quota, source)
            graph_builder.add_edge(self, node=region_quota)

    def compute_region_in_use(self, graph_builder: GraphBuilder) -> bool:
        ignore_kinds = {
            "gcp_subnetwork",  # There are subnetworks that are created by GCP automatically.
        }

        def ignore_for_count(resource: BaseResource) -> bool:
            if isinstance(resource, PhantomBaseResource):
                return True
            if resource.kind in ignore_kinds:
                return True
            return False

        # A region with less than 3 real resources is considered not in use.
        # GCP is creating a couple of resources in every region automatically.
        count = 0
        empty_region = 3
        for succ in graph_builder.graph.descendants(self):
            if not ignore_for_count(succ):
                count += 1
                if count > empty_region:
                    break

        in_use = count > empty_region
        self.region_in_use = in_use
        return in_use

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for zone_link in source.get("zones", []):
            builder.add_edge(self, clazz=GcpZone, link=zone_link)


@define(eq=False, slots=False)
class GcpZone(GcpResource, BaseZone):
    kind: ClassVar[str] = "gcp_zone"
    _kind_display: ClassVar[str] = "GCP Zone"
    _kind_description: ClassVar[str] = "A GCP Zone is a specific geographical location within a Google Cloud Platform region where computing resources are hosted. It contains data centers with independent power, cooling, and networking infrastructure. Zones provide isolation for workloads and help improve fault tolerance and availability by distributing resources across multiple physical locations within a region."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/compute/docs/regions-zones"
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
    def __init__(
        self,
        action: str,
        error_accumulator: ErrorAccumulator,
        service: str,
        region: Optional[str],
        expected_errors: Set[str],
        extra_info: str = "",
        expected_message_substrings: Optional[Set[str]] = None,
    ) -> None:
        self.action = action
        self.error_accumulator = error_accumulator
        self.service = service
        self.region = region
        self.extra_info = extra_info
        self.expected_errors = expected_errors
        self.expected_message_substrings = expected_message_substrings

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
            if exc_value.resp.status == 404 and "HttpError:none:none" in self.expected_errors:
                return True
            try:
                exc_content: Json = json.loads(exc_value.content.decode())
                status = value_in_path(exc_content, ["error", "status"])
                errors = {
                    f'{status}:{error.get("domain", "none")}:{error.get("reason", "none")}'
                    for error in (value_in_path(exc_content, ["error", "errors"]) or [])
                }
                error_details = str(exc_content.get("error", {}).get("message", exc_value))
                # Check if error message matches any of the expected substrings
                if self.expected_message_substrings:
                    for substring in self.expected_message_substrings:
                        if substring in error_details:
                            return True  # Suppress the exception
            except Exception as ex:
                errors = {f"ParseError:unknown:{ex}"}
        error_summary = " Error Codes: " + (", ".join(errors)) if errors else ""

        if errors and errors.issubset(self.expected_errors):
            log.debug(
                f"Expected Exception while collecting{self.extra_info} ({exc_type.__name__}): "
                f"{error_details}{error_summary}. Ignore."
            )
            return True

        if not Config.gcp.discard_account_on_resource_error:
            if exc_type is HttpError and isinstance(exc_value, HttpError):
                if exc_value.resp.status == 403:
                    self.error_accumulator.add_error(
                        as_info=False,
                        error_kind="AccessDenied",
                        service=self.service,
                        action=self.action,
                        message=f"Access denied: {error_details}",
                        region=None,
                    )
                    return True

            self.error_accumulator.add_error(
                as_info=False,
                error_kind=exc_type.__name__,
                service=self.service,
                action=self.action,
                message=f"Error while collecting{self.extra_info}: {error_details}{error_summary}",
                region=self.region,
            )
            return True

        return False
