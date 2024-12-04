from __future__ import annotations

import base64
import hashlib
import weakref
from abc import ABC, abstractmethod
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timedelta
from enum import Enum, StrEnum, unique
from functools import wraps, cached_property
from typing import Dict, Iterator, List, ClassVar, Optional, TypedDict, Any, TypeVar, Type, Callable, Set, Tuple

from attr import resolve_types
from attrs import define, field, Factory, frozen, evolve
from prometheus_client import Counter, Summary

from fixlib.basecategories import Category
from fixlib.json import from_json as _from_json, to_json as _to_json, to_json_str
from fixlib.logger import log
from fixlib.types import Json
from fixlib.utils import make_valid_timestamp, utc_str, utc

metrics_resource_pre_cleanup_exceptions = Counter(
    "resource_pre_cleanup_exceptions_total",
    "Number of resource pre_cleanup() exceptions",
    ["cloud", "account", "region", "kind"],
)
metrics_resource_cleanup_exceptions = Counter(
    "resource_cleanup_exceptions_total",
    "Number of resource cleanup() exceptions",
    ["cloud", "account", "region", "kind"],
)
metrics_resource_cleanup = Summary("fix_resource_cleanup_seconds", "Time it took the resource cleanup() method")


def unless_protected(f: Callable[..., bool]) -> Callable[..., bool]:
    @wraps(f)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> bool:
        if not isinstance(self, BaseResource):
            raise ValueError("unless_protected() only supports BaseResource type objects")
        if self.protected:
            log.error(f"Resource {self.rtdname} is protected - refusing modification")
            self.log(("Modification was requested even though resource is protected" " - refusing"))
            return False
        return f(self, *args, **kwargs)

    return wrapper


# To define predecessors and successors of a resource by kind
# Example:
# reference_kinds: ClassVar[ModelReference] = {
#   "successors": {"default": ["base"], "delete": ["other_kind"]]},
#   "predecessors": {"delete": ["other"]},
# }
class ModelReferenceEdges(TypedDict, total=False):
    default: List[str]
    delete: List[str]


class ModelReference(TypedDict, total=False):
    predecessors: ModelReferenceEdges
    successors: ModelReferenceEdges


class EdgeType(Enum):
    default = "default"
    delete = "delete"
    iam = "iam"

    @staticmethod
    def from_value(value: Optional[str] = None) -> EdgeType:
        try:
            return EdgeType(value)
        except ValueError:
            pass
        return EdgeType.default


class ResourceChanges:
    def __init__(self, node: BaseResource) -> None:
        self.node = node
        self.reported: Set[str] = set()
        self.desired: Set[str] = set()
        self.metadata: Set[str] = set()
        self.changed = False

    def add(self, property: str) -> None:
        if property == "tags":
            self.reported.add(property)
        elif property == "clean":
            self.desired.add(property)
        elif property in ("cleaned", "protected"):
            self.metadata.add(property)
        elif property == "log":
            pass
        else:
            raise ValueError(f"Unknown property {property}")
        self.changed = True

    def get(self) -> Dict[str, Any]:
        changes: Dict[str, Any] = {}
        for section in ("reported", "desired", "metadata"):
            for attribute in getattr(self, section, []):
                if section not in changes:
                    changes[section] = {}
                try:
                    changes[section][attribute] = getattr(self.node, attribute)
                except AttributeError:
                    log.error(f"Resource {self.node.rtdname} has no attribute {attribute}")
        if len(self.node.event_log) > 0:
            if "metadata" not in changes:
                changes[section] = {}
            changes["metadata"]["event_log"] = self.node.str_event_log
        return changes


class MetricName(StrEnum):
    def __str__(self) -> str:
        return self.value

    # instances
    CpuUtilization = "cpu_utilization"
    NetworkIn = "network_in"
    NetworkOut = "network_out"
    DiskRead = "disk_read"
    DiskWrite = "disk_write"
    ReadThroughput = "read_throughput"
    WriteThroughput = "write_throughput"

    # volumes
    VolumeWrite = "volume_write"
    VolumeRead = "volume_read"
    VolumeTotalWriteTime = "volume_total_write_time"
    VolumeIdleTime = "volume_idle_time"
    VolumeQueueLength = "volume_queue_length"
    NumberOfObjects = "number_of_objects"
    BucketSizeBytes = "bucket_size"
    UsedCapacity = "used_capacity"
    BlobCount = "blob"  # _count will be added to the end because of the unit
    BlobCapacity = "blob_capacity"
    QueueCount = "queue"  # _count will be added to the end because of the unit
    QueueCapacity = "queue_capacity"
    FileCount = "file"  # _count will be added to the end because of the unit
    FileCapacity = "file_capacity"
    TableCount = "table"  # _count will be added to the end because of the unit
    TableCapacity = "table_capacity"

    # load balancers
    RequestCount = "request"  # _count will be added to the end because of the unit
    RequestBytesCount = "request_bytes"  # _count will be added to the end because of the unit
    ResponseBytesCount = "response_bytes"  # _count will be added to the end because of the unit
    ActiveConnectionCount = "active_connection"  # _count will be added to the end because of the unit
    ALBActiveConnectionCount = "alb_active_connection"  # _count will be added to the end because of the unit
    ConnectionAttemptCount = "connection_attempt"  # _count will be added to the end because of the unit
    ConnectionEstablishedCount = "connection_established"  # _count will be added to the end because of the unit
    StatusCode2XX = "status_code_2xx"
    StatusCode4XX = "status_code_4xx"
    StatusCode5XX = "status_code_5xx"
    Latency = "latency"
    TargetResponseTime = "target_response_time"
    ProcessedBytes = "processed"  # _bytes will be added to the end because of the unit
    HealthyHostCount = "healthy_host"  # _count will be added to the end because of the unit
    UnHealthyHostCount = "unhealthy_host"  # _count will be added to the end because of the unit
    HealthyStateRouting = "healthy_state_routing"
    UnhealthyStateRouting = "unhealthy_state_routing"
    HealthyStateDNS = "healthy_state_dns"
    UnhealthyStateDNS = "unhealthy_state_dns"
    RejectedConnectionCount = "rejected_connection"
    IPv6RequestCount = "ipv6_request"
    IPv6ProcessedBytes = "ipv6_processed"
    ErrorPortAllocation = "error_port_allocation"
    IdleTimeoutCount = "idle_timeout"  # _count will be added to the end because of the unit
    PacketsDropCount = "packets_drop"  # _count will be added to the end because of the unit
    PacketsInFromDestination = "packets_in_from_destination"
    PacketsInFromSource = "packets_in_from_source"
    PacketsOutToDestination = "packets_out_to_destination"
    PacketsOutToSource = "packets_out_to_source"
    BytesInFromDestination = "bytes_in_from_destination"
    BytesInFromSource = "bytes_in_from_source"
    BytesOutToDestination = "bytes_out_to_destination"
    BytesOutToSource = "bytes_out_to_source"
    RecordsBytes = "records"  # _bytes will be added to the end because of the unit
    RecordsIteratorAgeMilliseconds = (
        "records_iterator_age"  # _milliseconds will be added to the end because of the unit
    )

    # databases
    DatabaseConnections = "database_connections"
    ReadLatency = "read_latency"
    WriteLatency = "write_latency"
    FreeStorageSpace = "free_storage_space"
    FreeableMemory = "freeable_memory"
    SwapUsage = "swap_usage"
    DiskQueueDepth = "disk_queue_depth"
    NetworkReceiveThroughput = "network_receive_throughput"
    NetworkTransmitThroughput = "network_transmit_throughput"
    NetworkBytesSent = "network_bytes_sent"
    NetworkBytesReceived = "network_bytes_received"

    # serverless
    Invocations = "invocations"
    Errors = "errors"
    Throttles = "throttles"
    Duration = "duration"
    ConcurrentExecutions = "concurrent_executions"

    # messages
    NumberOfMessagesPublished = "number_of_messages_published"
    NumberOfNotificationsDelivered = "number_of_notifications_delivered"
    NumberOfNotificationsFailed = "number_of_notifications_failed"
    PublishSize = "publish_size"
    ApproximateAgeOfOldestMessage = "approximate_age_of_oldest_message"
    ApproximateNumberOfMessagesDelayed = "approximate_number_of_messages_delayed"
    ApproximateNumberOfMessagesNotVisible = "approximate_number_of_messages_not_visible"
    ApproximateNumberOfMessagesVisible = "approximate_number_of_messages_visible"
    NumberOfMessagesReceived = "number_of_messages_received"
    NumberOfMessagesSent = "number_of_messages_sent"


class MetricUnit(str, Enum):
    def __str__(self) -> str:
        return self.value

    Count = "count"
    Bytes = "bytes"
    Seconds = "seconds"
    Milliseconds = "milliseconds"
    Percent = "percent"
    BytesPerSecond = "BytesPs"
    CountPerSecond = "CountPs"
    MegabitsPerSecond = "Mbps"
    MegabytesPerSecond = "MBps"
    PacketsPerSecond = "pps"
    IOPS = "iops"


class StatName(str, Enum):
    def __str__(self) -> str:
        return self.value

    min = "min"
    max = "max"
    avg = "avg"


MetricNameWithUnit = str


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


@define(slots=True)
class Finding:
    title: str
    severity: Severity = Severity.medium
    description: Optional[str] = None
    remediation: Optional[str] = None
    updated_at: Optional[datetime] = None
    details: Optional[Json] = None


SEVERITY_MAPPING = {
    "INFORMATIONAL": Severity.info,
    "LOW": Severity.low,
    "MEDIUM": Severity.medium,
    "HIGH": Severity.high,
    "CRITICAL": Severity.critical,
}


@define(slots=True)
class Assessment:
    # The provider of the security assessment
    provider: str
    # All findings of the security provider to this resource
    findings: List[Finding] = field(factory=list)


@define(eq=False, slots=False, kw_only=True)
class BaseResource(ABC):
    """
    Base class of all concrete resources.
    """

    ################################################################################
    # Class Variables

    # Every concrete resource type needs to override and define its own kind.
    kind: ClassVar[str] = "resource"
    # Human-readable name of the resource kind.
    _kind_display: ClassVar[str] = "Resource"
    # A description of the resource kind.
    _kind_description: ClassVar[str] = "A generic resource."
    # The cloud provider service that offers this resource kind.
    _kind_service: ClassVar[Optional[str]] = None
    # Define possible predecessors/successors of this resource kind.
    _reference_kinds: ClassVar[ModelReference] = {}
    # Metadata for the resource kind.
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "misc"}
    # Categories of this resource kind.
    _categories: ClassVar[List[Category]] = []
    # Link to the cloud providers product documentation of this resource kind.
    _docs_url: ClassVar[Optional[str]] = None
    # Mark this class as exportable. Use False for internal model classes without instances.
    _model_export: ClassVar[bool] = True

    ################################################################################
    # Instance Variables

    # Identifier of this resource. Does not need to be globally unique. chksum is used to compute a unique identifier.
    id: str
    # List if key/value pairs that describe this resource.
    tags: Dict[str, Optional[str]] = Factory(dict)
    # Name of this resource.
    name: Optional[str] = field(default=None)
    # The related cloud provider of this resource.
    _cloud: Optional[BaseCloud] = field(default=None, repr=False)
    # The related account of this resource.
    _account: Optional[BaseAccount] = field(default=None, repr=False)
    # The related region of this resource.
    _region: Optional[BaseRegion] = field(default=None, repr=False)
    # The related zone of this resource.
    _zone: Optional[BaseZone] = field(default=None, repr=False)
    # The id provided by fixcore. Only used for resources loaded from fixcore.
    _fixcore_id: Optional[str] = field(default=None, repr=False)
    # The revision id of this resource as defined by core. Only used for resources loaded from fixcore.
    _fixcore_revision: Optional[str] = field(default=None, repr=False)
    # Indicates if this resource is marked for cleanup.
    _clean: bool = False
    # Ephemeral state, indicating if this resource has been cleaned up.
    _cleaned: bool = False
    # Indicates if this resource is protected and not allowed to change.
    _protected: bool = False
    # List of deferred connections that need to be resolved in fixcore, after the resource is imported.
    _deferred_connections: List[Dict[str, Any]] = field(factory=list)
    # Usage of this resource since the last collect for specific metrics.
    _resource_usage: Dict[MetricNameWithUnit, Dict[str, float]] = field(factory=lambda: defaultdict(dict))
    # Deep link into the cloud provider's console
    _provider_link: Optional[str] = None
    # Assessment details for this resource: multiple providers can append their findings
    _assessments: List[Assessment] = field(factory=list)

    ctime: Optional[datetime] = field(
        default=None,
        metadata={"synthetic": {"age": "trafo.duration_to_datetime"}},
    )
    mtime: Optional[datetime] = field(
        default=None,
        metadata={"synthetic": {"last_update": "trafo.duration_to_datetime"}},
    )
    atime: Optional[datetime] = field(
        default=None,
        metadata={"synthetic": {"last_access": "trafo.duration_to_datetime"}},
    )

    def __attrs_post_init__(self) -> None:
        if self.name is None:
            self.name = self.id
        self._changes: ResourceChanges = ResourceChanges(self)
        self.__graph = None
        self.__log: List[Json] = []
        self._raise_tags_exceptions: bool = False
        if not hasattr(self, "_ctime"):
            self._ctime = None
        if not hasattr(self, "_atime"):
            self._atime = None
        if not hasattr(self, "_mtime"):
            self._mtime = None

    def _keys(self) -> Tuple[Any, ...]:
        """Return a tuple of all keys that make this resource unique

        Must not be called before the resource is connected to the graph
        as the relative location within the graph is used to determine the
        tuple of unique keys.

        E.g. instance -> aws -> 123457 -> us-east-1 -> us-east-1b -> i-987654 -> myServer
        """
        if self._graph is None:
            raise RuntimeError(f"_keys() called on {self.rtdname} before resource was added to graph")
        return self.kind, self.cloud().id, self.account().id, self.region().id, self.zone().id, self.id

    @property
    def safe_name(self) -> str:
        return self.name or self.id

    @property
    def dname(self) -> str:
        if self.id == self.name:
            return self.id
        return f"{self.name} ({self.id})"

    @property
    def kdname(self) -> str:
        return f"{self.kind} {self.dname}"

    rtdname = kdname

    @classmethod
    def from_json(cls: Type[BaseResourceType], json: Json) -> BaseResourceType:
        return _from_json(json, cls)

    def to_json(self) -> Json:
        return _to_json(self, strip_nulls=True)

    def log(self, msg: str, data: Optional[Any] = None, exception: Optional[Exception] = None) -> None:
        now = utc()
        log_entry = {
            "timestamp": now,
            "msg": str(msg),
            "exception": repr(exception) if exception else None,
            "data": deepcopy(data),
        }
        self.__log.append(log_entry)
        self._changes.add("log")

    def add_finding(self, provider: str, finding: Finding) -> None:
        for assessment in self._assessments:
            if assessment.provider == provider:
                assessment.findings.append(finding)
                return
        self._assessments.append(Assessment(provider=provider, findings=[finding]))

    def add_change(self, change: str) -> None:
        self._changes.add(change)

    @property
    def changes(self) -> ResourceChanges:
        return self._changes

    @property
    def event_log(self) -> List[Json]:
        return self.__log

    @property
    def str_event_log(self) -> List[Json]:
        return [
            {
                "timestamp": utc_str(le["timestamp"]),
                "msg": le["msg"],
                "exception": le["exception"],
            }
            for le in self.__log
        ]

    def update_tag(self, key: str, value: str) -> bool:
        raise NotImplementedError

    def delete_tag(self, key: str) -> bool:
        raise NotImplementedError

    @cached_property
    def chksum(self) -> str:
        """Return a checksum of the resource."""
        return (
            base64.urlsafe_b64encode(hashlib.blake2b(str(self._keys()).encode(), digest_size=16).digest())
            .decode("utf-8")
            .rstrip("=")
        )

    @property
    def age(self) -> Optional[timedelta]:
        now = utc()
        if self.ctime is not None:
            return now - self.ctime
        else:
            return None

    @property
    def last_access(self) -> Optional[timedelta]:
        now = utc()
        if self.atime is not None:
            return now - self.atime
        else:
            return None

    @property
    def last_update(self) -> Optional[timedelta]:
        now = utc()
        if self.mtime is not None:
            return now - self.mtime
        else:
            return None

    def _ctime_getter(self) -> Optional[datetime]:
        if ctime_string := self.tags.get("fix:ctime"):
            try:
                return make_valid_timestamp(datetime.fromisoformat(ctime_string))
            except ValueError:
                pass
        return self._ctime

    def _ctime_setter(self, value: Optional[datetime]) -> None:
        self._ctime = make_valid_timestamp(value) if value else None  # type: ignore

    def _atime_getter(self) -> Optional[datetime]:
        return self._atime

    def _atime_setter(self, value: Optional[datetime]) -> None:
        self._atime = make_valid_timestamp(value) if value else None  # type: ignore

    def _mtime_getter(self) -> Optional[datetime]:
        return self._mtime

    def _mtime_setter(self, value: Optional[datetime]) -> None:
        self._mtime = make_valid_timestamp(value) if value else None  # type: ignore

    @property
    def clean(self) -> bool:
        return self._clean

    @clean.setter
    @unless_protected
    def clean(self, value: bool) -> None:
        if isinstance(self, PhantomBaseResource) and value:
            raise ValueError(f"Can't cleanup phantom resource {self.rtdname}")

        clean_str = "" if value else "not "
        self.log(f"Setting to {clean_str}be cleaned")
        log.debug(f"Setting {self.rtdname} to {clean_str}be cleaned")
        self._changes.add("clean")
        self._clean = value

    @property
    def cleaned(self) -> bool:
        return self._cleaned

    @property
    def protected(self) -> bool:
        return self._protected

    @protected.setter
    def protected(self, value: bool) -> None:
        """Protects the resource from cleanup
        This property acts like a fuse, once protected it can't be unprotected
        """
        if self.protected:
            log.debug(f"Resource {self.rtdname} is already protected")
            return
        if value:
            log.debug(f"Protecting resource {self.rtdname}")
            self.log("Protecting resource")
            self._changes.add("protected")
            self._protected = value

    # deprecated. future collectors plugins should be responsible for running pre_cleanup
    # and calling delete_resource on resources
    @metrics_resource_cleanup.time()
    @unless_protected
    def cleanup(self, graph: Optional[Any] = None) -> bool:
        if isinstance(self, PhantomBaseResource):
            raise RuntimeError(f"Can't cleanup phantom resource {self.rtdname}")

        if self.cleaned:
            log.info(f"Resource {self.rtdname} has already been cleaned up")
            return True

        self._changes.add("cleaned")
        if graph is None:
            graph = self._graph

        account = self.account(graph)
        region = self.region(graph)
        if not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
            raise RuntimeError(f"Could not determine account or region for cleanup of {self.rtdname}")

        log_suffix = f" in account {account.dname} region {region.name}"
        self.log("Trying to clean up")
        log.info(f"Trying to clean up {self.rtdname}{log_suffix}")
        try:
            if deleted := self.delete(graph):
                self._cleaned = True
                self.log("Successfully cleaned up")
                log.info(f"Successfully cleaned up {self.rtdname}{log_suffix}")
        except Exception as e:
            self.log("An error occurred during clean up", exception=e)
            log.exception(f"An error occurred during clean up {self.rtdname}{log_suffix}")
            cloud = self.cloud(graph)
            metrics_resource_cleanup_exceptions.labels(
                cloud=cloud.name,
                account=account.dname,
                region=region.name,
                kind=self.kind,
            ).inc()
            raise
        if not deleted:
            raise RuntimeError(f"Failed to clean up {self.rtdname}{log_suffix}")
        return True

    # deprecated. future collectors plugins should be responsible for running pre_cleanup
    # and calling pre_delete_resource on resources
    @unless_protected
    def pre_cleanup(self, graph: Optional[Any] = None) -> bool:
        if not hasattr(self, "pre_delete"):
            return True

        if graph is None:
            graph = self._graph

        if isinstance(self, PhantomBaseResource):
            raise RuntimeError(f"Can't cleanup phantom resource {self.rtdname}")

        if self.cleaned:
            log.debug(f"Resource {self.rtdname} has already been cleaned up")
            return True

        account = self.account(graph)
        region = self.region(graph)
        if not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
            log.error(("Could not determine account or region for pre cleanup of" f" {self.rtdname}"))
            return False

        log_suffix = f" in account {account.dname} region {region.name}"
        self.log("Trying to run pre clean up")
        log.debug(f"Trying to run pre clean up {self.rtdname}{log_suffix}")
        try:
            if not getattr(self, "pre_delete")(graph):
                self.log("Failed to run pre clean up")
                log.error(f"Failed to run pre clean up {self.rtdname}{log_suffix}")
                return False
            self.log("Successfully ran pre clean up")
            log.info(f"Successfully ran pre clean up {self.rtdname}{log_suffix}")
        except Exception as e:
            self.log("An error occurred during pre clean up", exception=e)
            log.exception(f"An error occurred during pre clean up {self.rtdname}{log_suffix}")
            cloud = self.cloud(graph)
            metrics_resource_pre_cleanup_exceptions.labels(
                cloud=cloud.name,
                account=account.dname,
                region=region.name,
                kind=self.kind,
            ).inc()
            raise
        return True

    @unless_protected
    def delete(self, graph: Any) -> bool:
        return False

    def account(self, graph: Optional[Any] = None) -> "BaseAccount":
        account: Optional[BaseAccount] = None
        if graph is None:
            graph = self._graph
        if self._account:
            account = self._account
        elif graph:
            account = graph.search_first_parent_class(self, BaseAccount)
        if account is None:
            account = UnknownAccount(id="undefined", tags={})
        return account

    def cloud(self, graph: Optional[Any] = None) -> "BaseCloud":
        cloud: Optional[BaseCloud] = None
        if graph is None:
            graph = self._graph
        if self._cloud:
            cloud = self._cloud
        elif graph:
            cloud = graph.search_first_parent_class(self, BaseCloud)
        if cloud is None:
            cloud = UnknownCloud(id="undefined", tags={})
        return cloud

    def region(self, graph: Optional[Any] = None) -> "BaseRegion":
        region: Optional[BaseRegion] = None
        if graph is None:
            graph = self._graph
        if self._region:
            region = self._region
        elif graph:
            region = graph.search_first_parent_class(self, BaseRegion)
        if region is None:
            region = UnknownRegion(id="undefined", tags={})
        return region

    def zone(self, graph: Optional[Any] = None) -> "BaseZone":
        zone: Optional[BaseZone] = None
        if graph is None:
            graph = self._graph
        if self._zone:
            zone = self._zone
        elif graph:
            zone = graph.search_first_parent_class(self, BaseZone)
        if zone is None:
            zone = UnknownZone(id="undefined", tags={})
        return zone

    def resource_location(self, graph: Optional[Any] = None) -> "BaseResource":
        if graph is None:
            graph = self._graph
        zone = self.zone(graph)
        if zone.name != "undefined":
            return zone
        region = self.region(graph)
        if region.name != "undefined":
            return region
        account = self.account(graph)
        if account.name != "undefined":
            return account
        cloud = self.cloud(graph)
        if cloud.name != "undefined":
            return cloud
        return UnknownLocation(id="undefined", tags={})

    def add_deferred_connection(
        self, search: Dict[str, Any], parent: bool = True, edge_type: EdgeType = EdgeType.default
    ) -> None:
        self._deferred_connections.append({"search": search, "parent": parent, "edge_type": edge_type})

    def resolve_deferred_connections(self, graph: Any) -> None:
        if graph is None:
            graph = self._graph
        while self._deferred_connections:
            dc = self._deferred_connections.pop(0)
            node = graph.search_first_all(dc["search"])
            edge_type = dc["edge_type"]
            if node:
                if dc["parent"]:
                    src = node
                    dst = self
                else:
                    src = self
                    dst = node
                graph.add_edge(src, dst, edge_type=edge_type)

    def predecessors(self, graph: Optional[Any] = None, edge_type: Optional[EdgeType] = None) -> Iterator[BaseResource]:
        """Returns an iterator of the node's parent nodes"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return iter(())
        return graph.predecessors(self, edge_type=edge_type)  # type: ignore

    def successors(self, graph: Optional[Any] = None, edge_type: Optional[EdgeType] = None) -> Iterator[BaseResource]:
        """Returns an iterator of the node's child nodes"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return iter(())
        return graph.successors(self, edge_type=edge_type)  # type: ignore

    def predecessor_added(self, resource: BaseResource, graph: Any) -> None:
        """Called when a predecessor is added to this node"""
        pass

    def successor_added(self, resource: BaseResource, graph: Any) -> None:
        """Called when a successor is added to this node"""
        pass

    def ancestors(self, graph: Any, edge_type: Optional[EdgeType] = None) -> Iterator[BaseResource]:
        """Returns an iterator of the node's ancestors"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return iter(())
        return graph.ancestors(self, edge_type=edge_type)  # type: ignore

    def descendants(self, graph: Any, edge_type: Optional[EdgeType] = None) -> Iterator[BaseResource]:
        """Returns an iterator of the node's descendants"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return iter(())
        return graph.descendants(self, edge_type=edge_type)  # type: ignore

    @property
    def _graph(self) -> Optional[Any]:
        if self.__graph is not None:
            return self.__graph()
        else:
            return None

    @_graph.setter
    def _graph(self, value: Any) -> None:
        self.__graph = weakref.ref(value)  # type: ignore

    def __getstate__(self) -> Dict[str, Any]:
        ret = self.__dict__.copy()
        ret["_BaseResource__graph"] = None
        return ret

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)

    @classmethod
    def get_all_categories(cls: Type["BaseResource"]) -> List[Category]:
        def gather_categories(class_type: Type["BaseResource"]) -> List[Category]:
            merged = []
            for base in class_type.__bases__:
                if issubclass(base, BaseResource):
                    merged.extend(gather_categories(base))
            if hasattr(class_type, "_categories"):
                merged.extend(class_type._categories)
            return merged

        return list(set(gather_categories(cls)))

    @classmethod
    def categories(cls) -> List[str]:
        cs = {str(category.value) for category in cls.get_all_categories()}
        if group := cls._metadata.get("group"):
            cs.add(group)
        return list(cs)


BaseResource.ctime = property(BaseResource._ctime_getter, BaseResource._ctime_setter)  # type: ignore
BaseResource.mtime = property(BaseResource._mtime_getter, BaseResource._mtime_setter)  # type: ignore
BaseResource.atime = property(BaseResource._atime_getter, BaseResource._atime_setter)  # type: ignore


BaseResourceType = TypeVar("BaseResourceType", bound=BaseResource)


@define(eq=False, slots=False)
class PhantomBaseResource(BaseResource):
    kind: ClassVar[str] = "phantom_resource"
    _kind_display: ClassVar[str] = "Phantom Resource"
    _kind_description: ClassVar[str] = "A generic phantom resource."

    def update_tag(self, key: str, value: str) -> bool:
        log.error(f"Resource {self.rtdname} is a phantom resource and does not maintain tags")
        return False

    def delete_tag(self, key: str) -> bool:
        log.error(f"Resource {self.rtdname} is a phantom resource and does not maintain tags")
        return False

    def delete(self, graph: Any) -> bool:
        log.error(f"Resource {self.rtdname} is a phantom resource and can't be deleted")
        return False

    def cleanup(self, graph: Optional[Any] = None) -> bool:
        log.error(f"Resource {self.rtdname} is a phantom resource and can't be cleaned up")
        return False


@define(eq=False, slots=False)
class BaseQuota(PhantomBaseResource):
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "quota", "group": "management"}

    kind: ClassVar[str] = "quota"
    _kind_display: ClassVar[str] = "Quota"
    _kind_description: ClassVar[str] = "A service quota."
    quota: Optional[float] = None
    usage: Optional[float] = None
    quota_type: Optional[str] = None

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        if self.quota is not None:
            self.quota = float(self.quota)
        if self.usage is not None:
            self.usage = float(self.usage)

    @property
    def usage_percentage(self) -> float:
        if self.quota is not None and self.usage is not None and self.quota > 0.0:
            return self.usage / self.quota * 100
        else:
            return 0.0


@define(eq=False, slots=False)
class BaseType(BaseQuota):
    kind: ClassVar[str] = "type"
    _kind_display: ClassVar[str] = "Type"
    _kind_description: ClassVar[str] = "A generic type."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "type", "group": "management"}


@define(eq=False, slots=False)
class BaseInstanceQuota(BaseQuota):
    kind: ClassVar[str] = "instance_quota"
    _kind_display: ClassVar[str] = "Instance Quota"
    _kind_description: ClassVar[str] = "An instance quota."
    instance_type: Optional[str] = None
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "instance", "group": "compute"}

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.instance_type = self.id
        self.quota_type = "standard"


@define(eq=False, slots=False)
class BaseInstanceType(BaseType):
    kind: ClassVar[str] = "instance_type"
    _kind_display: ClassVar[str] = "Instance Type"
    _kind_description: ClassVar[str] = "An instance type."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "type", "group": "compute"}
    instance_type: Optional[str] = None
    instance_cores: float = 0.0
    instance_memory: float = 0.0
    ondemand_cost: Optional[float] = None
    reservations: Optional[int] = None

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        if self.instance_type is None:
            self.instance_type = self.id
        if self.reservations is not None:
            self.reservations = int(self.reservations)
        if self.ondemand_cost is not None:
            self.ondemand_cost = float(self.ondemand_cost)


@define(eq=False, slots=False)
class BaseCloud(PhantomBaseResource):
    kind: ClassVar[str] = "base_cloud"
    _kind_display: ClassVar[str] = "Cloud"
    _kind_description: ClassVar[str] = "A cloud."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "cloud", "group": "management"}

    def cloud(self, graph: Optional[Any] = None) -> BaseCloud:
        return self


@define(eq=False, slots=False)
class BaseAccount(BaseResource):
    kind: ClassVar[str] = "account"
    _kind_display: ClassVar[str] = "Account"
    _kind_description: ClassVar[str] = "An account."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "account", "group": "management"}

    def account(self, graph: Optional[Any] = None) -> BaseAccount:
        return self


@define(eq=False, slots=False)
class BaseRegion(PhantomBaseResource):
    kind: ClassVar[str] = "region"
    _kind_display: ClassVar[str] = "Region"
    _kind_description: ClassVar[str] = "A region."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "region", "group": "management"}

    long_name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    region_in_use: Optional[bool] = field(default=None, metadata={"description": "Indicates if the region is in use."})

    def _keys(self) -> Tuple[Any, ...]:
        if self._graph is None:
            raise RuntimeError(f"_keys() called on {self.rtdname} before resource was added to graph")
        return self.kind, self.cloud().id, self.account().id, self.region().id, self.zone().id, self.id, self.name

    def region(self, graph: Optional[Any] = None) -> BaseRegion:
        return self


@define(eq=False, slots=False)
class BaseZone(PhantomBaseResource):
    kind: ClassVar[str] = "zone"
    _kind_display: ClassVar[str] = "Zone"
    _kind_description: ClassVar[str] = "A zone."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "zone", "group": "management"}

    long_name: Optional[str] = None

    def zone(self, graph: Optional[Any] = None) -> BaseZone:
        return self


class InstanceStatus(Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    TERMINATED = "terminated"
    BUSY = "busy"
    UNKNOWN = "unknown"


@define(eq=False, slots=False)
class BaseInstance(BaseResource):
    kind: ClassVar[str] = "instance"
    _kind_display: ClassVar[str] = "Instance"
    _kind_description: ClassVar[str] = "An instance."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "instance", "group": "compute"}
    _categories: ClassVar[List[Category]] = [Category.compute]
    instance_cores: float = 0.0
    instance_memory: float = 0.0
    instance_type: Optional[str] = ""
    instance_status: Optional[InstanceStatus] = None


@define(eq=False, slots=False)
class BaseVolumeType(BaseType):
    kind: ClassVar[str] = "volume_type"
    _kind_display: ClassVar[str] = "Volume Type"
    _kind_description: ClassVar[str] = "A volume type."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "type", "group": "storage"}
    volume_type: Optional[str] = None
    ondemand_cost: Optional[float] = None

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        if self.volume_type is None:
            self.volume_type = self.id
        if self.ondemand_cost is not None:
            self.ondemand_cost = float(self.ondemand_cost)


@unique
class VolumeStatus(Enum):
    IN_USE = "in-use"
    AVAILABLE = "available"
    BUSY = "busy"
    ERROR = "error"
    DELETED = "deleted"
    UNKNOWN = "unknown"


@define(eq=False, slots=False)
class BaseNetworkShare(BaseResource):
    kind: ClassVar[str] = "network_share"
    _kind_display: ClassVar[str] = "Network Share"
    _kind_description: ClassVar[str] = "A network share."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "network_share", "group": "storage"}
    _categories: ClassVar[List[Category]] = [Category.storage]
    share_size: int = 0
    share_type: str = ""
    share_status: Optional[str] = None
    share_iops: Optional[int] = None
    share_throughput: Optional[float] = None  # bytes per second
    share_encrypted: Optional[bool] = None


@define(eq=False, slots=False)
class BaseVolume(BaseResource):
    kind: ClassVar[str] = "volume"
    _kind_display: ClassVar[str] = "Volume"
    _kind_description: ClassVar[str] = "A volume."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "volume", "group": "storage"}
    _categories: ClassVar[List[Category]] = [Category.storage]
    volume_size: int = 0
    volume_type: str = ""
    volume_status: Optional[VolumeStatus] = None
    volume_iops: Optional[int] = None
    volume_throughput: Optional[int] = None
    volume_encrypted: Optional[bool] = None
    snapshot_before_delete: bool = False


@define(eq=False, slots=False)
class BaseSnapshot(BaseResource):
    kind: ClassVar[str] = "snapshot"
    _kind_display: ClassVar[str] = "Snapshot"
    _kind_description: ClassVar[str] = "A snapshot."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "snapshot", "group": "storage"}
    _categories: ClassVar[List[Category]] = [Category.storage]
    snapshot_status: str = ""
    description: Optional[str] = None
    volume_id: Optional[str] = None
    volume_size: Optional[int] = None
    encrypted: bool = False
    owner_id: Optional[str] = None
    owner_alias: Optional[str] = None


@define(eq=False, slots=False)
class Cloud(BaseCloud):
    kind: ClassVar[str] = "cloud"
    _kind_display: ClassVar[str] = "Cloud"
    _kind_description: ClassVar[str] = "A cloud."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "cloud", "group": "management"}

    def delete(self, graph: Any) -> bool:
        return False


@define(eq=False, slots=False)
class GraphRoot(PhantomBaseResource):
    kind: ClassVar[str] = "graph_root"
    _kind_display: ClassVar[str] = "Graph Root"
    _kind_description: ClassVar[str] = "The root of the graph."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "graph_root", "group": "management"}

    def delete(self, graph: Any) -> bool:
        return False


@define(eq=False, slots=False)
class BaseBucket(BaseResource):
    kind: ClassVar[str] = "bucket"
    _kind_display: ClassVar[str] = "Storage Bucket"
    _kind_description: ClassVar[str] = "A storage bucket."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "bucket", "group": "storage"}
    _categories: ClassVar[List[Category]] = [Category.storage]

    encryption_enabled: Optional[bool] = None
    versioning_enabled: Optional[bool] = None


@unique
class QueueType(Enum):
    kind: ClassVar[str] = "queue_type"
    STANDARD = "standard"
    FIFO = "fifo"


@define(eq=False, slots=False)
class BaseQueue(BaseResource):
    kind: ClassVar[str] = "queue"
    _kind_display: ClassVar[str] = "Storage Queue"
    _kind_description: ClassVar[str] = "A storage queue."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "queue", "group": "storage"}
    _categories: ClassVar[List[Category]] = [Category.storage]
    queue_type: Optional[QueueType] = None
    approximate_message_count: Optional[int] = None
    message_retention_period_days: Optional[int] = None


@define(eq=False, slots=False)
class BaseKeyPair(BaseResource):
    kind: ClassVar[str] = "keypair"
    _kind_display: ClassVar[str] = "Key Pair"
    _kind_description: ClassVar[str] = "A key pair."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "key", "group": "access_control"}
    fingerprint: str = ""
    _categories: ClassVar[List[Category]] = [Category.access_control]


@define(eq=False, slots=False)
class BaseBucketQuota(BaseQuota):
    kind: ClassVar[str] = "bucket_quota"
    _kind_display: ClassVar[str] = "Bucket Quota"
    _kind_description: ClassVar[str] = "A bucket quota."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "quota", "group": "storage"}


@define(eq=False, slots=False)
class BaseServerlessFunction(BaseResource):
    kind: ClassVar[str] = "serverless_function"
    _kind_display: ClassVar[str] = "Serverless Function"
    _kind_description: ClassVar[str] = "A serverless function."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "function", "group": "compute"}
    _categories: ClassVar[List[Category]] = [Category.compute]

    memory_size: Optional[int] = None


@define(eq=False, slots=False)
class BaseNetwork(BaseResource):
    kind: ClassVar[str] = "network"
    _kind_display: ClassVar[str] = "Network"
    _kind_description: ClassVar[str] = "A network."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "network", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]

    cidr_blocks: List[str] = field(factory=list)


@define(eq=False, slots=False)
class BaseNetworkQuota(BaseQuota):
    kind: ClassVar[str] = "network_quota"
    _kind_display: ClassVar[str] = "Network Quota"
    _kind_description: ClassVar[str] = "A network quota."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "quota", "group": "networking"}


@define(eq=False, slots=False)
class BaseFirewall(BaseResource):
    kind: ClassVar[str] = "firewall"
    _kind_display: ClassVar[str] = "Firewall"
    _kind_description: ClassVar[str] = "A firewall."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "firewall", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking, Category.security]


class DatabaseInstanceStatus(Enum):
    AVAILABLE = "available"
    STOPPED = "stopped"
    TERMINATED = "terminated"
    FAILED = "failed"
    BUSY = "busy"
    UNKNOWN = "unknown"


@define(eq=False, slots=False)
class BaseDatabaseInstanceType(BaseInstanceType):
    kind: ClassVar[str] = "database_instance_type"
    _kind_display: ClassVar[str] = "Database Instance Type"
    _kind_description: ClassVar[str] = "A database instance type."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "database", "group": "database"}


@define(eq=False, slots=False)
class BaseDatabase(BaseResource):
    kind: ClassVar[str] = "database"
    _kind_display: ClassVar[str] = "Database"
    _kind_description: ClassVar[str] = "A database."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "database", "group": "database"}
    _categories: ClassVar[List[Category]] = [Category.compute, Category.database]
    db_type: Optional[str] = None
    db_status: Optional[DatabaseInstanceStatus] = None
    db_endpoint: Optional[str] = ""
    db_version: Optional[str] = None
    db_publicly_accessible: Optional[bool] = None
    instance_type: str = ""
    volume_size: Optional[int] = None
    volume_iops: Optional[int] = None
    volume_encrypted: Optional[bool] = None


@define(eq=False, slots=False)
class BaseLoadBalancer(BaseResource):
    kind: ClassVar[str] = "load_balancer"
    _kind_display: ClassVar[str] = "Load Balancer"
    _kind_description: ClassVar[str] = "A load balancer."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "load_balancer", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]
    lb_type: str = ""
    public_ip_address: Optional[str] = None
    backends: List[str] = field(factory=list)


@define(eq=False, slots=False)
class BaseLoadBalancerQuota(BaseQuota):
    kind: ClassVar[str] = "load_balancer_quota"
    _kind_display: ClassVar[str] = "Load Balancer Quota"
    _kind_description: ClassVar[str] = "A load balancer quota."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "quota", "group": "networking"}


@define(eq=False, slots=False)
class BaseSubnet(BaseResource):
    kind: ClassVar[str] = "subnet"
    _kind_display: ClassVar[str] = "Subnet"
    _kind_description: ClassVar[str] = "A subnet."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "subnet", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]

    cidr_block: Optional[str] = None


@define(eq=False, slots=False)
class BaseGateway(BaseResource):
    kind: ClassVar[str] = "gateway"
    _kind_display: ClassVar[str] = "Gateway"
    _kind_description: ClassVar[str] = "A gateway."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "gateway", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]


@define(eq=False, slots=False)
class BaseTunnel(BaseResource):
    kind: ClassVar[str] = "tunnel"
    _kind_display: ClassVar[str] = "Networking Tunnel"
    _kind_description: ClassVar[str] = "A networking tunnel."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "link", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]


@define(eq=False, slots=False)
class BaseGatewayQuota(BaseQuota):
    kind: ClassVar[str] = "gateway_quota"
    _kind_display: ClassVar[str] = "Gateway Quota"
    _kind_description: ClassVar[str] = "A gateway quota."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "quota", "group": "networking"}


@define(eq=False, slots=False)
class BaseSecurityGroup(BaseResource):
    kind: ClassVar[str] = "security_group"
    _kind_display: ClassVar[str] = "Security Group"
    _kind_description: ClassVar[str] = "A security group."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "security_group", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking, Category.security]


@define(eq=False, slots=False)
class BaseRoutingTable(BaseResource):
    kind: ClassVar[str] = "routing_table"
    _kind_display: ClassVar[str] = "Routing Table"
    _kind_description: ClassVar[str] = "A routing table."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "routing_table", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]


@define(eq=False, slots=False)
class BaseRoute(BaseResource):
    kind: ClassVar[str] = "route"
    _kind_display: ClassVar[str] = "Network Route"
    _kind_description: ClassVar[str] = "A network route."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "routing_table", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]


@define(eq=False, slots=False)
class BaseNetworkAcl(BaseResource):
    kind: ClassVar[str] = "network_acl"
    _kind_display: ClassVar[str] = "Network ACL"
    _kind_description: ClassVar[str] = "A network access control list."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "access_control", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking, Category.security]


@define(eq=False, slots=False)
class BasePeeringConnection(BaseResource):
    kind: ClassVar[str] = "peering_connection"
    _kind_display: ClassVar[str] = "Peering Connection"
    _kind_description: ClassVar[str] = "A peering connection."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "connection", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]


@define(eq=False, slots=False)
class BaseEndpoint(BaseResource):
    kind: ClassVar[str] = "endpoint"
    _kind_display: ClassVar[str] = "Endpoint"
    _kind_description: ClassVar[str] = "An endpoint."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "endpoint", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]


@define(eq=False, slots=False)
class BaseNetworkInterface(BaseResource):
    kind: ClassVar[str] = "network_interface"
    _kind_display: ClassVar[str] = "Network Interface"
    _kind_description: ClassVar[str] = "A network interface."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "endpoint", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]
    network_interface_status: str = ""
    network_interface_type: Optional[str] = None
    mac: str = ""
    private_ips: List[str] = field(factory=list)
    public_ips: List[str] = field(factory=list)
    v6_ips: Optional[List[str]] = None
    description: Optional[str] = None


@define(eq=False, slots=False)
class BaseIamPrincipal(BaseResource):
    kind: ClassVar[str] = "iam_principal"
    _kind_display: ClassVar[str] = "IAM Principal"
    _kind_description: ClassVar[str] = (
        "An IAM principal is an entity that can be authenticated and authorized to access resources."
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "user", "group": "access_control"}
    _categories: ClassVar[List[Category]] = [Category.access_control]


@define(eq=False, slots=False)
class BaseUser(BaseResource):
    kind: ClassVar[str] = "user"
    _kind_display: ClassVar[str] = "User"
    _kind_description: ClassVar[str] = "A user."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "user", "group": "access_control"}
    _categories: ClassVar[List[Category]] = [Category.access_control]


@define(eq=False, slots=False)
class BaseGroup(BaseResource):
    kind: ClassVar[str] = "group"
    _kind_display: ClassVar[str] = "Group"
    _kind_description: ClassVar[str] = "A group."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "group", "group": "access_control"}
    _categories: ClassVar[List[Category]] = [Category.access_control]


@define(eq=False, slots=False)
class BasePolicy(BaseResource):
    kind: ClassVar[str] = "policy"
    _kind_display: ClassVar[str] = "Policy"
    _kind_description: ClassVar[str] = "A policy."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "policy", "group": "access_control"}
    _categories: ClassVar[List[Category]] = [Category.access_control]


@define(eq=False, slots=False)
class BaseRole(BaseResource):
    kind: ClassVar[str] = "role"
    _kind_display: ClassVar[str] = "Role"
    _kind_description: ClassVar[str] = "A role."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "role", "group": "access_control"}
    _categories: ClassVar[List[Category]] = [Category.access_control]


@define(eq=False, slots=False)
class BaseInstanceProfile(BaseResource):
    kind: ClassVar[str] = "instance_profile"
    _kind_display: ClassVar[str] = "Instance Profile"
    _kind_description: ClassVar[str] = "An instance profile."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "profile", "group": "access_control"}
    _categories: ClassVar[List[Category]] = [Category.access_control]


@define(eq=False, slots=False)
class BaseAccessKey(BaseResource):
    kind: ClassVar[str] = "access_key"
    _kind_display: ClassVar[str] = "Access Key"
    _kind_description: ClassVar[str] = "An access key."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "key", "group": "access_control"}
    _categories: ClassVar[List[Category]] = [Category.access_control, Category.security]
    access_key_status: Optional[str] = None


@define(eq=False, slots=False)
class BaseCertificate(BaseResource):
    kind: ClassVar[str] = "certificate"
    _kind_display: ClassVar[str] = "Certificate"
    _kind_description: ClassVar[str] = "A certificate."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "certificate", "group": "access_control"}
    _categories: ClassVar[List[Category]] = [Category.access_control, Category.security]
    expires: Optional[datetime] = None
    dns_names: Optional[List[str]] = None
    sha1_fingerprint: Optional[str] = None


@define(eq=False, slots=False)
class BaseCertificateQuota(BaseQuota):
    kind: ClassVar[str] = "certificate_quota"
    _kind_display: ClassVar[str] = "Certificate Quota"
    _kind_description: ClassVar[str] = "A certificate quota."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "quota", "group": "access_control"}


@define(eq=False, slots=False)
class BaseStack(BaseResource):
    kind: ClassVar[str] = "stack"
    _kind_display: ClassVar[str] = "Stack"
    _kind_description: ClassVar[str] = "A stack."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "stack", "group": "management"}
    _categories: ClassVar[List[Category]] = [Category.devops, Category.management]
    stack_status: str = ""
    stack_status_reason: str = ""
    stack_parameters: Dict[str, str] = field(factory=dict)


@define(eq=False, slots=False)
class BaseAutoScalingGroup(BaseResource):
    kind: ClassVar[str] = "autoscaling_group"
    _kind_display: ClassVar[str] = "Auto Scaling Group"
    _kind_description: ClassVar[str] = "An auto scaling group."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "autoscaling_group", "group": "compute"}
    _categories: ClassVar[List[Category]] = [Category.compute, Category.management]
    min_size: Optional[int] = None
    max_size: Optional[int] = None


@define(eq=False, slots=False)
class BaseIPAddress(BaseResource):
    kind: ClassVar[str] = "ip_address"
    _kind_display: ClassVar[str] = "IP Address"
    _kind_description: ClassVar[str] = "An IP address."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "network_address", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.networking]
    ip_address: Optional[str] = None
    ip_address_family: str = ""


@define(eq=False, slots=False)
class BaseHealthCheck(BaseResource):
    kind: ClassVar[str] = "health_check"
    _kind_display: ClassVar[str] = "Health Check"
    _kind_description: ClassVar[str] = "A health check."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "health", "group": "compute"}
    _categories: ClassVar[List[Category]] = [Category.monitoring]
    check_interval: Optional[int] = None
    healthy_threshold: Optional[int] = None
    unhealthy_threshold: Optional[int] = None
    timeout: Optional[int] = None
    health_check_type: Optional[str] = None


@define(eq=False, slots=False)
class BaseDNSZone(BaseResource):
    kind: ClassVar[str] = "dns_zone"
    _kind_display: ClassVar[str] = "DNS Zone"
    _kind_description: ClassVar[str] = "A DNS zone."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "dns", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.dns, Category.networking]
    private_zone: Optional[bool] = None


@define(eq=False, slots=False)
class BaseDNSRecordSet(BaseResource):
    kind: ClassVar[str] = "dns_record_set"
    _kind_display: ClassVar[str] = "DNS Record Set"
    _kind_description: ClassVar[str] = "A DNS record set."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "dns", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.dns]

    record_ttl: Optional[int] = None
    record_type: str = ""
    record_values: List[str] = field(factory=list)

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.record_type = self.record_type.upper()

    def dns_zone(self, graph: Optional[Any] = None) -> "BaseDNSZone":
        if graph is None:
            graph = self._graph
        dns_zone = graph.search_first_parent_class(self, BaseDNSZone) if graph else None
        return dns_zone or UnknownDNSZone(id="undefined", tags={})

    def _keys(self) -> tuple[Any, ...]:
        if self._graph is None:
            raise RuntimeError(f"_keys() called on {self.rtdname} before resource was added to graph")
        return (
            self.kind,
            self.cloud().id,
            self.account().id,
            self.region().id,
            self.zone().id,
            self.dns_zone().id,
            self.id,
            self.name,
            self.record_type,
        )


@define(eq=False, slots=False)
class BaseDNSRecord(BaseResource):
    kind: ClassVar[str] = "dns_record"
    _kind_display: ClassVar[str] = "DNS Record"
    _kind_description: ClassVar[str] = "A DNS record."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "dns_record", "group": "networking"}
    _categories: ClassVar[List[Category]] = [Category.dns]

    record_ttl: int = -1
    record_type: str = ""
    record_data: str = ""
    record_value: str = ""
    record_priority: Optional[int] = None
    record_port: Optional[int] = None
    record_weight: Optional[int] = None
    record_flags: Optional[int] = None
    record_tag: Optional[str] = None
    record_mname: Optional[str] = None
    record_rname: Optional[str] = None
    record_serial: Optional[int] = None
    record_refresh: Optional[int] = None
    record_retry: Optional[int] = None
    record_expire: Optional[int] = None
    record_minimum: Optional[int] = None

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.record_type = self.record_type.upper()

    def dns_zone(self, graph: Optional[Any] = None) -> "BaseDNSZone":
        if graph is None:
            graph = self._graph
        dns_zone = graph.search_first_parent_class(self, BaseDNSZone) if graph else None
        return dns_zone or UnknownDNSZone(id="undefined", tags={})

    def _keys(self) -> tuple[Any, ...]:
        if self._graph is None:
            raise RuntimeError(f"_keys() called on {self.rtdname} before resource was added to graph")
        return (
            self.kind,
            self.cloud().id,
            self.account().id,
            self.region().id,
            self.zone().id,
            self.dns_zone().id,
            self.id,
            self.name,
            self.record_type,
            self.record_data,
        )


@define(eq=False, slots=False)
class BaseOrganizationalRoot(BaseResource):
    kind: ClassVar[str] = "organizational_root"
    _kind_display: ClassVar[str] = "Organizational Root"
    _kind_description: ClassVar[str] = "An Organizational Root."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "misc"}
    _categories: ClassVar[List[Category]] = [Category.management]


@define(eq=False, slots=False)
class BaseOrganizationalUnit(BaseResource):
    kind: ClassVar[str] = "organizational_unit"
    _kind_display: ClassVar[str] = "Organizational Unit"
    _kind_description: ClassVar[str] = "An Organizational Unit."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "misc"}
    _categories: ClassVar[List[Category]] = [Category.management]


@define(eq=False, slots=False)
class BaseManagedKubernetesClusterProvider(BaseResource):
    kind: ClassVar[str] = "managed_kubernetes_cluster_provider"
    _kind_display: ClassVar[str] = "Managed Kubernetes Cluster Provider"
    _kind_description: ClassVar[str] = "A managed kubernetes cluster provider."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "cluster", "group": "compute"}
    _categories: ClassVar[List[Category]] = [Category.compute, Category.management]
    version: Optional[str] = field(default=None, metadata={"description": "The kubernetes version"})
    endpoint: Optional[str] = field(default=None, metadata={"description": "The kubernetes API endpoint"})


class AIJobStatus(Enum):
    PENDING = "pending"
    PREPARING = "preparing"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    UNKNOWN = "unknown"


@define(eq=False, slots=False)
class BaseAIResource(BaseResource):
    kind: ClassVar[str] = "ai_resource"
    _kind_display: ClassVar[str] = "AI resource"
    _kind_description: ClassVar[str] = "An AI Resource."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}
    _categories: ClassVar[List[Category]] = [Category.ai, Category.compute]


@define(eq=False, slots=False)
class BaseAIJob(BaseAIResource):
    kind: ClassVar[str] = "ai_job"
    _kind_display: ClassVar[str] = "AI Job"
    _kind_description: ClassVar[str] = "An AI Job resource."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "job", "group": "ai"}

    ai_job_status: Optional[AIJobStatus] = field(default=None, metadata={"description": "Current status of the AI job"})


@define(eq=False, slots=False)
class BaseAIModel(BaseAIResource):
    kind: ClassVar[str] = "ai_model"
    _kind_display: ClassVar[str] = "AI Model"
    _kind_description: ClassVar[str] = "An AI Model resource."
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "ai"}


@define(eq=False, slots=False)
class UnknownCloud(BaseCloud):
    kind: ClassVar[str] = "unknown_cloud"
    _kind_display: ClassVar[str] = "Unknown Cloud"
    _kind_description: ClassVar[str] = "An unknown cloud."

    def delete(self, graph: Any) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownAccount(BaseAccount):
    kind: ClassVar[str] = "unknown_account"
    _kind_display: ClassVar[str] = "Unknown Account"
    _kind_description: ClassVar[str] = "An unknown account."

    def delete(self, graph: Any) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownRegion(BaseRegion):
    kind: ClassVar[str] = "unknown_region"
    _kind_display: ClassVar[str] = "Unknown Region"
    _kind_description: ClassVar[str] = "An unknown region."

    def delete(self, graph: Any) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownDNSZone(BaseDNSZone):
    kind: ClassVar[str] = "unknown_dns_zone"
    _kind_display: ClassVar[str] = "Unknown DNS Zone"
    _kind_description: ClassVar[str] = "An unknown DNS zone."

    def delete(self, graph: Any) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownZone(BaseZone):
    kind: ClassVar[str] = "unknown_zone"
    _kind_display: ClassVar[str] = "Unknown Zone"
    _kind_description: ClassVar[str] = "An unknown zone."

    def delete(self, graph: Any) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownLocation(BaseResource):
    kind: ClassVar[str] = "unknown_location"
    _kind_display: ClassVar[str] = "Unknown Location"
    _kind_description: ClassVar[str] = "An unknown location."

    def delete(self, graph: Any) -> bool:
        return False


class PolicySourceKind(StrEnum):
    principal = "principal"  # e.g. IAM user, attached policy
    group = "group"  # policy comes from an IAM group
    resource = "resource"  # e.g. s3 bucket policy


ResourceConstraint = str

ConditionString = str


@frozen
class PolicySource:
    kind: PolicySourceKind
    uri: str


class HasResourcePolicy(ABC):
    # returns a list of all policies that affects the resource (inline, attached, etc.)
    @abstractmethod
    def resource_policy(self, builder: Any) -> List[Tuple[PolicySource, Json]]:
        pass


@frozen
class PermissionCondition:
    # if nonempty and any evals to true, access is granted, otherwise implicitly denied
    allow: Optional[Tuple[ConditionString, ...]] = None
    # if nonempty and any is evals to false, access is implicitly denied
    boundary: Optional[Tuple[ConditionString, ...]] = None
    # if nonempty and any evals to true, access is explicitly denied
    deny: Optional[Tuple[ConditionString, ...]] = None


@frozen
class PermissionScope:
    source: PolicySource
    constraints: Tuple[ResourceConstraint, ...]  # aka resource constraints
    conditions: Optional[PermissionCondition] = None

    def with_deny_conditions(self, deny_conditions: List[Json]) -> "PermissionScope":
        c = self.conditions or PermissionCondition()
        return evolve(self, conditions=evolve(c, deny=tuple([to_json_str(c) for c in deny_conditions])))

    def with_boundary_conditions(self, boundary_conditions: List[Json]) -> "PermissionScope":
        c = self.conditions or PermissionCondition()
        return evolve(self, conditions=evolve(c, boundary=tuple([to_json_str(c) for c in boundary_conditions])))

    def has_no_condititons(self) -> bool:
        if self.conditions is None:
            return True

        if self.conditions.allow is None and self.conditions.boundary is None and self.conditions.deny is None:
            return True

        return False


class PermissionLevel(StrEnum):
    list = "list"
    read = "read"
    tagging = "tagging"
    write = "write"
    permission = "permission"
    can_become = "can_become"  # aka assume role
    unknown = "unknown"  # in case a resource is not in the levels database


@frozen
class AccessPermission:
    action: str
    level: PermissionLevel
    scopes: Tuple[PermissionScope, ...]


resolve_types(BaseResource)  # noqa
