from abc import ABC, abstractmethod
from functools import wraps, cached_property
from datetime import datetime, timezone, timedelta
from copy import deepcopy
import base64
import hashlib
import weakref
from resotolib.logger import log
from enum import Enum
from typing import Dict, Iterator, List, ClassVar, Optional, TypedDict
from resotolib.utils import make_valid_timestamp, utc_str
from prometheus_client import Counter, Summary
from attrs import define, field, resolve_types, Factory
import jsons

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
metrics_resource_cleanup = Summary("resoto_resource_cleanup_seconds", "Time it took the resource cleanup() method")


def unless_protected(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
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

    @staticmethod
    def from_value(value: Optional[str] = None) -> Enum:
        try:
            return EdgeType(value)
        except ValueError:
            pass
        return EdgeType.default


class ResourceChanges:
    def __init__(self, node) -> None:
        self.node = node
        self.reported = set()
        self.desired = set()
        self.metadata = set()
        self.changed = False

    def add(self, property: str) -> None:
        if property in ("tags"):
            self.reported.add(property)
        elif property in ("clean"):
            self.desired.add(property)
        elif property in ("cleaned", "protected"):
            self.metadata.add(property)
        elif property == "log":
            pass
        else:
            raise ValueError(f"Unknown property {property}")
        self.changed = True

    def get(self) -> Dict:
        changes = {}
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


@define(eq=False, slots=False, kw_only=True)
class BaseResource(ABC):
    """A BaseResource is any node we're connecting to the Graph()

    BaseResources have an id, name and tags. The id is a unique id used to search for
    the resource within the Graph. The name is used for display purposes. Tags are
    key/value pairs that get exported in the GRAPHML view.

    There's also class variables, kind, phantom and reference_kinds.
    `kind` is a string describing the type of resource, e.g. 'aws_ec2_instance'
       or 'some_cloud_load_balancer'.
    `phantom` is a bool describing whether the resource actually exists within
       the cloud or if it's just a phantom resource like pricing information
       or usage quota. I.e. some information relevant to the cloud account
       but not actually existing in the form of a usable resource.
    `reference_kinds` is a list of kinds that can be connected to this resource for
       the related edge type as successor or predecessor.
    """

    kind: ClassVar[str] = "resource"
    phantom: ClassVar[bool] = False
    reference_kinds: ClassVar[ModelReference] = {}

    id: str
    tags: Dict[str, Optional[str]] = Factory(dict)
    name: Optional[str] = field(default=None)
    _cloud: "Optional[BaseCloud]" = field(default=None, repr=False)
    _account: "Optional[BaseAccount]" = field(default=None, repr=False)
    _region: "Optional[BaseRegion]" = field(default=None, repr=False)
    _zone: "Optional[BaseZone]" = field(default=None, repr=False)
    _resotocore_id: Optional[str] = field(default=None, repr=False)
    _resotocore_revision: Optional[str] = field(default=None, repr=False)
    _resotocore_query_tag: Optional[str] = field(default=None, repr=False)
    _clean: bool = False
    _cleaned: bool = False
    _protected: bool = False
    _deferred_connections: List = field(factory=list)

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
        self.__log: List = []
        self._raise_tags_exceptions: bool = False
        if not hasattr(self, "_ctime"):
            self._ctime = None
        if not hasattr(self, "_atime"):
            self._atime = None
        if not hasattr(self, "_mtime"):
            self._mtime = None

    def _keys(self) -> tuple:
        """Return a tuple of all keys that make this resource unique

        Must not be called before the resource is connected to the graph
        as the relative location within the graph is used to determine the
        tuple of unique keys.

        E.g. instance -> aws -> 123457 -> us-east-1 -> us-east-1b -> i-987654 -> myServer
        """
        if self._graph is None:
            raise RuntimeError(f"_keys() called on {self.rtdname} before resource was added to graph")
        return (
            self.kind,
            self.cloud().id,
            self.account().id,
            self.region().id,
            self.zone().id,
            self.id,
            self.name,
        )

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

    def log(self, msg: str, data=None, exception=None) -> None:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        log_entry = {
            "timestamp": now,
            "msg": str(msg),
            "exception": repr(exception) if exception else None,
            "data": deepcopy(data),
        }
        self.__log.append(log_entry)
        self._changes.add("log")

    def add_change(self, change: str) -> None:
        self._changes.add(change)

    @property
    def changes(self) -> ResourceChanges:
        return self._changes

    @property
    def event_log(self) -> List:
        return self.__log

    @property
    def str_event_log(self) -> List:
        return [
            {
                "timestamp": utc_str(le["timestamp"]),
                "msg": le["msg"],
                "exception": le["exception"],
            }
            for le in self.__log
        ]

    def update_tag(self, key, value) -> bool:
        raise NotImplementedError

    def delete_tag(self, key) -> bool:
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
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        if self.ctime is not None:
            return now - self.ctime

    @property
    def last_access(self) -> Optional[timedelta]:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        if self.atime is not None:
            return now - self.atime

    @property
    def last_update(self) -> Optional[timedelta]:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        if self.mtime is not None:
            return now - self.mtime

    def _ctime_getter(self) -> Optional[datetime]:
        if "resoto:ctime" in self.tags:
            ctime = self.tags["resoto:ctime"]
            try:
                ctime = make_valid_timestamp(datetime.fromisoformat(ctime))
            except ValueError:
                pass
            else:
                return ctime
        return self._ctime

    def _ctime_setter(self, value: Optional[datetime]) -> None:
        self._ctime = make_valid_timestamp(value)

    def _atime_getter(self) -> Optional[datetime]:
        return self._atime

    def _atime_setter(self, value: Optional[datetime]) -> None:
        self._atime = make_valid_timestamp(value)

    def _mtime_getter(self) -> Optional[datetime]:
        return self._mtime

    def _mtime_setter(self, value: Optional[datetime]) -> None:
        self._mtime = make_valid_timestamp(value)

    @property
    def clean(self) -> bool:
        return self._clean

    @clean.setter
    @unless_protected
    def clean(self, value: bool) -> None:
        if self.phantom and value:
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
    def cleanup(self, graph=None) -> bool:
        if self.phantom:
            raise RuntimeError(f"Can't cleanup phantom resource {self.rtdname}")

        if self.cleaned:
            log.debug(f"Resource {self.rtdname} has already been cleaned up")
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
        log.debug(f"Trying to clean up {self.rtdname}{log_suffix}")
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
    def pre_cleanup(self, graph=None) -> bool:
        if not hasattr(self, "pre_delete"):
            return True

        if graph is None:
            graph = self._graph

        if self.phantom:
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
    @abstractmethod
    def delete(self, graph) -> bool:
        raise NotImplementedError

    def account(self, graph=None) -> "BaseAccount":
        account = None
        if graph is None:
            graph = self._graph
        if self._account:
            account = self._account
        elif graph:
            account = graph.search_first_parent_class(self, BaseAccount)
        if account is None:
            account = UnknownAccount(id="undefined", tags={})
        return account

    def cloud(self, graph=None) -> "BaseCloud":
        cloud = None
        if graph is None:
            graph = self._graph
        if self._cloud:
            cloud = self._cloud
        elif graph:
            cloud = graph.search_first_parent_class(self, BaseCloud)
        if cloud is None:
            cloud = UnknownCloud(id="undefined", tags={})
        return cloud

    def region(self, graph=None) -> "BaseRegion":
        region = None
        if graph is None:
            graph = self._graph
        if self._region:
            region = self._region
        elif graph:
            region = graph.search_first_parent_class(self, BaseRegion)
        if region is None:
            region = UnknownRegion(id="undefined", tags={})
        return region

    def zone(self, graph=None) -> "BaseZone":
        zone = None
        if graph is None:
            graph = self._graph
        if self._zone:
            zone = self._zone
        elif graph:
            zone = graph.search_first_parent_class(self, BaseZone)
        if zone is None:
            zone = UnknownZone(id="undefined", tags={})
        return zone

    def location(self, graph=None):
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
        self, search: Dict, parent: bool = True, edge_type: EdgeType = EdgeType.default
    ) -> None:
        self._deferred_connections.append({"search": search, "parent": parent, "edge_type": edge_type})

    def resolve_deferred_connections(self, graph) -> None:
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

    def predecessors(self, graph, edge_type=None) -> Iterator:
        """Returns an iterator of the node's parent nodes"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return ()
        return graph.predecessors(self, edge_type=edge_type)

    def successors(self, graph, edge_type=None) -> Iterator:
        """Returns an iterator of the node's child nodes"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return ()
        return graph.successors(self, edge_type=edge_type)

    def predecessor_added(self, resource, graph) -> None:
        """Called when a predecessor is added to this node"""
        pass

    def successor_added(self, resource, graph) -> None:
        """Called when a successor is added to this node"""
        pass

    def ancestors(self, graph, edge_type=None) -> Iterator:
        """Returns an iterator of the node's ancestors"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return ()
        return graph.ancestors(self, edge_type=edge_type)

    def descendants(self, graph, edge_type=None) -> Iterator:
        """Returns an iterator of the node's descendants"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return ()
        return graph.descendants(self, edge_type=edge_type)

    @property
    def _graph(self):
        if self.__graph is not None:
            return self.__graph()

    @_graph.setter
    def _graph(self, value) -> None:
        self.__graph = weakref.ref(value)

    def __getstate__(self):
        ret = self.__dict__.copy()
        ret["_BaseResource__graph"] = None
        return ret

    def __setstate__(self, state):
        self.__dict__.update(state)


BaseResource.ctime = property(BaseResource._ctime_getter, BaseResource._ctime_setter)
BaseResource.mtime = property(BaseResource._mtime_getter, BaseResource._mtime_setter)
BaseResource.atime = property(BaseResource._atime_getter, BaseResource._atime_setter)


@define(eq=False, slots=False)
class PhantomBaseResource(BaseResource):
    kind: ClassVar[str] = "phantom_resource"
    phantom: ClassVar[bool] = True

    def cleanup(self, graph=None) -> bool:
        log.error(f"Resource {self.rtdname} is a phantom resource and can't be cleaned up")
        return False


@define(eq=False, slots=False)
class BaseQuota(PhantomBaseResource):
    kind: ClassVar[str] = "quota"
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


@define(eq=False, slots=False)
class BaseInstanceQuota(BaseQuota):
    kind: ClassVar[str] = "instance_quota"
    instance_type: Optional[str] = None

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.instance_type = self.id
        self.quota_type = "standard"


@define(eq=False, slots=False)
class BaseInstanceType(BaseType):
    kind: ClassVar[str] = "instance_type"
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
class BaseCloud(BaseResource):
    kind: ClassVar[str] = "base_cloud"

    def cloud(self, graph=None):
        return self


@define(eq=False, slots=False)
class BaseAccount(BaseResource):
    kind: ClassVar[str] = "account"

    def account(self, graph=None):
        return self


@define(eq=False, slots=False)
class BaseRegion(BaseResource):
    kind: ClassVar[str] = "region"

    def region(self, graph=None):
        return self


@define(eq=False, slots=False)
class BaseZone(BaseResource):
    kind: ClassVar[str] = "zone"

    def zone(self, graph=None):
        return self


class InstanceStatus(Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    TERMINATED = "terminated"
    BUSY = "busy"
    UNKNOWN = "unknown"


def serialize_enum(obj, **kwargs):
    return obj.value


jsons.set_serializer(serialize_enum, InstanceStatus)


@define(eq=False, slots=False)
class BaseInstance(BaseResource):
    kind: ClassVar[str] = "instance"
    instance_cores: float = 0.0
    instance_memory: float = 0.0
    instance_type: Optional[str] = ""
    instance_status: Optional[InstanceStatus] = None

    def instance_type_info(self, graph) -> BaseInstanceType:
        return graph.search_first_parent_class(self, BaseInstanceType)


@define(eq=False, slots=False)
class BaseVolumeType(BaseType):
    kind: ClassVar[str] = "volume_type"
    volume_type: str = ""
    ondemand_cost: float = 0.0

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.volume_type = self.id


class VolumeStatus(Enum):
    IN_USE = "in-use"
    AVAILABLE = "available"
    BUSY = "busy"
    ERROR = "error"
    DELETED = "deleted"
    UNKNOWN = "unknown"


jsons.set_serializer(serialize_enum, VolumeStatus)


@define(eq=False, slots=False)
class BaseVolume(BaseResource):
    kind: ClassVar[str] = "volume"
    volume_size: int = 0
    volume_type: str = ""
    volume_status: Optional[VolumeStatus] = None
    volume_iops: Optional[int] = None
    volume_throughput: Optional[int] = None
    volume_encrypted: Optional[bool] = None
    snapshot_before_delete: bool = False

    def volume_type_info(self, graph) -> BaseVolumeType:
        return graph.search_first_parent_class(self, BaseVolumeType)


@define(eq=False, slots=False)
class BaseSnapshot(BaseResource):
    kind: ClassVar[str] = "snapshot"
    snapshot_status: str = ""
    description: Optional[str] = None
    volume_id: Optional[str] = None
    volume_size: int = 0
    encrypted: bool = False
    owner_id: Optional[str] = None
    owner_alias: Optional[str] = None


@define(eq=False, slots=False)
class Cloud(BaseCloud):
    kind: ClassVar[str] = "cloud"

    def delete(self, graph) -> bool:
        return False


@define(eq=False, slots=False)
class GraphRoot(PhantomBaseResource):
    kind: ClassVar[str] = "graph_root"

    def delete(self, graph) -> bool:
        return False


@define(eq=False, slots=False)
class BaseBucket(BaseResource):
    kind: ClassVar[str] = "bucket"


@define(eq=False, slots=False)
class BaseServerlessFunction(BaseResource):
    kind: ClassVar[str] = "serverless_function"


@define(eq=False, slots=False)
class BaseKeyPair(BaseResource):
    kind: ClassVar[str] = "keypair"
    fingerprint: str = ""


@define(eq=False, slots=False)
class BaseBucketQuota(BaseQuota):
    kind: ClassVar[str] = "bucket_quota"


@define(eq=False, slots=False)
class BaseNetwork(BaseResource):
    kind: ClassVar[str] = "network"


@define(eq=False, slots=False)
class BaseNetworkQuota(BaseQuota):
    kind: ClassVar[str] = "network_quota"


@define(eq=False, slots=False)
class BaseDatabase(BaseResource):
    kind: ClassVar[str] = "database"
    db_type: str = ""
    db_status: str = ""
    db_endpoint: str = ""
    db_version: Optional[str] = None
    db_publicly_accessible: Optional[bool] = None
    instance_type: str = ""
    volume_size: int = 0
    volume_iops: Optional[int] = None
    volume_encrypted: Optional[bool] = None


@define(eq=False, slots=False)
class BaseLoadBalancer(BaseResource):
    kind: ClassVar[str] = "load_balancer"
    lb_type: str = ""
    public_ip_address: Optional[str] = None
    backends: List[str] = field(factory=list)


@define(eq=False, slots=False)
class BaseLoadBalancerQuota(BaseQuota):
    kind: ClassVar[str] = "load_balancer_quota"


@define(eq=False, slots=False)
class BaseSubnet(BaseResource):
    kind: ClassVar[str] = "subnet"


@define(eq=False, slots=False)
class BaseGateway(BaseResource):
    kind: ClassVar[str] = "gateway"


@define(eq=False, slots=False)
class BaseTunnel(BaseResource):
    kind: ClassVar[str] = "tunnel"


@define(eq=False, slots=False)
class BaseGatewayQuota(BaseQuota):
    kind: ClassVar[str] = "gateway_quota"


@define(eq=False, slots=False)
class BaseSecurityGroup(BaseResource):
    kind: ClassVar[str] = "security_group"


@define(eq=False, slots=False)
class BaseRoutingTable(BaseResource):
    kind: ClassVar[str] = "routing_table"


@define(eq=False, slots=False)
class BaseNetworkAcl(BaseResource):
    kind: ClassVar[str] = "network_acl"


@define(eq=False, slots=False)
class BasePeeringConnection(BaseResource):
    kind: ClassVar[str] = "peering_connection"


@define(eq=False, slots=False)
class BaseEndpoint(BaseResource):
    kind: ClassVar[str] = "endpoint"


@define(eq=False, slots=False)
class BaseNetworkInterface(BaseResource):
    kind: ClassVar[str] = "network_interface"
    network_interface_status: str = ""
    network_interface_type: str = ""
    mac: str = ""
    private_ips: List[str] = field(factory=list)
    public_ips: List[str] = field(factory=list)
    v6_ips: List[str] = field(factory=list)
    description: str = ""


@define(eq=False, slots=False)
class BaseUser(BaseResource):
    kind: ClassVar[str] = "user"


@define(eq=False, slots=False)
class BaseGroup(BaseResource):
    kind: ClassVar[str] = "group"


@define(eq=False, slots=False)
class BasePolicy(BaseResource):
    kind: ClassVar[str] = "policy"


@define(eq=False, slots=False)
class BaseRole(BaseResource):
    kind: ClassVar[str] = "role"


@define(eq=False, slots=False)
class BaseInstanceProfile(BaseResource):
    kind: ClassVar[str] = "instance_profile"


@define(eq=False, slots=False)
class BaseAccessKey(BaseResource):
    kind: ClassVar[str] = "access_key"
    access_key_status: str = ""


@define(eq=False, slots=False)
class BaseCertificate(BaseResource):
    kind: ClassVar[str] = "certificate"
    expires: Optional[datetime] = None
    dns_names: Optional[List[str]] = None
    sha1_fingerprint: Optional[str] = None


@define(eq=False, slots=False)
class BaseCertificateQuota(BaseQuota):
    kind: ClassVar[str] = "certificate_quota"


@define(eq=False, slots=False)
class BaseStack(BaseResource):
    kind: ClassVar[str] = "stack"
    stack_status: str = ""
    stack_status_reason: str = ""
    stack_parameters: Dict = field(factory=dict)


@define(eq=False, slots=False)
class BaseAutoScalingGroup(BaseResource):
    kind: ClassVar[str] = "autoscaling_group"
    min_size: int = -1
    max_size: int = -1


@define(eq=False, slots=False)
class BaseIPAddress(BaseResource):
    kind: ClassVar[str] = "ip_address"
    ip_address: str = ""
    ip_address_family: str = ""


@define(eq=False, slots=False)
class BaseHealthCheck(BaseResource):
    kind: ClassVar[str] = "health_check"
    check_interval: int = -1
    healthy_threshold: int = -1
    unhealthy_threshold: int = -1
    timeout: int = -1
    health_check_type: str = ""


@define(eq=False, slots=False)
class BaseDNSZone(BaseResource):
    kind: ClassVar[str] = "dns_zone"


@define(eq=False, slots=False)
class BaseDNSRecordSet(BaseResource):
    kind: ClassVar[str] = "dns_record_set"

    record_ttl: Optional[int] = None
    record_type: str = ""
    record_values: List[str] = field(factory=list)

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.record_type = self.record_type.upper()

    def dns_zone(self, graph=None) -> "BaseDNSZone":
        if graph is None:
            graph = self._graph
        dns_zone = graph.search_first_parent_class(self, BaseDNSZone)
        if dns_zone is None:
            dns_zone = UnknownDNSZone(id="undefined", tags={})
        return dns_zone

    def _keys(self) -> tuple:
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

    def dns_zone(self, graph=None) -> "BaseDNSZone":
        if graph is None:
            graph = self._graph
        dns_zone = graph.search_first_parent_class(self, BaseDNSZone)
        if dns_zone is None:
            dns_zone = UnknownDNSZone(id="undefined", tags={})
        return dns_zone

    def _keys(self) -> tuple:
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
class UnknownCloud(BaseCloud):
    kind: ClassVar[str] = "unknown_cloud"

    def delete(self, graph) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownAccount(BaseAccount):
    kind: ClassVar[str] = "unknown_account"

    def delete(self, graph) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownRegion(BaseRegion):
    kind: ClassVar[str] = "unknown_region"

    def delete(self, graph) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownDNSZone(BaseDNSZone):
    kind: ClassVar[str] = "unknown_dns_zone"

    def delete(self, graph) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownZone(BaseZone):
    kind: ClassVar[str] = "unknown_zone"

    def delete(self, graph) -> bool:
        return False


@define(eq=False, slots=False)
class UnknownLocation(BaseResource):
    kind: ClassVar[str] = "unknown_location"

    def delete(self, graph) -> bool:
        return False


resolve_types(BaseResource)
