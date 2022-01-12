from abc import ABC, abstractmethod
from functools import wraps
from datetime import datetime, timezone, timedelta
from copy import deepcopy
import base64
import hashlib
import uuid
import weakref
import networkx.algorithms.dag
from resotolib.logging import log
from enum import Enum
from typing import Dict, Iterator, List, Tuple, ClassVar, Optional
from resotolib.utils import make_valid_timestamp, ResourceChanges
from prometheus_client import Counter, Summary
from dataclasses import dataclass, field


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
metrics_resource_cleanup = Summary(
    "cloudkeeper_resource_cleanup_seconds", "Time it took the resource cleanup() method"
)


def unless_protected(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        if not isinstance(self, BaseResource):
            raise ValueError(
                "unless_protected() only supports BaseResource type objects"
            )
        if self.protected:
            log.error(f"Resource {self.rtdname} is protected - refusing modification")
            self.log(
                (
                    "Modification was requested even though resource is protected"
                    " - refusing"
                )
            )
            return False
        return f(self, *args, **kwargs)

    return wrapper


@dataclass(eq=False)
class BaseResource(ABC):
    """A BaseResource is any node we're connecting to the Graph()

    BaseResources have an id, name and tags. The id is a unique id used to search for
    the resource within the Graph. The name is used for display purposes. Tags are
    key/value pairs that get exported in the GRAPHML view.

    There's also three class variables, kind, phantom and metrics_description.
    kind is a string describing the type of resource, e.g. 'aws_ec2_instance'
    or 'some_cloud_load_balancer'.
    phantom is a bool describing whether or not the resource actually exists within
    the cloud or if it's just a phantom resource like pricing information or usage
    quota. I.e. some information relevant to the cloud account but not actually existing
    in the form of a usable resource.

    metrics_description is a dict of metrics the resource exports. They are turned into
    Prometheus GaugeMetricFamily() metrics by the metrics module. The key defines the
    name of the metric. Its value is another Dict with the keys 'help' containing the
    Help Text and nother key 'labels' containing a List of metrics labels.

    An example for an instance metric could be
    {
      'cores_total':
        {
          'help': 'Number of CPU cores',
          'labels': ['cloud', 'account', 'region', 'type']
        }
    }
    which would get exported as 'cloudkeeper_cores_total' with labels cloud=aws,
    account=1234567, region=us-west-2, type=m5.xlarge and value 8 if the instance has
    8 CPU cores. The actual /metrics endpoint would then SUM all the values from metrics
    with the same name and labels and export a total of e.g. 1105 cores accross all
    instances of this type and in this cloud, account and region.
    """

    kind: ClassVar[str] = "resource"
    phantom: ClassVar[bool] = False
    metrics_description: ClassVar[Dict] = {}

    id: str
    tags: Dict[str, str] = None
    name: str = None
    _cloud: object = field(default=None, repr=False)
    _account: object = field(default=None, repr=False)
    _region: object = field(default=None, repr=False)
    _zone: object = field(default=None, repr=False)
    _resotocore_id: Optional[str] = field(default=None, repr=False)
    _resotocore_revision: Optional[str] = field(default=None, repr=False)
    _resotocore_query_tag: Optional[str] = field(default=None, repr=False)
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

    def __post_init__(self) -> None:
        if self.name is None:
            self.name = self.id
        self.uuid = uuid.uuid4().hex
        self._clean: bool = False
        self._cleaned: bool = False
        self._protected: bool = False
        self._changes: ResourceChanges = ResourceChanges(self)
        self._metrics: Dict = {}
        self._deferred_connections: List = []
        self.__graph = None
        self.__log: List = []
        self.__custom_metrics: bool = False
        self._raise_tags_exceptions: bool = False
        self.max_graph_depth: int = 0
        for metric in self.metrics_description.keys():
            self._metrics[metric] = {}
        if not hasattr(self, "_tags"):
            self._tags = None
        if not hasattr(self, "_ctime"):
            self._ctime = None
        if not hasattr(self, "_atime"):
            self._atime = None
        if not hasattr(self, "_mtime"):
            self._mtime = None

    def __repr__(self):
        return (
            f"{self.__class__.__name__}('{self.id}', name='{self.name}',"
            f" region='{self.region().name}', zone='{self.zone().name}',"
            f" account='{self.account().dname}', kind='{self.kind}',"
            f" ctime={self.ctime!r}, uuid={self.uuid}, chksum={self.chksum})"
        )

    def _keys(self):
        return (
            self.kind,
            self.cloud().id,
            self.account().id,
            self.region().id,
            self.zone().id,
            self.id,
            self.name,
        )

    #    def __hash__(self):
    #        return hash(self._keys())

    #    def __eq__(self, other):
    #        if isinstance(other, type(self)):
    #            return self._keys() == other._keys()
    #        return NotImplemented

    @property
    def dname(self) -> str:
        if self.id == self.name:
            return self.id
        return f"{self.name} ({self.id})"

    @property
    def kdname(self) -> str:
        return f"{self.kind} {self.dname}"

    rtdname = kdname

    def _tags_getter(self) -> Dict:
        return self._tags

    def _tags_setter(self, value: Dict) -> None:
        if value is None:
            value = {}
        self._tags = ResourceTagsDict(dict(value), parent_resource=self)

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

    @property
    def resource_type(self) -> str:
        return self.kind

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
                "timestamp": le["timestamp"].isoformat(),
                "msg": le["msg"],
                "exception": le["exception"],
            }
            for le in self.__log
        ]

    def update_tag(self, key, value) -> bool:
        raise NotImplementedError

    def delete_tag(self, key) -> bool:
        raise NotImplementedError

    @property
    def chksum(self) -> str:
        return (
            base64.urlsafe_b64encode(
                hashlib.blake2b(str(self._keys()).encode(), digest_size=16).digest()
            )
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
        if "cloudkeeper:ctime" in self.tags:
            ctime = self.tags["cloudkeeper:ctime"]
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
            log.error(
                f"Could not determine account or region for cleanup of {self.rtdname}"
            )
            return False

        log_suffix = f" in account {account.dname} region {region.name}"
        self.log("Trying to clean up")
        log.debug(f"Trying to clean up {self.rtdname}{log_suffix}")
        try:
            if not self.delete(graph):
                self.log("Failed to clean up")
                log.error(f"Failed to clean up {self.rtdname}{log_suffix}")
                return False
            self._cleaned = True
            self.log("Successfully cleaned up")
            log.info(f"Successfully cleaned up {self.rtdname}{log_suffix}")
        except Exception as e:
            self.log("An error occurred during clean up", exception=e)
            log.exception(
                f"An error occurred during clean up {self.rtdname}{log_suffix}"
            )
            cloud = self.cloud(graph)
            metrics_resource_cleanup_exceptions.labels(
                cloud=cloud.name,
                account=account.dname,
                region=region.name,
                kind=self.kind,
            ).inc()
            return False
        return True

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
            log.error(
                (
                    "Could not determine account or region for pre cleanup of"
                    f" {self.rtdname}"
                )
            )
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
            log.exception(
                f"An error occurred during pre clean up {self.rtdname}{log_suffix}"
            )
            cloud = self.cloud(graph)
            metrics_resource_pre_cleanup_exceptions.labels(
                cloud=cloud.name,
                account=account.dname,
                region=region.name,
                kind=self.kind,
            ).inc()
            return False
        return True

    @unless_protected
    @abstractmethod
    def delete(self, graph) -> bool:
        raise NotImplementedError

    def account(self, graph=None):
        account = None
        if graph is None:
            graph = self._graph
        if self._account:
            account = self._account
        elif graph:
            account = graph.search_first_parent_class(self, BaseAccount)
        if account is None:
            account = UnknownAccount("undefined", {})
        return account

    def cloud(self, graph=None):
        cloud = None
        if graph is None:
            graph = self._graph
        if self._cloud:
            cloud = self._cloud
        elif graph:
            cloud = graph.search_first_parent_class(self, BaseCloud)
        if cloud is None:
            cloud = UnknownCloud("undefined", {})
        return cloud

    def region(self, graph=None):
        region = None
        if graph is None:
            graph = self._graph
        if self._region:
            region = self._region
        elif graph:
            region = graph.search_first_parent_class(self, BaseRegion)
        if region is None:
            region = UnknownRegion("undefined", {})
        return region

    def zone(self, graph=None):
        zone = None
        if graph is None:
            graph = self._graph
        if self._zone:
            zone = self._zone
        elif graph:
            zone = graph.search_first_parent_class(self, BaseZone)
        if zone is None:
            zone = UnknownZone("undefined", {})
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
        return UnknownLocation("undefined", {})

    def to_json(self):
        return self.__repr__()

    def metrics(self, graph) -> Dict:
        return self._metrics

    def add_metric(
        self, metric: str, value: int, help: str, labels: List, label_values: Tuple
    ) -> bool:
        self.__custom_metrics = True
        # todo: sync test and assignment
        if metric not in self.metrics_description:
            log.debug(f"Metric {metric} not in class metrics description - adding")
            self.metrics_description[metric] = {"help": help, "labels": labels}
        self._metrics[metric] = {}
        self._metrics[metric][label_values] = value

    def add_deferred_connection(self, attr, value, parent=True) -> None:
        self._deferred_connections.append(
            {"attr": attr, "value": value, "parent": parent}
        )

    def resolve_deferred_connections(self, graph) -> None:
        if graph is None:
            graph = self._graph
        while self._deferred_connections:
            dc = self._deferred_connections.pop(0)
            node = graph.search_first(dc["attr"], dc["value"])
            if node:
                if dc["parent"]:
                    src = node
                    dst = self
                else:
                    src = self
                    dst = node
                graph.add_edge(src, dst)

    def predecessors(self, graph) -> Iterator:
        """Returns an iterator of the node's parent nodes"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return ()
        return graph.predecessors(self)

    def successors(self, graph) -> Iterator:
        """Returns an iterator of the node's child nodes"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return ()
        return graph.successors(self)

    def predecessor_added(self, resource, graph) -> None:
        """Called when a predecessor is added to this node"""
        pass

    def successor_added(self, resource, graph) -> None:
        """Called when a successor is added to this node"""
        pass

    def ancestors(self, graph) -> Iterator:
        """Returns an iterator of the node's ancestors"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return ()
        return networkx.algorithms.dag.ancestors(graph, self)

    def descendants(self, graph) -> Iterator:
        """Returns an iterator of the node's descendants"""
        if graph is None:
            graph = self._graph
        if graph is None:
            return ()
        return networkx.algorithms.dag.descendants(graph, self)

    @property
    def _graph(self):
        if self.__graph is not None:
            return self.__graph()

    @_graph.setter
    def _graph(self, value) -> None:
        self.__graph = weakref.ref(value)

    def __getstate__(self):
        ret = self.__dict__.copy()
        if self.__custom_metrics:
            ret["__instance_metrics_description"] = self.metrics_description
        ret["_BaseResource__graph"] = None
        return ret

    def __setstate__(self, state):
        if "__instance_metrics_description" in state:
            self.metrics_description = state.pop("__instance_metrics_description")
        self.__dict__.update(state)


BaseResource.tags = property(BaseResource._tags_getter, BaseResource._tags_setter)
BaseResource.ctime = property(BaseResource._ctime_getter, BaseResource._ctime_setter)
BaseResource.mtime = property(BaseResource._mtime_getter, BaseResource._mtime_setter)
BaseResource.atime = property(BaseResource._atime_getter, BaseResource._atime_setter)


class ResourceTagsDict(dict):
    def __init__(self, *args, parent_resource=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.__parent_resource = None
        self.parent_resource = parent_resource

    @property
    def parent_resource(self):
        return self.__parent_resource

    @parent_resource.setter
    def parent_resource(self, value):
        self.__parent_resource = value

    def __setitem__(self, key, value):
        if self.parent_resource and isinstance(self.parent_resource, BaseResource):
            log.debug(f"Calling parent resource to set tag {key} to {value} in cloud")
            try:
                if self.parent_resource.update_tag(key, value):
                    log_msg = f"Successfully set tag {key} to {value} in cloud"
                    self.parent_resource._changes.add("tags")
                    self.parent_resource.log(log_msg)
                    log.info(
                        (
                            f"{log_msg} for {self.parent_resource.kind}"
                            f" {self.parent_resource.id}"
                        )
                    )
                    return super().__setitem__(key, value)
                else:
                    log_msg = f"Error setting tag {key} to {value} in cloud"
                    self.parent_resource.log(log_msg)
                    log.error(
                        (
                            f"{log_msg} for {self.parent_resource.kind}"
                            f" {self.parent_resource.id}"
                        )
                    )
            except Exception as e:
                log_msg = (
                    f"Unhandled exception while trying to set tag {key} to {value}"
                    f" in cloud: {type(e)} {e}"
                )
                self.parent_resource.log(log_msg, exception=e)
                if self.parent_resource._raise_tags_exceptions:
                    raise
                else:
                    log.exception(log_msg)
        else:
            return super().__setitem__(key, value)

    def __delitem__(self, key):
        if self.parent_resource and isinstance(self.parent_resource, BaseResource):
            log.debug(f"Calling parent resource to delete tag {key} in cloud")
            try:
                if self.parent_resource.delete_tag(key):
                    log_msg = f"Successfully deleted tag {key} in cloud"
                    self.parent_resource._changes.add("tags")
                    self.parent_resource.log(log_msg)
                    log.info(
                        (
                            f"{log_msg} for {self.parent_resource.kind}"
                            f" {self.parent_resource.id}"
                        )
                    )
                    return super().__delitem__(key)
                else:
                    log_msg = f"Error deleting tag {key} in cloud"
                    self.parent_resource.log(log_msg)
                    log.error(
                        (
                            f"{log_msg} for {self.parent_resource.kind}"
                            f" {self.parent_resource.id}"
                        )
                    )
            except Exception as e:
                log_msg = (
                    f"Unhandled exception while trying to delete tag {key} in cloud:"
                    f" {type(e)} {e}"
                )
                self.parent_resource.log(log_msg, exception=e)
                if self.parent_resource._raise_tags_exceptions:
                    raise
                else:
                    log.exception(log_msg)
        else:
            return super().__delitem__(key)

    def __reduce__(self):
        return super().__reduce__()


@dataclass(eq=False)
class PhantomBaseResource(BaseResource):
    kind: ClassVar[str] = "phantom_resource"
    phantom: ClassVar[bool] = True

    def cleanup(self, graph=None) -> bool:
        log.error(
            f"Resource {self.rtdname} is a phantom resource and can't be cleaned up"
        )
        return False


@dataclass(eq=False)
class BaseQuota(PhantomBaseResource):
    kind: ClassVar[str] = "quota"
    quota: Optional[float] = None
    usage: Optional[float] = None
    quota_type: Optional[str] = None

    def __post_init__(self) -> None:
        super().__post_init__()
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


@dataclass(eq=False)
class BaseType(BaseQuota):
    kind: ClassVar[str] = "type"


@dataclass(eq=False)
class BaseInstanceQuota(BaseQuota):
    kind: ClassVar[str] = "instance_quota"
    metrics_description: ClassVar[Dict] = {
        "instances_quotas_total": {
            "help": "Quotas of Instances",
            "labels": ["cloud", "account", "region", "type", "quota_type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " instance_type as type, quota_type : sum(quota) as instances_quotas_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("instance_quota") and quota >= 0'
            ),
        },
    }
    instance_type: Optional[str] = None

    def __post_init__(self, *args, **kwargs) -> None:
        super().__post_init__(*args, **kwargs)
        self.instance_type = self.id
        self.quota_type = "standard"

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.instance_type,
            self.quota_type,
        )
        if self.quota is not None:
            self._metrics["instances_quotas_total"][metrics_keys] = self.quota
        return self._metrics


@dataclass(eq=False)
class BaseInstanceType(BaseType):
    kind: ClassVar[str] = "instance_type"
    metrics_description: ClassVar[Dict] = {
        "reserved_instances_total": {
            "help": "Number of Reserved Instances",
            "labels": ["cloud", "account", "region", "type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " instance_type as type, quota_type : sum(reservations) as reserved_instances_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("instance_type") and reservations >= 0'
            ),
        },
    }
    instance_type: Optional[str] = None
    instance_cores: float = 0.0
    instance_memory: float = 0.0
    ondemand_cost: Optional[float] = None
    reservations: Optional[int] = None

    def __post_init__(
        self,
        *args,
        **kwargs,
    ) -> None:
        super().__post_init__(*args, **kwargs)
        if self.instance_type is None:
            self.instance_type = self.id
        if self.reservations is not None:
            self.reservations = int(self.reservations)
        if self.ondemand_cost is not None:
            self.ondemand_cost = float(self.ondemand_cost)

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.instance_type,
        )
        if self.reservations and self.reservations > 0:
            self._metrics["reserved_instances_total"][metrics_keys] = self.reservations
        return self._metrics


@dataclass(eq=False)
class BaseCloud(BaseResource):
    kind: ClassVar[str] = "base_cloud"

    _replace: bool = field(default=False, repr=False)

    def cloud(self, graph=None):
        return self


@dataclass(eq=False)
class BaseAccount(BaseResource):
    kind: ClassVar[str] = "account"
    metrics_description: ClassVar[Dict] = {
        "accounts_total": {
            "help": "Number of Accounts",
            "labels": ["cloud"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud,"
                " instance_type as type, quota_type : sum(1) as accounts_total)"
                ' (merge_with_ancestors="cloud"): is("account")'
            ),
        },
    }

    _replace: bool = field(default=False, repr=False)

    def account(self, graph=None):
        return self

    def metrics(self, graph) -> Dict:
        self._metrics["accounts_total"][(self.cloud(graph).name)] = 1
        return self._metrics


@dataclass(eq=False)
class BaseRegion(BaseResource):
    kind: ClassVar[str] = "region"

    _replace: bool = field(default=False, repr=False)

    def region(self, graph=None):
        return self


@dataclass(eq=False)
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


@dataclass(eq=False)
class BaseInstance(BaseResource):
    kind: ClassVar[str] = "instance"
    metrics_description: ClassVar[Dict] = {
        "instances_total": {
            "help": "Number of Instances",
            "labels": ["cloud", "account", "region", "type", "status"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " instance_type as type, instance_status as status : sum(1) as instances_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("instance")'
            ),
        },
        "cores_total": {
            "help": "Number of CPU cores",
            "labels": ["cloud", "account", "region", "type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " instance_type as type : sum(instance_cores) as cores_total)"
                ' (merge_with_ancestors="cloud,account,region"):'
                ' is("instance") and instance_status == "running"'
            ),
        },
        "memory_bytes": {
            "help": "Amount of RAM in bytes",
            "labels": ["cloud", "account", "region", "type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " instance_type as type : sum(instance_memory * 1024 * 1024 * 1024) as memory_bytes)"
                ' (merge_with_ancestors="cloud,account,region"):'
                ' is("instance") and instance_status == "running"'
            ),
        },
        "instances_hourly_cost_estimate": {
            "help": "Hourly instance cost estimate",
            "labels": ["cloud", "account", "region", "type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " instance_type as type : sum(parent_instance_type.ondemand_cost) as instances_hourly_cost_estimate)"
                ' (merge_with_ancestors="cloud,account,region,instance_type as parent_instance_type"):'
                ' is("instance") and instance_status == "running"'
            ),
        },
        "cleaned_instances_total": {
            "help": "Cleaned number of Instances",
            "labels": ["cloud", "account", "region", "type", "status"],
        },
        "cleaned_cores_total": {
            "help": "Cleaned number of CPU cores",
            "labels": ["cloud", "account", "region", "type"],
        },
        "cleaned_memory_bytes": {
            "help": "Cleaned amount of RAM in bytes",
            "labels": ["cloud", "account", "region", "type"],
        },
        "cleaned_instances_hourly_cost_estimate": {
            "help": "Cleaned hourly instance cost estimate",
            "labels": ["cloud", "account", "region", "type"],
        },
    }
    instance_cores: float = 0.0
    instance_memory: float = 0.0
    instance_type: Optional[str] = ""
    instance_status: Optional[str] = ""

    def instance_type_info(self, graph) -> BaseInstanceType:
        return graph.search_first_parent_class(self, BaseInstanceType)

    def _instance_status_getter(self) -> str:
        return self._instance_status.value

    @abstractmethod
    def _instance_status_setter(self, value: str) -> None:
        raise NotImplementedError

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.instance_type,
        )
        instance_type_info = self.instance_type_info(graph)
        self._metrics["instances_total"][metrics_keys + (self.instance_status,)] = 1
        if self._cleaned:
            self._metrics["cleaned_instances_total"][
                metrics_keys + (self.instance_status,)
            ] = 1

        if self.instance_status == "running":
            self._metrics["cores_total"][metrics_keys] = self.instance_cores
            if self._cleaned:
                self._metrics["cleaned_cores_total"][metrics_keys] = self.instance_cores
            if instance_type_info:
                self._metrics["memory_bytes"][metrics_keys] = (
                    instance_type_info.instance_memory * 1024 ** 3
                )
                if self._cleaned:
                    self._metrics["cleaned_memory_bytes"][metrics_keys] = (
                        instance_type_info.instance_memory * 1024 ** 3
                    )
                self._metrics["instances_hourly_cost_estimate"][
                    metrics_keys
                ] = instance_type_info.ondemand_cost
                if self._cleaned:
                    self._metrics["cleaned_instances_hourly_cost_estimate"][
                        metrics_keys
                    ] = instance_type_info.ondemand_cost
        return self._metrics


BaseInstance.instance_status = property(
    BaseInstance._instance_status_getter, BaseInstance._instance_status_setter
)


@dataclass(eq=False)
class BaseVolumeType(BaseType):
    kind: ClassVar[str] = "volume_type"
    metrics_description: ClassVar[Dict] = {
        "volumes_quotas_bytes": {
            "help": "Quotas of Volumes in bytes",
            "labels": ["cloud", "account", "region", "type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " volume_type as type : sum(quota * 1024 * 1024 * 1024 * 1024) as volumes_quotas_bytes)"
                ' (merge_with_ancestors="cloud,account,region"): is("volume_type") and quota >= 0'
            ),
        },
    }
    volume_type: str = ""
    ondemand_cost: float = 0.0

    def __post_init__(self, *args, **kwargs) -> None:
        super().__post_init__(*args, **kwargs)
        self.volume_type = self.id

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.volume_type,
        )
        if self.quota is not None and self.quota > -1:
            self._metrics["volumes_quotas_bytes"][metrics_keys] = self.quota * 1024 ** 4
        return self._metrics


class VolumeStatus(Enum):
    IN_USE = "in-use"
    AVAILABLE = "available"
    BUSY = "busy"
    ERROR = "error"
    DELETED = "deleted"
    UNKNOWN = "unknown"


@dataclass(eq=False)
class BaseVolume(BaseResource):
    kind: ClassVar[str] = "volume"
    metrics_description: ClassVar[Dict] = {
        "volumes_total": {
            "help": "Number of Volumes",
            "labels": ["cloud", "account", "region", "type", "status"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " volume_type as type, volume_status as status : sum(1) as volumes_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("volume")'
            ),
        },
        "volume_bytes": {
            "help": "Size of Volumes in bytes",
            "labels": ["cloud", "account", "region", "type", "status"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " volume_type as type, volume_status as status :"
                " sum(volume_size * 1024 * 1024 * 1024) as volume_bytes)"
                ' (merge_with_ancestors="cloud,account,region"): is("volume")'
            ),
        },
        "volumes_monthly_cost_estimate": {
            "help": "Monthly volume cost estimate",
            "labels": ["cloud", "account", "region", "type", "status"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " volume_type as type, volume_status as status :"
                " sum(parent_volume_type.ondemand_cost) as volumes_monthly_cost_estimate)"
                ' (merge_with_ancestors="cloud,account,region,volume_type as parent_volume_type"):'
                ' is("volume")'
            ),
        },
        "cleaned_volumes_total": {
            "help": "Cleaned number of Volumes",
            "labels": ["cloud", "account", "region", "type", "status"],
        },
        "cleaned_volume_bytes": {
            "help": "Cleaned size of Volumes in bytes",
            "labels": ["cloud", "account", "region", "type", "status"],
        },
        "cleaned_volumes_monthly_cost_estimate": {
            "help": "Cleaned monthly volume cost estimate",
            "labels": ["cloud", "account", "region", "type", "status"],
        },
    }
    volume_size: int = 0
    volume_type: str = ""
    volume_status: str = ""
    volume_iops: Optional[int] = None
    volume_throughput: Optional[int] = None
    volume_encrypted: Optional[bool] = None
    snapshot_before_delete: bool = False

    def _volume_status_getter(self) -> str:
        return self._volume_status.value

    @abstractmethod
    def _volume_status_setter(self, value: str) -> None:
        raise NotImplementedError

    def volume_type_info(self, graph) -> BaseVolumeType:
        return graph.search_first_parent_class(self, BaseVolumeType)

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.volume_type,
            self.volume_status,
        )
        volume_type_info = self.volume_type_info(graph)
        self._metrics["volumes_total"][metrics_keys] = 1
        self._metrics["volume_bytes"][metrics_keys] = self.volume_size * 1024 ** 3
        if self._cleaned:
            self._metrics["cleaned_volumes_total"][metrics_keys] = 1
            self._metrics["cleaned_volume_bytes"][metrics_keys] = (
                self.volume_size * 1024 ** 3
            )
        if volume_type_info:
            self._metrics["volumes_monthly_cost_estimate"][metrics_keys] = (
                self.volume_size * volume_type_info.ondemand_cost
            )
            if self._cleaned:
                self._metrics["cleaned_volumes_monthly_cost_estimate"][metrics_keys] = (
                    self.volume_size * volume_type_info.ondemand_cost
                )
        return self._metrics


BaseVolume.volume_status = property(
    BaseVolume._volume_status_getter, BaseVolume._volume_status_setter
)


@dataclass(eq=False)
class BaseSnapshot(BaseResource):
    kind: ClassVar[str] = "snapshot"
    metrics_description: ClassVar[Dict] = {
        "snapshots_total": {
            "help": "Number of Snapshots",
            "labels": ["cloud", "account", "region", "status"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " snapshot_status as status : sum(1) as snapshots_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("snapshot")'
            ),
        },
        "snapshots_volumes_bytes": {
            "help": "Size of Snapshots Volumes in bytes",
            "labels": ["cloud", "account", "region", "status"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " snapshot_status as status : sum(volume_size * 1024 * 1024 * 1024) as snapshots_volumes_bytes)"
                ' (merge_with_ancestors="cloud,account,region"): is("snapshot")'
            ),
        },
        "cleaned_snapshots_total": {
            "help": "Cleaned number of Snapshots",
            "labels": ["cloud", "account", "region", "status"],
        },
        "cleaned_snapshots_volumes_bytes": {
            "help": "Cleaned size of Snapshots Volumes in bytes",
            "labels": ["cloud", "account", "region", "status"],
        },
    }

    snapshot_status: str = ""
    description: str = ""
    volume_id: Optional[str] = None
    volume_size: int = 0
    encrypted: bool = False
    owner_id: Optional[str] = None
    owner_alias: str = ""

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.snapshot_status,
        )
        self._metrics["snapshots_total"][metrics_keys] = 1
        self._metrics["snapshots_volumes_bytes"][metrics_keys] = (
            self.volume_size * 1024 ** 3
        )
        if self._cleaned:
            self._metrics["cleaned_snapshots_total"][metrics_keys] = 1
            self._metrics["cleaned_snapshots_volumes_bytes"][metrics_keys] = (
                self.volume_size * 1024 ** 3
            )
        return self._metrics


@dataclass(eq=False)
class Cloud(BaseCloud):
    kind: ClassVar[str] = "cloud"

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class GraphRoot(PhantomBaseResource):
    kind: ClassVar[str] = "graph_root"

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class BaseBucket(BaseResource):
    kind: ClassVar[str] = "bucket"
    metrics_description: ClassVar[Dict] = {
        "buckets_total": {
            "help": "Number of Storage Buckets",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region:"
                " sum(1) as buckets_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("bucket")'
            ),
        },
        "cleaned_buckets_total": {
            "help": "Cleaned number of Storage Buckets",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["buckets_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_buckets_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseKeyPair(BaseResource):
    kind: ClassVar[str] = "keypair"
    metrics_description: ClassVar[Dict] = {
        "keypairs_total": {
            "help": "Number of Key Pairs",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region:"
                " sum(1) as keypairs_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("keypair")'
            ),
        },
        "cleaned_keypairs_total": {
            "help": "Cleaned number of Key Pairs",
            "labels": ["cloud", "account", "region"],
        },
    }
    fingerprint: str = ""

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["keypairs_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_keypairs_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseBucketQuota(BaseQuota):
    kind: ClassVar[str] = "bucket_quota"
    metrics_description: ClassVar[Dict] = {
        "buckets_quotas_total": {
            "help": "Quotas of Storage Buckets",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region:"
                " sum(1) as buckets_quotas_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("bucket_quota")'
            ),
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        if self.quota > -1:
            self._metrics["buckets_quotas_total"][metrics_keys] = self.quota
        return self._metrics


@dataclass(eq=False)
class BaseNetwork(BaseResource):
    kind: ClassVar[str] = "network"
    metrics_description: ClassVar[Dict] = {
        "networks_total": {
            "help": "Number of Networks",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region:"
                " sum(1) as networks_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("network")'
            ),
        },
        "cleaned_networks_total": {
            "help": "Cleaned number of Networks",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["networks_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_networks_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseNetworkQuota(BaseQuota):
    kind: ClassVar[str] = "network_quota"
    metrics_description: ClassVar[Dict] = {
        "networks_quotas_total": {
            "help": "Quotas of Networks",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region:"
                " sum(1) as networks_quotas_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("network_quota")'
            ),
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        if self.quota > -1:
            self._metrics["networks_quotas_total"][metrics_keys] = self.quota
        return self._metrics


@dataclass(eq=False)
class BaseDatabase(BaseResource):
    kind: ClassVar[str] = "database"
    metrics_description: ClassVar[Dict] = {
        "databases_total": {
            "help": "Number of Databases",
            "labels": ["cloud", "account", "region", "type", "instance_type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " db_type as type, instance_type : sum(1) as databases_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("database")'
            ),
        },
        "databases_bytes": {
            "help": "Size of Databases in bytes",
            "labels": ["cloud", "account", "region", "type", "instance_type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " db_type as type, instance_type : sum(volume_size * 1024 * 1024 * 1024) as databases_bytes)"
                ' (merge_with_ancestors="cloud,account,region"): is("database")'
            ),
        },
        "cleaned_databases_total": {
            "help": "Cleaned number of Databases",
            "labels": ["cloud", "account", "region", "type", "instance_type"],
        },
        "cleaned_databases_bytes": {
            "help": "Cleaned size of Databases in bytes",
            "labels": ["cloud", "account", "region", "type", "instance_type"],
        },
    }
    db_type: str = ""
    db_status: str = ""
    db_endpoint: str = ""
    db_version: Optional[str] = None
    db_publicly_accessible: Optional[bool] = None
    instance_type: str = ""
    volume_size: int = 0
    volume_iops: Optional[int] = None
    volume_encrypted: Optional[bool] = None

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.db_type,
            self.instance_type,
        )
        self._metrics["databases_total"][metrics_keys] = 1
        self._metrics["databases_bytes"][metrics_keys] = self.volume_size * 1024 ** 3
        if self._cleaned:
            self._metrics["cleaned_databases_total"][metrics_keys] = 1
            self._metrics["cleaned_databases_bytes"][metrics_keys] = (
                self.volume_size * 1024 ** 3
            )
        return self._metrics


@dataclass(eq=False)
class BaseLoadBalancer(BaseResource):
    kind: ClassVar[str] = "load_balancer"
    metrics_description: ClassVar[Dict] = {
        "load_balancers_total": {
            "help": "Number of Load Balancers",
            "labels": ["cloud", "account", "region", "type"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " lb_type as type : sum(1) as load_balancers_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("load_balancer")'
            ),
        },
        "cleaned_load_balancers_total": {
            "help": "Cleaned number of Load Balancers",
            "labels": ["cloud", "account", "region", "type"],
        },
    }
    lb_type: str = ""
    backends: List[str] = field(default_factory=list)

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.lb_type,
        )
        self._metrics["load_balancers_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_load_balancers_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseLoadBalancerQuota(BaseQuota):
    kind: ClassVar[str] = "load_balancer_quota"
    metrics_description: ClassVar[Dict] = {
        "load_balancers_quotas_total": {
            "help": "Quotas of Load Balancers",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as load_balancers_quotas_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("load_balancer_quota")'
            ),
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        if self.quota > -1:
            self._metrics["load_balancers_quotas_total"][metrics_keys] = self.quota
        return self._metrics


@dataclass(eq=False)
class BaseSubnet(BaseResource):
    kind: ClassVar[str] = "subnet"
    metrics_description: ClassVar[Dict] = {
        "subnets_total": {
            "help": "Number of Subnets",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as subnets_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("subnet")'
            ),
        },
        "cleaned_subnets_total": {
            "help": "Cleaned number of Subnets",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["subnets_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_subnets_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseGateway(BaseResource):
    kind: ClassVar[str] = "gateway"
    metrics_description: ClassVar[Dict] = {
        "gateways_total": {
            "help": "Number of Gateways",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as gateways_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("gateway")'
            ),
        },
        "cleaned_gateways_total": {
            "help": "Cleaned number of Gateways",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["gateways_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_gateways_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseTunnel(BaseResource):
    kind: ClassVar[str] = "tunnel"
    metrics_description: ClassVar[Dict] = {
        "tunnels_total": {
            "help": "Number of Tunnels",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as tunnels_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("tunnel")'
            ),
        },
        "cleaned_tunnels_total": {
            "help": "Cleaned number of Tunnels",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["tunnels_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_tunnels_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseGatewayQuota(BaseQuota):
    kind: ClassVar[str] = "gateway_quota"
    metrics_description: ClassVar[Dict] = {
        "gateways_quotas_total": {
            "help": "Quotas of Gateways",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as gateways_quotas_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("gateway_quota")'
            ),
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        if self.quota > -1:
            self._metrics["gateways_quotas_total"][metrics_keys] = self.quota
        return self._metrics


@dataclass(eq=False)
class BaseSecurityGroup(BaseResource):
    kind: ClassVar[str] = "security_group"
    metrics_description: ClassVar[Dict] = {
        "security_groups_total": {
            "help": "Number of Security Groups",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as security_groups_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("security_group")'
            ),
        },
        "cleaned_security_groups_total": {
            "help": "Cleaned number of Security Groups",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["security_groups_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_security_groups_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseRoutingTable(BaseResource):
    kind: ClassVar[str] = "routing_table"
    metrics_description: ClassVar[Dict] = {
        "routing_tables_total": {
            "help": "Number of Routing Tables",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as routing_tables_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("routing_table")'
            ),
        },
        "cleaned_routing_tables_total": {
            "help": "Cleaned number of Routing Tables",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["routing_tables_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_routing_tables_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseNetworkAcl(BaseResource):
    kind: ClassVar[str] = "network_acl"
    metrics_description: ClassVar[Dict] = {
        "network_acls_total": {
            "help": "Number of Network ACLs",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as network_acls_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("network_acl")'
            ),
        },
        "cleaned_network_acls_total": {
            "help": "Cleaned number of Network ACLs",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["network_acls_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_network_acls_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BasePeeringConnection(BaseResource):
    kind: ClassVar[str] = "peering_connection"
    metrics_description: ClassVar[Dict] = {
        "peering_connections_total": {
            "help": "Number of Peering Connections",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as peering_connections_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("peering_connection")'
            ),
        },
        "cleaned_peering_connections_total": {
            "help": "Cleaned number of Peering Connections",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["peering_connections_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_peering_connections_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseEndpoint(BaseResource):
    kind: ClassVar[str] = "endpoint"
    metrics_description: ClassVar[Dict] = {
        "endpoints_total": {
            "help": "Number of Endpoints",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as endpoints_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("endpoint")'
            ),
        },
        "cleaned_endpoints_total": {
            "help": "Cleaned number of Endpoints",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["endpoints_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_endpoints_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseNetworkInterface(BaseResource):
    kind: ClassVar[str] = "network_interface"
    metrics_description: ClassVar[Dict] = {
        "network_interfaces_total": {
            "help": "Number of Network Interfaces",
            "labels": ["cloud", "account", "region", "status"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " network_interface_status as status : sum(1) as network_interfaces_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("network_interface")'
            ),
        },
        "cleaned_network_interfaces_total": {
            "help": "Cleaned number of Network Interfaces",
            "labels": ["cloud", "account", "region", "status"],
        },
    }
    network_interface_status: str = ""
    network_interface_type: str = ""
    mac: str = ""
    private_ips: List[str] = field(default_factory=list)
    public_ips: List[str] = field(default_factory=list)
    v6_ips: List[str] = field(default_factory=list)
    description: str = ""

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.network_interface_status,
        )
        self._metrics["network_interfaces_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_network_interfaces_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseUser(BaseResource):
    kind: ClassVar[str] = "user"
    metrics_description: ClassVar[Dict] = {
        "users_total": {
            "help": "Number of Users",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as users_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("user")'
            ),
        },
        "cleaned_users_total": {
            "help": "Cleaned number of Users",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["users_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_users_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseGroup(BaseResource):
    kind: ClassVar[str] = "group"
    metrics_description: ClassVar[Dict] = {
        "groups_total": {
            "help": "Number of Groups",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as groups_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("group")'
            ),
        },
        "cleaned_groups_total": {
            "help": "Cleaned number of Groups",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["groups_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_groups_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BasePolicy(BaseResource):
    kind: ClassVar[str] = "policy"
    metrics_description: ClassVar[Dict] = {
        "policies_total": {
            "help": "Number of Policies",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as policies_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("policy")'
            ),
        },
        "cleaned_policies_total": {
            "help": "Cleaned number of Policies",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["policies_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_policies_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseRole(BaseResource):
    kind: ClassVar[str] = "role"
    metrics_description: ClassVar[Dict] = {
        "roles_total": {
            "help": "Number of Roles",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as roles_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("role")'
            ),
        },
        "cleaned_roles_total": {
            "help": "Cleaned number of Roles",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["roles_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_roles_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseInstanceProfile(BaseResource):
    kind: ClassVar[str] = "instance_profile"
    metrics_description: ClassVar[Dict] = {
        "instance_profiles_total": {
            "help": "Number of Instance Profiles",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as instance_profiles_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("instance_profile")'
            ),
        },
        "cleaned_instance_profiles_total": {
            "help": "Cleaned number of Instance Profiles",
            "labels": ["cloud", "account", "region"],
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["instance_profiles_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_instance_profiles_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseAccessKey(BaseResource):
    kind: ClassVar[str] = "access_key"
    metrics_description: ClassVar[Dict] = {
        "access_keys_total": {
            "help": "Number of Access Keys",
            "labels": ["cloud", "account", "region", "status"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region,"
                " access_key_status as status : sum(1) as access_keys_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("access_key")'
            ),
        },
        "cleaned_access_keys_total": {
            "help": "Cleaned number of Access Keys",
            "labels": ["cloud", "account", "region", "status"],
        },
    }
    access_key_status: str = ""

    def metrics(self, graph) -> Dict:
        self._metrics["access_keys_total"][
            (
                self.cloud(graph).name,
                self.account(graph).dname,
                self.region(graph).name,
                str(self.access_key_status).lower(),
            )
        ] = 1
        if self._cleaned:
            self._metrics["cleaned_access_keys_total"][
                (
                    self.cloud(graph).name,
                    self.account(graph).dname,
                    self.region(graph).name,
                    str(self.access_key_status).lower(),
                )
            ] = 1
        return self._metrics


@dataclass(eq=False)
class BaseCertificate(BaseResource):
    kind: ClassVar[str] = "certificate"
    metrics_description: ClassVar[Dict] = {
        "certificates_total": {
            "help": "Number of Certificates",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as certificates_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("certificate")'
            ),
        },
        "cleaned_certificates_total": {
            "help": "Cleaned number of Certificates",
            "labels": ["cloud", "account", "region"],
        },
    }
    expires: Optional[datetime] = None

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["certificates_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_certificates_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseCertificateQuota(BaseQuota):
    kind: ClassVar[str] = "certificate_quota"
    metrics_description: ClassVar[Dict] = {
        "certificates_quotas_total": {
            "help": "Quotas of Certificates",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as certificates_quotas_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("certificate_quota")'
            ),
        },
    }

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        if self.quota > -1:
            self._metrics["certificates_quotas_total"][metrics_keys] = self.quota
        return self._metrics


@dataclass(eq=False)
class BaseStack(BaseResource):
    kind: ClassVar[str] = "stack"
    metrics_description: ClassVar[Dict] = {
        "stacks_total": {
            "help": "Number of Stacks",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as stacks_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("stack")'
            ),
        },
        "cleaned_stacks_total": {
            "help": "Cleaned number of Stacks",
            "labels": ["cloud", "account", "region"],
        },
    }
    stack_status: str = ""
    stack_status_reason: str = ""
    stack_parameters: Dict = field(default_factory=dict)

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["stacks_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_stacks_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseAutoScalingGroup(BaseResource):
    kind: ClassVar[str] = "autoscaling_group"
    metrics_description: ClassVar[Dict] = {
        "autoscaling_groups_total": {
            "help": "Number of Autoscaling Groups",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as autoscaling_groups_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("autoscaling_group")'
            ),
        },
        "cleaned_autoscaling_groups_total": {
            "help": "Cleaned number of Autoscaling Groups",
            "labels": ["cloud", "account", "region"],
        },
    }
    min_size: int = -1
    max_size: int = -1

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["autoscaling_groups_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_autoscaling_groups_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseIPAddress(BaseResource):
    kind: ClassVar[str] = "ip_address"
    metrics_description: ClassVar[Dict] = {
        "ip_addresses_total": {
            "help": "Number of IP Addresses",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as ip_addresses_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("ip_address")'
            ),
        },
        "cleaned_ip_addresses_total": {
            "help": "Cleaned number of IP Addresses",
            "labels": ["cloud", "account", "region"],
        },
    }
    ip_address: str = ""
    ip_address_family: str = ""

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["ip_addresses_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_ip_addresses_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class BaseHealthCheck(BaseResource):
    kind: ClassVar[str] = "health_check"
    metrics_description: ClassVar[Dict] = {
        "health_checks_total": {
            "help": "Number of Health Checks",
            "labels": ["cloud", "account", "region"],
            "type": "gauge",
            "query": (
                "aggregate(cloud.name as cloud, account.name as account, region.name as region :"
                " sum(1) as health_checks_total)"
                ' (merge_with_ancestors="cloud,account,region"): is("health_check")'
            ),
        },
        "cleaned_health_checks_total": {
            "help": "Cleaned number of Health Checks",
            "labels": ["cloud", "account", "region"],
        },
    }
    check_interval: int = -1
    healthy_threshold: int = -1
    unhealthy_threshold: int = -1
    timeout: int = -1
    health_check_type: str = ""

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
        )
        self._metrics["health_checks_total"][metrics_keys] = 1
        if self._cleaned:
            self._metrics["cleaned_health_checks_total"][metrics_keys] = 1
        return self._metrics


@dataclass(eq=False)
class UnknownCloud(BaseCloud):
    kind: ClassVar[str] = "unknown_cloud"

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class UnknownAccount(BaseAccount):
    kind: ClassVar[str] = "unknown_account"

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class UnknownRegion(BaseRegion):
    kind: ClassVar[str] = "unknown_region"

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class UnknownZone(BaseZone):
    kind: ClassVar[str] = "unknown_zone"

    def delete(self, graph) -> bool:
        return False


@dataclass(eq=False)
class UnknownLocation(BaseResource):
    kind: ClassVar[str] = "unknown_location"

    def delete(self, graph) -> bool:
        return False
