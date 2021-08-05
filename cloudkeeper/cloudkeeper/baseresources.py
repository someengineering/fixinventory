from __future__ import annotations
from abc import ABC, abstractmethod
from functools import wraps
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from copy import deepcopy
import uuid
import weakref
import networkx.algorithms.dag
import cloudkeeper.logging
from enum import Enum
from typing import Dict, Iterator, List, Tuple, ClassVar, Optional
from cloudkeeper.utils import make_valid_timestamp
from prometheus_client import Counter, Summary
from dataclasses import dataclass, InitVar, field


log = cloudkeeper.logging.getLogger(__name__)

metrics_resource_pre_cleanup_exceptions = Counter(
    "resource_pre_cleanup_exceptions_total",
    "Number of resource pre_cleanup() exceptions",
    ["cloud", "account", "region", "resource_type"],
)
metrics_resource_cleanup_exceptions = Counter(
    "resource_cleanup_exceptions_total",
    "Number of resource cleanup() exceptions",
    ["cloud", "account", "region", "resource_type"],
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


@dataclass
class BaseResource(ABC):
    """A BaseResource is any node we're connecting to the Graph()

    BaseResources have an id, name and tags. The id is a unique id used to search for
    the resource within the Graph. The name is used for display purposes. Tags are
    key/value pairs that get exported in the GRAPHML view.

    There's also three class variables, resource_type, phantom and metrics_description.
    resource_type is a string describing the type of resource, e.g. 'aws_ec2_instance'
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

    resource_type: ClassVar[str] = "base_resource"
    phantom: ClassVar[bool] = False
    metrics_description: ClassVar[Dict] = {}

    id: str
    tags: Dict = None
    name: InitVar[str] = None
    _cloud: BaseCloud = field(default=None, repr=False)
    _account: BaseAccount = field(default=None, repr=False)
    _region: BaseRegion  = field(default=None, repr=False)
    _zone: BaseZone = field(default=None, repr=False)
    ctime: datetime = None
    mtime: datetime = None
    atime: datetime = None

    def __post_init__(
        self,
        name: str = None,
    ) -> None:
        self.name = name if name else self.id
        self.uuid = uuid.uuid4().hex
        self._clean = False
        self._cleaned = False
        self._metrics = {}
        self._deferred_connections = []
        self.__graph = None
        self.__log = []
        self.__protected = False
        self.__custom_metrics = False
        self.max_graph_depth = 0
        for metric in self.metrics_description.keys():
            self._metrics[metric] = {}

    def __repr__(self):
        return (
            f"{self.__class__.__name__}('{self.id}', name='{self.name}',"
            f" region='{self.region().name}', zone='{self.zone().name}',"
            f" account='{self.account().dname}', resource_type='{self.resource_type}',"
            f" ctime={self.ctime!r}, uuid={self.uuid}, sha256={self.sha256})"
        )

    def _keys(self):
        return (
            self.resource_type,
            self.account().id,
            self.region().id,
            self.zone().id,
            self.id,
            self.name,
            self.ctime,
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
    def rtdname(self) -> str:
        return f"{self.resource_type} {self.dname}"

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
            "exception": deepcopy(exception),
            "data": deepcopy(data),
        }
        self.__log.append(log_entry)

    @property
    def event_log(self) -> List:
        return self.__log

    def update_tag(self, key, value) -> bool:
        raise NotImplementedError

    def delete_tag(self, key) -> bool:
        raise NotImplementedError

    @property
    def sha256(self) -> str:
        return sha256(str(self._keys()).encode()).hexdigest()

    @property
    def age(self) -> timedelta:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        return now - self.ctime

    @property
    def last_access(self) -> timedelta:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        return now - self.atime

    @property
    def last_update(self) -> timedelta:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        return now - self.mtime

    def _ctime_getter(self) -> datetime:
        if "cloudkeeper:ctime" in self.tags:
            ctime = self.tags["cloudkeeper:ctime"]
            try:
                ctime = make_valid_timestamp(datetime.fromisoformat(ctime))
            except ValueError:
                pass
            else:
                return ctime
        return self._ctime

    def _ctime_setter(self, value: datetime) -> None:
        self._ctime = make_valid_timestamp(value)

    def _atime_getter(self) -> datetime:
        return self._atime

    def _atime_setter(self, value: datetime) -> None:
        self._atime = make_valid_timestamp(value)

    def _mtime_getter(self) -> datetime:
        return self._mtime

    def _mtime_setter(self, value: datetime) -> None:
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
        self._clean = value

    @property
    def cleaned(self) -> bool:
        return self._cleaned

    @property
    def protected(self) -> bool:
        return self.__protected

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
            self.__protected = value

    @metrics_resource_cleanup.time()
    @unless_protected
    def cleanup(self, graph=None) -> bool:
        if self.phantom:
            raise RuntimeError(f"Can't cleanup phantom resource {self.rtdname}")

        if self.cleaned:
            log.debug(f"Resource {self.rtdname} has already been cleaned up")
            return True

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
                resource_type=self.resource_type,
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
                resource_type=self.resource_type,
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
                    self.parent_resource.log(log_msg)
                    log.info(
                        (
                            f"{log_msg} for {self.parent_resource.resource_type}"
                            f" {self.parent_resource.id}"
                        )
                    )
                    return super().__setitem__(key, value)
                else:
                    log_msg = f"Error setting tag {key} to {value} in cloud"
                    self.parent_resource.log(log_msg)
                    log.error(
                        (
                            f"{log_msg} for {self.parent_resource.resource_type}"
                            f" {self.parent_resource.id}"
                        )
                    )
            except Exception as e:
                log_msg = (
                    f"Unhandled exception while trying to set tag {key} to {value}"
                    f" in cloud: {type(e)} {e}"
                )
                self.parent_resource.log(log_msg, exception=e)
                log.exception(log_msg)
        else:
            return super().__setitem__(key, value)

    def __delitem__(self, key):
        if self.parent_resource and isinstance(self.parent_resource, BaseResource):
            log.debug(f"Calling parent resource to delete tag {key} in cloud")
            try:
                if self.parent_resource.delete_tag(key):
                    log_msg = f"Successfully deleted tag {key} in cloud"
                    self.parent_resource.log(log_msg)
                    log.info(
                        (
                            f"{log_msg} for {self.parent_resource.resource_type}"
                            f" {self.parent_resource.id}"
                        )
                    )
                    return super().__delitem__(key)
                else:
                    log_msg = f"Error deleting tag {key} in cloud"
                    self.parent_resource.log(log_msg)
                    log.error(
                        (
                            f"{log_msg} for {self.parent_resource.resource_type}"
                            f" {self.parent_resource.id}"
                        )
                    )
            except Exception as e:
                log_msg = (
                    f"Unhandled exception while trying to delete tag {key} in cloud:"
                    f" {type(e)} {e}"
                )
                self.parent_resource.log(log_msg, exception=e)
                log.exception(log_msg)
        else:
            return super().__delitem__(key)

    def __reduce__(self):
        return super().__reduce__()


@dataclass
class PhantomBaseResource(BaseResource):
    phantom: ClassVar[bool] = True

    def cleanup(self, graph=None) -> bool:
        log.error(
            f"Resource {self.rtdname} is a phantom resource and can't be cleaned up"
        )
        return False


@dataclass
class BaseQuota(PhantomBaseResource):
    quota: int = -1
    usage: int = 0

    @property
    def usage_percentage(self) -> float:
        if self.quota > 0:
            return self.usage / self.quota * 100
        else:
            return 0.0


@dataclass
class BaseType(BaseQuota):
    pass


@dataclass
class BaseInstanceQuota(BaseQuota):
    metrics_description: ClassVar[Dict] = {
        "instances_quotas_total": {
            "help": "Quotas of Instances",
            "labels": ["cloud", "account", "region", "type", "quota_type"],
        },
    }

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
        if self.quota > -1:
            self._metrics["instances_quotas_total"][metrics_keys] = self.quota
        return self._metrics


@dataclass
class BaseInstanceType(BaseType):
    metrics_description: ClassVar[Dict] = {
        "reserved_instances_total": {
            "help": "Number of Reserved Instances",
            "labels": ["cloud", "account", "region", "type"],
        },
    }
    instance_type: str = None
    instance_cores: float = 0.0
    instance_memory: float = 0.0
    ondemand_cost: float = 0.0
    reservations: int = 0

    def __post_init__(
        self,
        *args,
        **kwargs,
    ) -> None:
        super().__post_init__(*args, **kwargs)
        if self.instance_type is None:
            self.instance_type = self.id

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.instance_type,
        )
        if self.reservations > 0:
            self._metrics["reserved_instances_total"][metrics_keys] = self.reservations
        return self._metrics


@dataclass
class BaseCloud(BaseResource):
    def cloud(self, graph=None):
        return self


@dataclass
class BaseAccount(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "accounts_total": {"help": "Number of Accounts", "labels": ["cloud"]},
    }

    def account(self, graph=None):
        return self

    def metrics(self, graph) -> Dict:
        self._metrics["accounts_total"][(self.cloud(graph).name)] = 1
        return self._metrics


@dataclass
class BaseRegion(BaseResource):
    def region(self, graph=None):
        return self


@dataclass
class BaseZone(BaseResource):
    def zone(self, graph=None):
        return self


class InstanceStatus(Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    TERMINATED = "terminated"
    BUSY = "busy"
    UNKNOWN = "unknown"


@dataclass
class BaseInstance(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "instances_total": {
            "help": "Number of Instances",
            "labels": ["cloud", "account", "region", "type", "status"],
        },
        "cores_total": {
            "help": "Number of CPU cores",
            "labels": ["cloud", "account", "region", "type"],
        },
        "memory_bytes": {
            "help": "Amount of RAM in bytes",
            "labels": ["cloud", "account", "region", "type"],
        },
        "instances_hourly_cost_estimate": {
            "help": "Hourly instance cost estimate",
            "labels": ["cloud", "account", "region", "type"],
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
    instance_type: str = ""
    instance_status: str = ""

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
BaseInstance.instance_status = property(BaseInstance._instance_status_getter, BaseInstance._instance_status_setter)


@dataclass
class BaseVolumeType(BaseType):
    metrics_description: ClassVar[Dict] = {
        "volumes_quotas_bytes": {
            "help": "Quotas of Volumes in bytes",
            "labels": ["cloud", "account", "region", "type"],
        },
    }

    def __post_init__(self, *args, **kwargs) -> None:
        super().__post_init__(*args, **kwargs)
        self.volume_type = self.id
        self.ondemand_cost = 0.0

    def metrics(self, graph) -> Dict:
        metrics_keys = (
            self.cloud(graph).name,
            self.account(graph).dname,
            self.region(graph).name,
            self.volume_type,
        )
        if self.quota > -1:
            self._metrics["volumes_quotas_bytes"][metrics_keys] = self.quota * 1024 ** 4
        return self._metrics


class VolumeStatus(Enum):
    IN_USE = "in-use"
    AVAILABLE = "available"
    BUSY = "busy"
    ERROR = "error"
    DELETED = "deleted"
    UNKNOWN = "unknown"


@dataclass
class BaseVolume(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "volumes_total": {
            "help": "Number of Volumes",
            "labels": ["cloud", "account", "region", "type", "status"],
        },
        "volume_bytes": {
            "help": "Size of Volumes in bytes",
            "labels": ["cloud", "account", "region", "type", "status"],
        },
        "volumes_monthly_cost_estimate": {
            "help": "Monthly volume cost estimate",
            "labels": ["cloud", "account", "region", "type", "status"],
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
BaseVolume.volume_status = property(BaseVolume._volume_status_getter, BaseVolume._volume_status_setter)


@dataclass
class BaseSnapshot(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "snapshots_total": {
            "help": "Number of Snapshots",
            "labels": ["cloud", "account", "region", "status"],
        },
        "snapshots_volumes_bytes": {
            "help": "Size of Snapshots Volumes in bytes",
            "labels": ["cloud", "account", "region", "status"],
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
    volume_id: str = None
    volume_size: int = 0
    encrypted: bool = False
    owner_id: int = None
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


@dataclass
class Cloud(BaseCloud):
    resource_type: ClassVar[str] = "cloud"

    def delete(self, graph) -> bool:
        return False


@dataclass
class GraphRoot(PhantomBaseResource):
    resource_type: ClassVar[str] = "graph_root"

    def delete(self, graph) -> bool:
        return False


@dataclass
class BaseBucket(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "buckets_total": {
            "help": "Number of Storage Buckets",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseKeyPair(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "keypairs_total": {
            "help": "Number of Key Pairs",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseBucketQuota(BaseQuota):
    metrics_description: ClassVar[Dict] = {
        "buckets_quotas_total": {
            "help": "Quotas of Storage Buckets",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseNetwork(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "networks_total": {
            "help": "Number of Networks",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseNetworkQuota(BaseQuota):
    metrics_description: ClassVar[Dict] = {
        "networks_quotas_total": {
            "help": "Quotas of Networks",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseDatabase(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "databases_total": {
            "help": "Number of Databases",
            "labels": ["cloud", "account", "region", "type", "instance_type"],
        },
        "databases_bytes": {
            "help": "Size of Databases in bytes",
            "labels": ["cloud", "account", "region", "type", "instance_type"],
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
    instance_type: str = ""
    volume_size: int = -1
    volume_iops: int = -1

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


@dataclass
class BaseLoadBalancer(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "load_balancers_total": {
            "help": "Number of Load Balancers",
            "labels": ["cloud", "account", "region", "type"],
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


@dataclass
class BaseLoadBalancerQuota(BaseQuota):
    metrics_description: ClassVar[Dict] = {
        "load_balancers_quotas_total": {
            "help": "Quotas of Load Balancers",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseSubnet(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "subnets_total": {
            "help": "Number of Subnets",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseGateway(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "gateways_total": {
            "help": "Number of Gateways",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseTunnel(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "tunnels_total": {
            "help": "Number of Tunnels",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseGatewayQuota(BaseQuota):
    metrics_description: ClassVar[Dict] = {
        "gateways_quotas_total": {
            "help": "Quotas of Gateways",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseSecurityGroup(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "security_groups_total": {
            "help": "Number of Security Groups",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseRoutingTable(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "routing_tables_total": {
            "help": "Number of Routing Tables",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseNetworkAcl(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "network_acls_total": {
            "help": "Number of Network ACLs",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BasePeeringConnection(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "peering_connections_total": {
            "help": "Number of Peering Connections",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseEndpoint(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "endpoints_total": {
            "help": "Number of Endpoints",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseNetworkInterface(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "network_interfaces_total": {
            "help": "Number of Network Interfaces",
            "labels": ["cloud", "account", "region", "status"],
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


@dataclass
class BaseUser(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "users_total": {
            "help": "Number of Users",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseGroup(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "groups_total": {
            "help": "Number of Groups",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BasePolicy(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "policies_total": {
            "help": "Number of Policies",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseRole(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "roles_total": {
            "help": "Number of Roles",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseInstanceProfile(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "instance_profiles_total": {
            "help": "Number of Instance Profiles",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseAccessKey(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "access_keys_total": {
            "help": "Number of Access Keys",
            "labels": ["cloud", "account", "region", "status"],
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


@dataclass
class BaseCertificate(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "certificates_total": {
            "help": "Number of Certificates",
            "labels": ["cloud", "account", "region"],
        },
        "cleaned_certificates_total": {
            "help": "Cleaned number of Certificates",
            "labels": ["cloud", "account", "region"],
        },
    }
    expires: datetime = None

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


@dataclass
class BaseCertificateQuota(BaseQuota):
    metrics_description: ClassVar[Dict] = {
        "certificates_quotas_total": {
            "help": "Quotas of Certificates",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseStack(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "stacks_total": {
            "help": "Number of Stacks",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseAutoScalingGroup(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "autoscaling_groups_total": {
            "help": "Number of Autoscaling Groups",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseIPAddress(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "ip_addresses_total": {
            "help": "Number of IP Addresses",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class BaseHealthCheck(BaseResource):
    metrics_description: ClassVar[Dict] = {
        "health_checks_total": {
            "help": "Number of Health Checks",
            "labels": ["cloud", "account", "region"],
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


@dataclass
class UnknownCloud(BaseCloud):
    resource_type: ClassVar[str] = "unknown_cloud"

    def delete(self, graph) -> bool:
        return False


@dataclass
class UnknownAccount(BaseAccount):
    resource_type: ClassVar[str] = "unknown_account"

    def delete(self, graph) -> bool:
        return False


@dataclass
class UnknownRegion(BaseRegion):
    resource_type: ClassVar[str] = "unknown_region"

    def delete(self, graph) -> bool:
        return False


@dataclass
class UnknownZone(BaseZone):
    resource_type: ClassVar[str] = "unknown_zone"

    def delete(self, graph) -> bool:
        return False


@dataclass
class UnknownLocation(BaseResource):
    resource_type: ClassVar[str] = "unknown_location"

    def delete(self, graph) -> bool:
        return False
