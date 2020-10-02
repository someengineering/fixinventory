from abc import ABC, abstractmethod
from functools import wraps
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from copy import deepcopy
import uuid
import networkx.algorithms.dag
import cloudkeeper.logging
from enum import Enum
from typing import Dict, Iterator, List, Tuple
from cloudkeeper.utils import make_valid_timestamp
from prometheus_client import Counter, Summary


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

    resource_type = NotImplemented
    phantom = False
    metrics_description = {}

    def __init__(
        self,
        identifier: str,
        tags: dict,
        name: str = None,
        cloud=None,
        account=None,
        region=None,
        zone=None,
        ctime: datetime = None,
        mtime: datetime = None,
        atime: datetime = None,
    ) -> None:
        self.tags = tags
        self.id = str(identifier)
        self.name = name if name else self.id
        self.uuid = uuid.uuid4().hex
        self._cloud = cloud
        self._account = account
        self._region = region
        self._zone = zone
        self._ctime = None
        self._mtime = None
        self._atime = None
        self.ctime = ctime
        self.mtime = mtime
        self.atime = atime
        self._clean = False
        self._cleaned = False
        self._metrics = {}
        self._deferred_connections = []
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

    @property
    def tags(self) -> Dict:
        return self._tags

    @tags.setter
    def tags(self, value: Dict) -> None:
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

    @property
    def ctime(self) -> datetime:
        if "cloudkeeper:ctime" in self.tags:
            ctime = self.tags["cloudkeeper:ctime"]
            try:
                ctime = make_valid_timestamp(datetime.fromisoformat(ctime))
            except ValueError:
                pass
            else:
                return ctime
        return self._ctime

    @property
    def atime(self) -> datetime:
        return self._atime

    @property
    def mtime(self) -> datetime:
        return self._mtime

    @property
    def clean(self) -> bool:
        return self._clean

    @ctime.setter
    def ctime(self, value: datetime) -> None:
        self._ctime = make_valid_timestamp(value)

    @mtime.setter
    def mtime(self, value: datetime) -> None:
        self._mtime = make_valid_timestamp(value)

    @atime.setter
    def atime(self, value: datetime) -> None:
        self._atime = make_valid_timestamp(value)

    @clean.setter
    @unless_protected
    def clean(self, value: bool) -> None:
        if self.phantom and value:
            raise ValueError(f"Can't cleanup phantom resource {self.dname}")

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
        if self.cleaned:
            log.debug(f"Resource {self.rtdname} has already been cleaned up")
            return True

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
        if self._account:
            account = self._account
        elif graph:
            account = graph.search_first_parent_class(self, BaseAccount)
        if account is None:
            account = UnknownAccount("undefined", {})
        return account

    def cloud(self, graph=None):
        cloud = None
        if self._cloud:
            cloud = self._cloud
        elif graph:
            cloud = graph.search_first_parent_class(self, BaseCloud)
        if cloud is None:
            cloud = UnknownCloud("undefined", {})
        return cloud

    def region(self, graph=None):
        region = None
        if self._region:
            region = self._region
        elif graph:
            region = graph.search_first_parent_class(self, BaseRegion)
        if region is None:
            region = UnknownRegion("undefined", {})
        return region

    def zone(self, graph=None):
        zone = None
        if self._zone:
            zone = self._zone
        elif graph:
            zone = graph.search_first_parent_class(self, BaseZone)
        if zone is None:
            zone = UnknownZone("undefined", {})
        return zone

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
                if not graph.has_edge(src, dst):
                    log.debug(
                        f"Adding deferred edge from {src.rtdname} to {dst.rtdname}"
                    )
                    graph.add_edge(src, dst)
                else:
                    log.error(
                        (
                            f"Edge from {src.rtdname} to {dst.rtdname}"
                            " already exists in graph"
                        )
                    )

    def predecessors(self, graph) -> Iterator:
        """Returns an iterator of the node's parent nodes"""
        return graph.predecessors(self)

    def successors(self, graph) -> Iterator:
        """Returns an iterator of the node's child nodes"""
        return graph.successors(self)

    def ancestors(self, graph) -> Iterator:
        """Returns an iterator of the node's ancestors"""
        return networkx.algorithms.dag.ancestors(graph, self)

    def descendants(self, graph) -> Iterator:
        """Returns an iterator of the node's descendants"""
        return networkx.algorithms.dag.descendants(graph, self)

    def __getstate__(self):
        ret = self.__dict__.copy()
        if self.__custom_metrics:
            ret["__instance_metrics_description"] = self.metrics_description
        return ret

    def __setstate__(self, state):
        if "__instance_metrics_description" in state:
            self.metrics_description = state.pop("__instance_metrics_description")
        self.__dict__.update(state)


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


class PhantomBaseResource(BaseResource):
    phantom = True

    def cleanup(self, graph=None) -> bool:
        log.error(
            f"Resource {self.rtdname} is a phantom resource and can't be cleaned up"
        )
        return False


class BaseQuota(PhantomBaseResource):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.quota = -1.0


class BaseType(BaseQuota):
    pass


class BaseInstanceQuota(BaseQuota):
    metrics_description = {
        "instances_quotas_total": {
            "help": "Quotas of Instances",
            "labels": ["cloud", "account", "region", "type", "quota_type"],
        },
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
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


class BaseInstanceType(BaseType):
    metrics_description = {
        "reserved_instances_total": {
            "help": "Number of Reserved Instances",
            "labels": ["cloud", "account", "region", "type"],
        },
    }

    def __init__(
        self,
        *args,
        instance_type: str = None,
        instance_cores: int = 0,
        instance_memory: int = 0,
        ondemand_cost: float = 0.0,
        reservations: int = 0,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.instance_type = instance_type if instance_type else self.id
        self.instance_cores = int(instance_cores)
        self.instance_memory = int(instance_memory)
        self.ondemand_cost = float(ondemand_cost)
        self.reservations = int(reservations)

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


class BaseCloud(BaseResource):
    def cloud(self, graph=None):
        return self


class BaseAccount(BaseResource):
    metrics_description = {
        "accounts_total": {"help": "Number of Accounts", "labels": ["cloud"]},
    }

    def account(self, graph=None):
        return self

    def metrics(self, graph) -> Dict:
        self._metrics["accounts_total"][(self.cloud(graph).name)] = 1
        return self._metrics


class BaseRegion(BaseResource):
    def region(self, graph=None):
        return self


class BaseZone(BaseResource):
    def zone(self, graph=None):
        return self


class InstanceStatus(Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    TERMINATED = "terminated"
    BUSY = "busy"
    UNKNOWN = "unknown"


class BaseInstance(BaseResource):
    metrics_description = {
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

    def __init__(
        self,
        *args,
        instance_cores: int = 0,
        instance_memory: int = 0,
        instance_type: str = "",
        instance_status: str = "",
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.instance_cores = int(instance_cores)
        self.instance_memory = int(instance_memory)
        self.instance_type = instance_type
        self._instance_status = InstanceStatus.UNKNOWN
        self.instance_status = instance_status

    def instance_type_info(self, graph) -> BaseInstanceType:
        return graph.search_first_parent_class(self, BaseInstanceType)

    @property
    def instance_status(self) -> str:
        return self._instance_status.value

    @instance_status.setter
    @abstractmethod
    def instance_status(self, value: str) -> None:
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


class BaseVolumeType(BaseType):
    metrics_description = {
        "volumes_quotas_bytes": {
            "help": "Quotas of Volumes in bytes",
            "labels": ["cloud", "account", "region", "type"],
        },
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
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


class BaseVolume(BaseResource):
    metrics_description = {
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

    def __init__(
        self,
        *args,
        volume_size: int = 0,
        volume_type: str = "",
        volume_status: str = "",
        snapshot_before_delete: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.volume_size = int(volume_size)
        self.volume_type = volume_type
        self._volume_status = VolumeStatus.UNKNOWN
        self.volume_status = volume_status
        self.snapshot_before_delete = snapshot_before_delete

    @property
    def volume_status(self) -> str:
        return self._volume_status.value

    @volume_status.setter
    @abstractmethod
    def volume_status(self, value: str) -> None:
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


class BaseSnapshot(BaseResource):
    metrics_description = {
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

    def __init__(
        self,
        *args,
        snapshot_status: str = "",
        description: str = "",
        volume_id: str = None,
        volume_size: int = 0,
        encrypted: bool = False,
        owner_id=None,
        owner_alias="",
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.snapshot_status = snapshot_status
        self.description = description
        self.volume_id = volume_id
        self.volume_size = int(volume_size)
        self.encrypted = encrypted
        self.owner_id = owner_id
        self.owner_alias = owner_alias

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


class Cloud(BaseCloud):
    resource_type = "cloud"

    def delete(self, graph) -> bool:
        return False


class GraphRoot(PhantomBaseResource):
    resource_type = "graph_root"

    def delete(self, graph) -> bool:
        return False


class BaseBucket(BaseResource):
    metrics_description = {
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


class BaseKeyPair(BaseResource):
    metrics_description = {
        "keypairs_total": {
            "help": "Number of Key Pairs",
            "labels": ["cloud", "account", "region"],
        },
        "cleaned_keypairs_total": {
            "help": "Cleaned number of Key Pairs",
            "labels": ["cloud", "account", "region"],
        },
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.fingerprint = ""

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


class BaseBucketQuota(BaseQuota):
    metrics_description = {
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


class BaseNetwork(BaseResource):
    metrics_description = {
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


class BaseNetworkQuota(BaseQuota):
    metrics_description = {
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


class BaseDatabase(BaseResource):
    metrics_description = {
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

    def __init__(
        self,
        *args,
        db_type: str = "",
        db_status: str = "",
        db_endpoint: str = "",
        instance_type: str = "",
        volume_size: int = -1,
        volume_iops: int = -1,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.db_type = db_type
        self.db_status = db_status
        self.db_endpoint = db_endpoint
        self.instance_type = instance_type
        self.volume_size = int(volume_size)
        self.volume_iops = int(volume_iops)

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


class BaseLoadBalancer(BaseResource):
    metrics_description = {
        "load_balancers_total": {
            "help": "Number of Load Balancers",
            "labels": ["cloud", "account", "region", "type"],
        },
        "cleaned_load_balancers_total": {
            "help": "Cleaned number of Load Balancers",
            "labels": ["cloud", "account", "region", "type"],
        },
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.lb_type = ""
        self.backends = []

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


class BaseLoadBalancerQuota(BaseQuota):
    metrics_description = {
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


class BaseSubnet(BaseResource):
    metrics_description = {
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


class BaseGateway(BaseResource):
    metrics_description = {
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


class BaseTunnel(BaseResource):
    metrics_description = {
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


class BaseGatewayQuota(BaseQuota):
    metrics_description = {
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


class BaseSecurityGroup(BaseResource):
    metrics_description = {
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


class BaseRoutingTable(BaseResource):
    metrics_description = {
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


class BaseNetworkAcl(BaseResource):
    metrics_description = {
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


class BasePeeringConnection(BaseResource):
    metrics_description = {
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


class BaseEndpoint(BaseResource):
    metrics_description = {
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


class BaseNetworkInterface(BaseResource):
    metrics_description = {
        "network_interfaces_total": {
            "help": "Number of Network Interfaces",
            "labels": ["cloud", "account", "region", "status"],
        },
        "cleaned_network_interfaces_total": {
            "help": "Cleaned number of Network Interfaces",
            "labels": ["cloud", "account", "region", "status"],
        },
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.network_interface_status = ""
        self.network_interface_type = ""
        self.mac = ""
        self.private_ips = []
        self.public_ips = []
        self.v6_ips = []
        self.description = ""

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


class BaseUser(BaseResource):
    metrics_description = {
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


class BaseGroup(BaseResource):
    metrics_description = {
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


class BasePolicy(BaseResource):
    metrics_description = {
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


class BaseRole(BaseResource):
    metrics_description = {
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


class BaseInstanceProfile(BaseResource):
    metrics_description = {
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


class BaseAccessKey(BaseResource):
    metrics_description = {
        "access_keys_total": {
            "help": "Number of Access Keys",
            "labels": ["cloud", "account", "region", "status"],
        },
        "cleaned_access_keys_total": {
            "help": "Cleaned number of Access Keys",
            "labels": ["cloud", "account", "region", "status"],
        },
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.access_key_status = ""

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


class BaseCertificate(BaseResource):
    metrics_description = {
        "certificates_total": {
            "help": "Number of Certificates",
            "labels": ["cloud", "account", "region"],
        },
        "cleaned_certificates_total": {
            "help": "Cleaned number of Certificates",
            "labels": ["cloud", "account", "region"],
        },
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.expires = None

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


class BaseCertificateQuota(BaseQuota):
    metrics_description = {
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


class BaseStack(BaseResource):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.stack_status = ""
        self.stack_status_reason = ""
        self.stack_parameters = {}

    metrics_description = {
        "stacks_total": {
            "help": "Number of Stacks",
            "labels": ["cloud", "account", "region"],
        },
        "cleaned_stacks_total": {
            "help": "Cleaned number of Stacks",
            "labels": ["cloud", "account", "region"],
        },
    }

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


class BaseAutoScalingGroup(BaseResource):
    def __init__(self, *args, min_size: int = -1, max_size: int = -1, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.min_size = int(min_size)
        self.max_size = int(max_size)

    metrics_description = {
        "autoscaling_groups_total": {
            "help": "Number of Autoscaling Groups",
            "labels": ["cloud", "account", "region"],
        },
        "cleaned_autoscaling_groups_total": {
            "help": "Cleaned number of Autoscaling Groups",
            "labels": ["cloud", "account", "region"],
        },
    }

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


class BaseIPAddress(BaseResource):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.ip_address = ""
        self.ip_address_family = ""

    metrics_description = {
        "ip_addresses_total": {
            "help": "Number of IP Addresses",
            "labels": ["cloud", "account", "region"],
        },
        "cleaned_ip_addresses_total": {
            "help": "Cleaned number of IP Addresses",
            "labels": ["cloud", "account", "region"],
        },
    }

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


class BaseHealthCheck(BaseResource):
    def __init__(
        self,
        *args,
        check_interval: int = -1,
        healthy_threshold: int = -1,
        unhealthy_threshold: int = -1,
        timeout: int = -1,
        health_check_type: str = "",
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.check_interval = int(check_interval)
        self.healthy_threshold = int(healthy_threshold)
        self.unhealthy_threshold = int(unhealthy_threshold)
        self.timeout = int(timeout)
        self.health_check_type = health_check_type

    metrics_description = {
        "health_checks_total": {
            "help": "Number of Health Checks",
            "labels": ["cloud", "account", "region"],
        },
        "cleaned_health_checks_total": {
            "help": "Cleaned number of Health Checks",
            "labels": ["cloud", "account", "region"],
        },
    }

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


class UnknownCloud(BaseCloud):
    def delete(self, graph) -> bool:
        return False


class UnknownAccount(BaseAccount):
    def delete(self, graph) -> bool:
        return False


class UnknownRegion(BaseRegion):
    def delete(self, graph) -> bool:
        return False


class UnknownZone(BaseZone):
    def delete(self, graph) -> bool:
        return False
