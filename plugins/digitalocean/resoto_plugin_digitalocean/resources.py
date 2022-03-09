from dataclasses import InitVar, dataclass, field
from typing import ClassVar, Dict, List, Optional

import resotolib.logging
from resotolib.baseresources import (
    BaseAccount,
    BaseDatabase,
    BaseInstance,
    BaseIPAddress,
    BaseLoadBalancer,
    BaseNetwork,
    BaseRegion,
    BaseResource,
    BaseSnapshot,
    BaseVolume,
    InstanceStatus,
    VolumeStatus,
)
from resotolib.graph import Graph

log = resotolib.logging.getLogger("resoto." + __name__)


@dataclass(eq=False)
class DigitalOceanResource(BaseResource):
    """A class that implements the abstract method delete() as well as update_tag()
    and delete_tag().

    delete() must be implemented. update_tag() and delete_tag() are optional.
    """

    kind: ClassVar[str] = "digitalocean_resource"

    def delete(self, graph: Graph) -> bool:
        """Delete a resource in the cloud"""
        log.debug(
            f"Deleting resource {self.id} in account {self.account(graph).id} region {self.region(graph).id}"
        )
        return True

    def update_tag(self, key, value) -> bool:
        """Update a resource tag in the cloud"""
        log.debug(f"Updating or setting tag {key}: {value} on resource {self.id}")
        return True

    def delete_tag(self, key) -> bool:
        """Delete a resource tag in the cloud"""
        log.debug(f"Deleting tag {key} on resource {self.id}")
        return True


@dataclass(eq=False)
class DigitalOceanTeam(DigitalOceanResource, BaseAccount):
    """DigitalOcean Team"""

    kind: ClassVar[str] = "digitalocean_team"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented  # DO does not have a team API yet


@dataclass(eq=False)
class DigitalOceanRegion(DigitalOceanResource, BaseRegion):
    """DigitalOcean region"""

    kind: ClassVar[str] = "digitalocean_region"

    slug: str = field(default="")
    features: List[str] = field(default_factory=list)
    available: bool = field(default=True)
    sizes: List[str] = field(default_factory=list)

    def delete(self, graph: Graph) -> bool:
        """Regions can usually not be deleted so we return NotImplemented"""
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanProject(DigitalOceanResource, BaseAccount):
    """DigitalOcean project"""

    kind: ClassVar[str] = "digitalocean_project"
    owner_uuid: str = field(default="")
    owner_id: str = field(default="")
    description: str = field(default="")
    purpose: str = field(default="")
    environment: str = field(default="")
    is_default: bool = field(default=False)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanDroplet(DigitalOceanResource, BaseInstance):
    """A DigitalOcean Droplet Resource

    Droplet have a class variable `instance_status_map` which contains
    a mapping from the droplet status string the cloud API returns
    to our internal InstanceStatus state.
    """

    kind: ClassVar[str] = "digitalocean_droplet"
    instance_status_map: ClassVar[Dict[str, InstanceStatus]] = {
        "new": InstanceStatus.BUSY,
        "active": InstanceStatus.RUNNING,
        "off": InstanceStatus.TERMINATED,
        "archive": InstanceStatus.TERMINATED,
    }
    backup_ids: List[str] = field(default_factory=list)
    locked: bool = field(default=False)
    features: List[str] = field(default_factory=list)
    image: str = field(default="")

    def _instance_status_setter(self, value: str) -> None:
        """Setter that looks up the instance status

        Based on the string that was give we're doing a dict lookup
        for the corresponding instance status and assign it or
        InstanceStatus.UNKNOWN.
        """
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )


# Because we are using dataclasses and allow to supply the `instance_status`
# string to the constructor we can not use the normal @property decorator.
# Instead we assign the property once the class has been fully defined.
DigitalOceanDroplet.instance_status = property(
    DigitalOceanDroplet._instance_status_getter,
    DigitalOceanDroplet._instance_status_setter,
)


@dataclass(eq=False)
class DigitalOceanKubernetesCluster(DigitalOceanResource, BaseResource):
    """DigitalOcean Kubernetes Cluster"""

    kind: ClassVar[str] = "digitalocean_kubernetes_cluster"

    verson: str = field(default="")
    cluster_subnet: str = field(default="")
    service_subnet: str = field(default="")
    ipv4: str = field(default="")
    endpoint: str = field(default="")
    auto_upgrade: bool = field(default=False)
    status: str = field(default="")
    surge_upgrade: bool = field(default=False)
    registry_enabled: bool = field(default=False)
    ha: bool = field(default=False)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanVolume(DigitalOceanResource, BaseVolume):
    kind: ClassVar[str] = "digitalocean_volume"

    volume_status_map: ClassVar[Dict[str, VolumeStatus]] = {
        "creating": VolumeStatus.BUSY,
        "available": VolumeStatus.AVAILABLE,
        "in-use": VolumeStatus.IN_USE,
        "deleting": VolumeStatus.BUSY,
        "deleted": VolumeStatus.DELETED,
        "error": VolumeStatus.ERROR,
        "busy": VolumeStatus.BUSY,
    }

    description: str = field(default="")
    filesystem_type: str = field(default="")
    filesystem_label: str = field(default="")

    def _volume_status_setter(self, value: str) -> None:
        self._volume_status = self.volume_status_map.get(value, VolumeStatus.UNKNOWN)


DigitalOceanVolume.volume_status = property(
    DigitalOceanVolume._volume_status_getter, DigitalOceanVolume._volume_status_setter
)


@dataclass(eq=False)
class DigitalOceanDatabase(DigitalOceanResource, BaseDatabase):
    kind: ClassVar[str] = "digitalocean_database"


@dataclass(eq=False)
class DigitalOceanNetwork(DigitalOceanResource, BaseNetwork):
    """DigitalOcean network

    This is what instances and other networking related resources might reside in.
    """

    kind: ClassVar[str] = "digitalocean_network"

    ip_range: str = field(default="")
    description: str = field(default="")
    default: bool = field(default=False)


@dataclass(eq=False)
class DigitalOceanSnapshot(DigitalOceanResource, BaseSnapshot):
    """DigitalOcean image"""

    kind: ClassVar[str] = "digitalocean_snapshot"

    size_gigabytes: float = field(default=0.0)
    resource_id: str = field(default="")
    resource_type: str = field(default="")

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanLoadBalancer(DigitalOceanResource, BaseLoadBalancer):
    """DigitalOcean load balancer"""

    kind: ClassVar[str] = "digitalocean_load_balancer"

    ip: str = field(default="")
    size_unit: int = field(default=1)
    status: str = field(default="")
    redirect_http_to_https: bool = field(default=False)
    enable_proxy_protocol: bool = field(default=False)
    enable_backend_keepalive: bool = field(default=False)
    disable_lets_encrypt_dns_records: bool = field(default=False)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanFloatingIP(DigitalOceanResource, BaseIPAddress):
    """DigitalOcean floating IP"""

    kind: ClassVar[str] = "digitalocean_floating_ip"

    locked: bool = field(default=False)

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


@dataclass(eq=False)
class DigitalOceanCustomResource(DigitalOceanResource, BaseResource):
    """An digitalocean custom resource that only inherits the collectors
    DigitalOceanResource class as well as the BaseResource base class.

    This is mainly an digitalocean of how to use typed Python dataclasses
    from which the resoto data model is being generated.
    """

    kind: ClassVar[str] = "digitalocean_custom_resource"

    custom_string_attribute: str = ""
    custom_int_attribute: int = 0
    custom_optional_float_attribute: Optional[float] = None
    custom_dict_attribute: Dict[str, str] = field(default_factory=dict)
    custom_list_attribute: List[str] = field(default_factory=list)
    init_only_attribute: InitVar[Optional[str]] = None

    def __post_init__(self, init_only_attribute: str) -> None:
        super().__post_init__()
        if init_only_attribute is not None:
            self.some_other_var = init_only_attribute
