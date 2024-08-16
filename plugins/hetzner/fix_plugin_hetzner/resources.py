from attrs import define
from typing import ClassVar, Optional, Union, Any
from datetime import datetime
from fixlib.graph import Graph
from fixlib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseZone,
    BaseInstance,
    BaseNetwork,
    BaseResource,
    BaseVolume,
    BaseInstanceType,
    BaseIPAddress,
)


@define(eq=False, slots=False)
class HcloudResource(BaseResource):
    kind: ClassVar[str] = "hcloud_resource"
    kind_display: ClassVar[str] = "Hetzner Cloud Resource"
    kind_description: ClassVar[str] = "A Hetzner Cloud Resource represents a single resource in the Hetzner Cloud"

    hcloud_id: Optional[int] = None

    def delete(self, graph: Graph) -> bool:
        return NotImplemented

    def update_tag(self, key, value) -> bool:
        return NotImplemented

    def delete_tag(self, key) -> bool:
        return NotImplemented


@define(eq=False, slots=False)
class HcloudProject(BaseAccount, HcloudResource):
    kind: ClassVar[str] = "hcloud_project"


@define(eq=False, slots=False)
class HcloudLocation(BaseRegion, HcloudResource):
    kind: ClassVar[str] = "hcloud_location"


@define(eq=False, slots=False)
class HcloudDatacenter(BaseZone, HcloudResource):
    kind: ClassVar[str] = "hcloud_datacenter"


@define(eq=False, slots=False)
class HcloudIPv4Address:
    kind: ClassVar[str] = "hcloud_ipv4_address"

    ip_address: Optional[str] = None
    blocked: Optional[bool] = None
    dns_ptr: Optional[Union[str, list[dict[str, str]]]] = None


@define(eq=False, slots=False)
class HcloudIPv6Network:
    kind: ClassVar[str] = "hcloud_ipv6_network"

    ip_address: Optional[str] = None
    blocked: Optional[bool] = None
    dns_ptr: Optional[Union[str, list[dict[str, str]]]] = None
    network: Optional[str] = None
    network_mask: Optional[str] = None


@define(eq=False, slots=False)
class HcloudFloatingIP(BaseIPAddress, HcloudResource):
    kind: ClassVar[str] = "hcloud_floating_ip"

    description: Optional[str] = None
    dns_ptr: Optional[Union[str, list[dict[str, str]]]] = None
    home_location: Optional[HcloudLocation] = None
    blocked: Optional[bool] = None
    protection: Optional[dict[str, bool]] = None


@define(eq=False, slots=False)
class HcloudFirewall(HcloudResource):
    kind: ClassVar[str] = "hcloud_firewall"


@define(eq=False, slots=False)
class HcloudPrimaryIP(BaseIPAddress, HcloudResource):
    kind: ClassVar[str] = "hcloud_primary_ip"

    dns_ptr: Optional[Union[str, list[dict[str, str]]]] = None
    blocked: Optional[bool] = None
    protection: Optional[dict[str, bool]] = None
    assignee_id: Optional[int] = None
    assigneer_type: Optional[str] = None
    auto_delete: Optional[bool] = None


@define(eq=False, slots=False)
class HcloudPublicNetwork:
    kind: ClassVar[str] = "hcloud_public_network"

    ipv4: Optional[HcloudIPv4Address] = None
    ipv6: Optional[HcloudIPv6Network] = None


@define(eq=False, slots=False)
class HcloudPrivateNetwork:
    kind: ClassVar[str] = "hcloud_private_network"

    ip_address: Optional[str] = None
    alias_ips: Optional[list[str]] = None
    mac_address: Optional[str] = None


@define(eq=False, slots=False)
class HcloudDeprecationInfo:
    kind: ClassVar[str] = "hcloud_deprecation_info"

    announced_at: Optional[datetime] = None
    unavailable_after: Optional[datetime] = None


@define(eq=False, slots=False)
class HcloudServerType(BaseInstanceType, HcloudResource):
    kind: ClassVar[str] = "hcloud_server_type"

    description: Optional[str] = None
    volume_size: Optional[int] = None
    prices: Optional[list[dict[str, Union[str, float, dict[str, Union[str, float]]]]]] = None
    storage_type: Optional[str] = None
    cpu_type: Optional[str] = None
    architecture: Optional[str] = None
    deprecated: Optional[bool] = None
    deprecation: Optional[HcloudDeprecationInfo] = None
    included_traffic: Optional[int] = None


@define(eq=False, slots=False)
class HcloudVolume(BaseVolume, HcloudResource):
    kind: ClassVar[str] = "hcloud_volume"

    linux_device: Optional[str] = None
    protection: Optional[dict[str, bool]] = None
    format: Optional[str] = None


@define(eq=False, slots=False)
class HcloudSubnet:
    kind: ClassVar[str] = "hcloud_subnet"

    type: Optional[str] = None
    ip_range: Optional[str] = None
    network_zone: Optional[str] = None
    gateway: Optional[str] = None
    vswitch_id: Optional[int] = None


@define(eq=False, slots=False)
class HcloudRoute:
    kind: ClassVar[str] = "hcloud_route"

    destination: Optional[str] = None
    gateway: Optional[str] = None


@define(eq=False, slots=False)
class HcloudNetwork(BaseNetwork, HcloudResource):
    kind: ClassVar[str] = "hcloud_network"

    ip_range: Optional[str] = None
    network_subnets: Optional[list[HcloudSubnet]] = None
    network_routes: Optional[list[HcloudRoute]] = None
    expose_routes_to_vswitch: Optional[bool] = None
    protection: Optional[dict[str, bool]] = None


@define(eq=False, slots=False)
class HcloudServer(BaseInstance, HcloudResource):
    kind: ClassVar[str] = "hcloud_server"

    rescue_enabled: Optional[bool] = None
    locked: Optional[bool] = None
    backup_window: Optional[str] = None
    outgoing_traffic: Optional[int] = None
    ingoing_traffic: Optional[int] = None
    included_traffic: Optional[int] = None
    primary_disk_size: Optional[int] = None
    protection: Optional[dict[str, bool]] = None
    public_net: Optional[HcloudPublicNetwork] = None
    private_net: Optional[list[HcloudPrivateNetwork]] = None


@define(eq=False, slots=False)
class HcloudIso(HcloudResource):
    kind: ClassVar[str] = "hcloud_iso"

    description: Optional[str] = None
    type: Optional[str] = None
    architecture: Optional[str] = None
    deprecated_at: Optional[datetime] = None
    deprecation: Optional[HcloudDeprecationInfo] = None


@define(eq=False, slots=False)
class HcloudImage(HcloudResource):
    kind: ClassVar[str] = "hcloud_image"

    type: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    image_size: Optional[float] = None
    disk_size: Optional[float] = None
    created_at: Optional[datetime] = None
    created_from: Optional[HcloudServer] = None
    bound_to: Optional[HcloudServer] = None
    os_flavor: Optional[str] = None
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    rapid_deploy: Optional[bool] = None
    protection: Optional[dict[str, bool]] = None
    deprecated_at: Optional[datetime] = None
