from attrs import define, field
from typing import ClassVar, List, Optional, Dict
from datetime import datetime
from fixlib.graph import Graph
from fixlib.logger import log
from fixlib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseZone,
    BaseInstance,
    BaseNetwork,
    BaseResource,
    BaseVolume,
    InstanceStatus,
    VolumeStatus,
)


@define(eq=False, slots=False)
class HcloudResource(BaseResource):
    kind: ClassVar[str] = "hcloud_resource"
    kind_display: ClassVar[str] = "Hetzner Cloud Resource"
    kind_description: ClassVar[str] = "A Hetzner Cloud Resource represents a single resource in the Hetzner Cloud"

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
class HcloudPublicNet(HcloudResource):
    kind: ClassVar[str] = "hcloud_public_net"


@define(eq=False, slots=False)
class HcloudServerType(HcloudResource):
    kind: ClassVar[str] = "hcloud_server_type"


@define(eq=False, slots=False)
class HcloudImage(HcloudResource):
    kind: ClassVar[str] = "hcloud_image"


@define(eq=False, slots=False)
class HcloudIso(HcloudResource):
    kind: ClassVar[str] = "hcloud_iso"


@define(eq=False, slots=False)
class HcloudVolume(BaseVolume, HcloudResource):
    kind: ClassVar[str] = "hcloud_volume"

    linux_device: Optional[str] = None
    protection: Optional[dict[str, bool]] = None
    format: Optional[str] = None


@define(eq=False, slots=False)
class HcloudPrivateNet(BaseNetwork, HcloudResource):
    kind: ClassVar[str] = "hcloud_private_net"


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
