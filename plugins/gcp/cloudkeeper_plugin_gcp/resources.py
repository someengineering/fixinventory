from datetime import datetime, timezone, timedelta
from cloudkeeper.utils import make_valid_timestamp
import cloudkeeper.logging
from cloudkeeper.baseresources import (
    BaseAccount,
    BaseRegion,
    VolumeStatus,
    BaseVolume,
    BaseVolumeType,
    BaseZone,
    BaseResource,
    BaseInstance,
    BaseNetwork,
)

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class GCPResource:
    def __init__(
        self,
        *args,
        link: str = None,
        gcpid: str = None,
        label_fingerprint: str = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.link = link
        self.gcpid = gcpid
        self.label_fingerprint = label_fingerprint

    def delete(self, graph) -> bool:
        return False


class GCPProject(GCPResource, BaseAccount):
    resource_type = "gcp_project"


class GCPZone(GCPResource, BaseZone):
    resource_type = "gcp_zone"

    def __init__(self, *args, zone_status=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.zone_status = zone_status


class GCPRegion(GCPResource, BaseRegion):
    resource_type = "gcp_region"

    def __init__(self, *args, region_status=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.region_status = region_status


class GCPDiskType(GCPResource, BaseVolumeType):
    resource_type = "gcp_disk_type"


class GCPDisk(GCPResource, BaseVolume):
    resource_type = "gcp_disk"

    volume_status_map = {
        "CREATING": VolumeStatus.BUSY,
        "RESTORING": VolumeStatus.BUSY,
        "FAILED": VolumeStatus.ERROR,
        "READY": VolumeStatus.IN_USE,
        "AVAILABLE": VolumeStatus.AVAILABLE,
        "DELETING": VolumeStatus.BUSY,
    }

    def __init__(
        self,
        *args,
        last_attach_timestamp: datetime = None,
        last_detach_timestamp: datetime = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.last_attach_timestamp = make_valid_timestamp(last_attach_timestamp)
        self.last_detach_timestamp = make_valid_timestamp(last_detach_timestamp)

        last_activity = (
            self.last_detach_timestamp
            if self.last_detach_timestamp > self.last_attach_timestamp
            else self.last_attach_timestamp
        )
        if self.volume_status == "available":
            #self.atime = self.mtime = last_activity
            pass

        if isinstance(self.volume_type, BaseResource):
            self.volume_type = self.volume_type.name

    @property
    def last_attach(self) -> timedelta:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        return now - self.last_attach_timestamp

    @property
    def last_detach(self) -> timedelta:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        return now - self.last_detach_timestamp

    @BaseVolume.volume_status.setter
    def volume_status(self, value: str) -> None:
        self._volume_status = self.volume_status_map.get(value, VolumeStatus.UNKNOWN)


class GCPInstance(GCPResource, BaseInstance):
    resource_type = "gcp_instance"

    def __init__(self, *args, network_interfaces=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.network_interfaces = network_interfaces


class GCPNetwork(GCPResource, BaseNetwork):
    resource_type = "gcp_network"
