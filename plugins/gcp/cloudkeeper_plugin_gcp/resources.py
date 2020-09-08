import cloudkeeper.logging
from cloudkeeper.graph import Graph
from cloudkeeper.args import ArgumentParser
from cloudkeeper.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseVolume, BaseVolumeType,
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

    def __init__(
        self, *args, lifecycle_status=None, project_number=None, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.lifecycle_status = lifecycle_status


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

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if isinstance(self.volume_type, BaseResource):
            self.volume_type = self.volume_type.name


class GCPInstance(GCPResource, BaseInstance):
    resource_type = "gcp_instance"
