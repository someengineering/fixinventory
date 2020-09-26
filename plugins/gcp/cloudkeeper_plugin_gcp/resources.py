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
    BaseInstanceType,
    BaseNetwork,
    BaseSubnet,
    BaseTunnel,
    BaseGateway,
    BasePolicy,
    BaseSnapshot,
    BaseCertificate,
    BaseAutoScalingGroup,
    BaseHealthCheck,
)
from .utils import update_label, delete_resource


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class GCPResource:
    api_identifier = NotImplemented

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
        self._client_method = self.api_identifier + "s"
        self._get_identifier = self.api_identifier
        self._delete_identifier = self.api_identifier
        self._set_label_identifier = self.api_identifier

    def delete(self, graph) -> bool:
        return delete_resource(self)

    def update_tag(self, key, value) -> bool:
        return update_label(self, key, value)

    def delete_tag(self, key) -> bool:
        return update_label(self, key, None)


class GCPProject(GCPResource, BaseAccount):
    resource_type = "gcp_project"
    api_identifier = "project"


class GCPZone(GCPResource, BaseZone):
    resource_type = "gcp_zone"
    api_identifier = "zone"

    def __init__(self, *args, zone_status=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.zone_status = zone_status


class GCPRegion(GCPResource, BaseRegion):
    resource_type = "gcp_region"
    api_identifier = "region"

    def __init__(self, *args, region_status=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.region_status = region_status


class GCPDiskType(GCPResource, BaseVolumeType):
    resource_type = "gcp_disk_type"
    api_identifier = "diskType"


class GCPDisk(GCPResource, BaseVolume):
    resource_type = "gcp_disk"
    api_identifier = "disk"

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
        self._set_label_identifier = "resource"
        self.last_attach_timestamp = make_valid_timestamp(last_attach_timestamp)
        self.last_detach_timestamp = make_valid_timestamp(last_detach_timestamp)

        #        last_activity = (
        #            self.last_detach_timestamp
        #            if self.last_detach_timestamp > self.last_attach_timestamp
        #            else self.last_attach_timestamp
        #        )
        #        if self.volume_status == "available":
        #            self.atime = self.mtime = last_activity

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
    api_identifier = "instance"

    def __init__(self, *args, network_interfaces=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.network_interfaces = network_interfaces
        if isinstance(self.instance_type, GCPMachineType):
            self.instance_cores = self.instance_type.instance_cores
            self.instance_memory = self.instance_type.instance_memory
            self.instance_type = self.instance_type.name


class GCPNetwork(GCPResource, BaseNetwork):
    resource_type = "gcp_network"
    api_identifier = "network"


class GCPSubnetwork(GCPResource, BaseSubnet):
    resource_type = "gcp_subnetwork"
    api_identifier = "subnetwork"


class GCPVPNTunnel(GCPResource, BaseTunnel):
    resource_type = "gcp_vpn_tunnel"
    api_identifier = "vpnTunnel"


class GCPVPNGateway(GCPResource, BaseGateway):
    resource_type = "gcp_vpn_gateway"
    api_identifier = "vpnGateway"


class GCPTargetVPNGateway(GCPResource, BaseGateway):
    resource_type = "gcp_target_vpn_gateway"
    api_identifier = "targetVpnGateway"


class GCPRouter(GCPResource, BaseGateway):
    resource_type = "gcp_router"
    api_identifier = "router"


class GCPRoute(GCPResource, BaseResource):
    resource_type = "gcp_route"
    api_identifier = "route"


class GCPSecurityPolicy(GCPResource, BasePolicy):
    resource_type = "gcp_security_policy"
    api_identifier = "securityPolicy"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._client_method = "securityPolicies"


class GCPSnapshot(GCPResource, BaseSnapshot):
    resource_type = "gcp_snapshot"
    api_identifier = "snapshot"

    def __init__(self, *args, storage_bytes: int = 0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.storage_bytes = int(storage_bytes)
        if isinstance(self.volume_id, BaseResource):
            self.volume_id = self.volume_id.name


class GCPSSLCertificate(GCPResource, BaseCertificate):
    resource_type = "gcp_ssl_certificate"
    api_identifier = "sslCertificate"


class GCPMachineType(GCPResource, BaseInstanceType):
    resource_type = "gcp_machine_type"
    api_identifier = "machineType"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.instance_type = self.name


class GCPNetworkEndpointGroup(GCPResource, BaseResource):
    resource_type = "gcp_network_endpoint_group"
    api_identifier = "networkEndpointGroup"

    def __init__(
        self, *args, default_port: int = -1, neg_type: str = "", **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.default_port = int(default_port)
        self.neg_type = neg_type


class GCPInstanceGroup(GCPResource, BaseResource):
    resource_type = "gcp_instance_group"
    api_identifier = "instanceGroup"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class GCPInstanceGroupManager(GCPResource, BaseResource):
    resource_type = "gcp_instance_group_manager"
    api_identifier = "instanceGroupManager"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class GCPAutoscaler(GCPResource, BaseAutoScalingGroup):
    resource_type = "gcp_autoscaler"
    api_identifier = "autoscaler"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class GCPHealthCheck(GCPResource, BaseHealthCheck):
    resource_type = "gcp_health_check"
    api_identifier = "healthCheck"


class GCPUrlMap(GCPResource, BaseResource):
    resource_type = "gcp_url_map"
    api_identifier = "urlMap"


class GCPTargetPool(GCPResource, BaseResource):
    resource_type = "gcp_target_pool"
    api_identifier = "targetPool"

    def __init__(
        self, *args, session_affinity: str = "", failover_ratio: float = -1.0, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.session_affinity = session_affinity
        failover_ratio = float(failover_ratio)
