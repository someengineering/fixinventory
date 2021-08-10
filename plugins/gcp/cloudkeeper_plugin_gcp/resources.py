from typing import List, Dict, ClassVar, Optional
from datetime import datetime, timezone, timedelta
from cloudkeeper.graph import Graph
from cloudkeeper.utils import make_valid_timestamp
import cloudkeeper.logging
from cloudkeeper.baseresources import (
    BaseQuota,
    BaseAccount,
    BaseLoadBalancer,
    BaseRegion,
    VolumeStatus,
    BaseVolume,
    BaseVolumeType,
    BaseZone,
    BaseResource,
    InstanceStatus,
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
    BaseBucket,
    BaseDatabase,
)
from .utils import (
    gcp_service,
    paginate,
    update_label,
    delete_resource,
    gcp_resource,
    common_resource_kwargs,
)
from dataclasses import dataclass, field, InitVar


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)

# Resources that can exist within zones OR outside zones in regions only
regional_resources = (
    "gcp_autoscaler",
    "gcp_backend_service",
    "gcp_commitment",
    "gcp_disk_type",
    "gcp_disk",
    "gcp_health_check",
    "gcp_instance_group_manager",
    "gcp_instance_group",
    "gcp_network_endpoint_group",
    "gcp_notification_endpoint",
    "gcp_ssl_certificate",
    "gcp_target_http_proxy",
    "gcp_target_https_proxy",
    "gcp_url_map",
)


@dataclass(eq=False)
class GCPResource:
    api_identifier: ClassVar[str] = NotImplemented
    client: ClassVar[str] = "compute"
    api_version: ClassVar[str] = "v1"
    resource_args: ClassVar[List[str]] = ["project", "zone", "region"]

    link: Optional[str] = None
    label_fingerprint: Optional[str] = None

    def __post_init__(self) -> None:
        super().__post_init__()
        self._client_method = self.api_identifier + "s"
        self._get_identifier = self.api_identifier
        self._list_identifier = self.api_identifier
        self._update_identifier = self.api_identifier
        self._patch_identifier = self.api_identifier
        self._delete_identifier = self.api_identifier
        self._set_label_identifier = self.api_identifier
        self._check_region_resource()

    def _check_region_resource(self):
        """Checks if the resource is a regional or a zonal one.

        If the resource has no zone but a region assigned and is part of
        the list of `regional_resources` above we will update the
        client method name as regional resources have their own API
        methods.
        """
        if (
            self.id != ""
            and self.zone().name == "undefined"
            and self.region().name != "undefined"
            and self.resource_type in regional_resources
        ):
            self._client_method = (
                "region" + self._client_method[0].upper() + self._client_method[1:]
            )

    def delete(self, graph) -> bool:
        return delete_resource(self)

    def update_tag(self, key, value) -> bool:
        return update_label(self, key, value)

    def delete_tag(self, key) -> bool:
        return update_label(self, key, None)


@dataclass(eq=False)
class GCPProject(GCPResource, BaseAccount):
    resource_type: ClassVar[str] = "gcp_project"
    api_identifier: ClassVar[str] = "project"


@dataclass(eq=False)
class GCPZone(GCPResource, BaseZone):
    resource_type: ClassVar[str] = "gcp_zone"
    api_identifier: ClassVar[str] = "zone"
    zone_status: Optional[str] = None


@dataclass(eq=False)
class GCPRegion(GCPResource, BaseRegion):
    resource_type: ClassVar[str] = "gcp_region"
    api_identifier: ClassVar[str] = "region"
    region_status: Optional[str] = None
    quotas: InitVar[List[str]] = None

    def __post_init__(self, quotas: List[str]) -> None:
        super().__post_init__()
        if quotas is not None:
            self._quotas = quotas
        else:
            self._quotas = []


@dataclass(eq=False)
class GCPDiskType(GCPResource, BaseVolumeType):
    resource_type: ClassVar[str] = "gcp_disk_type"
    api_identifier: ClassVar[str] = "diskType"


@dataclass(eq=False)
class GCPDisk(GCPResource, BaseVolume):
    resource_type: ClassVar[str] = "gcp_disk"
    api_identifier: ClassVar[str] = "disk"

    volume_status_map: ClassVar[Dict[str, VolumeStatus]] = {
        "CREATING": VolumeStatus.BUSY,
        "RESTORING": VolumeStatus.BUSY,
        "FAILED": VolumeStatus.ERROR,
        "READY": VolumeStatus.IN_USE,
        "AVAILABLE": VolumeStatus.AVAILABLE,
        "DELETING": VolumeStatus.BUSY,
    }

    last_attach_timestamp: Optional[datetime] = None
    last_detach_timestamp: Optional[datetime] = None

    def __post_init__(self) -> None:
        super().__post_init__()
        self._set_label_identifier = "resource"
        self.last_attach_timestamp = make_valid_timestamp(self.last_attach_timestamp)
        self.last_detach_timestamp = make_valid_timestamp(self.last_detach_timestamp)

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

    def _volume_status_setter(self, value: str) -> None:
        self._volume_status = self.volume_status_map.get(value, VolumeStatus.UNKNOWN)


GCPDisk.volume_status = property(
    GCPDisk._volume_status_getter, GCPDisk._volume_status_setter
)


@dataclass(eq=False)
class GCPInstance(GCPResource, BaseInstance):
    resource_type: ClassVar[str] = "gcp_instance"
    api_identifier: ClassVar[str] = "instance"

    instance_status_map: ClassVar[Dict[str, InstanceStatus]] = {
        "PROVISIONING": InstanceStatus.BUSY,
        "STAGING": InstanceStatus.BUSY,
        "RUNNING": InstanceStatus.RUNNING,
        "STOPPING": InstanceStatus.BUSY,
        "SUSPENDING": InstanceStatus.BUSY,
        "SUSPENDED": InstanceStatus.STOPPED,
        "REPAIRING": InstanceStatus.BUSY,
        "TERMINATED": InstanceStatus.TERMINATED,
    }

    network_interfaces: Optional[str] = None
    machine_type_link: InitVar[str] = None
    machine_type: InitVar[BaseInstanceType] = None

    def __post_init__(
        self, machine_type_link: str, machine_type: BaseInstanceType
    ) -> None:
        super().__post_init__()
        self._machine_type_link = machine_type_link
        self._machine_type = machine_type

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )

    @property
    def _machine_type(self) -> Optional[BaseInstanceType]:
        if hasattr(self, "__machine_type"):
            return self.__machine_type

    @_machine_type.setter
    def _machine_type(self, value: BaseInstanceType) -> None:
        if isinstance(value, BaseInstanceType):
            self.__machine_type = value
            self.instance_cores = value.instance_cores
            self.instance_memory = value.instance_memory
            self.instance_type = value.name


GCPInstance.instance_status = property(
    GCPInstance._instance_status_getter, GCPInstance._instance_status_setter
)


@dataclass(eq=False)
class GCPNetwork(GCPResource, BaseNetwork):
    resource_type: ClassVar[str] = "gcp_network"
    api_identifier: ClassVar[str] = "network"


@dataclass(eq=False)
class GCPSubnetwork(GCPResource, BaseSubnet):
    resource_type: ClassVar[str] = "gcp_subnetwork"
    api_identifier: ClassVar[str] = "subnetwork"


@dataclass(eq=False)
class GCPVPNTunnel(GCPResource, BaseTunnel):
    resource_type: ClassVar[str] = "gcp_vpn_tunnel"
    api_identifier: ClassVar[str] = "vpnTunnel"


@dataclass(eq=False)
class GCPVPNGateway(GCPResource, BaseGateway):
    resource_type: ClassVar[str] = "gcp_vpn_gateway"
    api_identifier: ClassVar[str] = "vpnGateway"


@dataclass(eq=False)
class GCPTargetVPNGateway(GCPResource, BaseGateway):
    resource_type: ClassVar[str] = "gcp_target_vpn_gateway"
    api_identifier: ClassVar[str] = "targetVpnGateway"


@dataclass(eq=False)
class GCPRouter(GCPResource, BaseGateway):
    resource_type: ClassVar[str] = "gcp_router"
    api_identifier: ClassVar[str] = "router"


@dataclass(eq=False)
class GCPRoute(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_route"
    api_identifier: ClassVar[str] = "route"


@dataclass(eq=False)
class GCPInstanceTemplate(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_instance_template"
    api_identifier: ClassVar[str] = "instanceTemplate"


@dataclass(eq=False)
class GCPSecurityPolicy(GCPResource, BasePolicy):
    resource_type: ClassVar[str] = "gcp_security_policy"
    api_identifier: ClassVar[str] = "securityPolicy"

    def __post_init__(self) -> None:
        super().__post_init__()
        self._client_method = "securityPolicies"


@dataclass(eq=False)
class GCPSnapshot(GCPResource, BaseSnapshot):
    resource_type: ClassVar[str] = "gcp_snapshot"
    api_identifier: ClassVar[str] = "snapshot"

    storage_bytes: int = 0

    def __post_init__(self) -> None:
        super().__post_init__()
        if isinstance(self.volume_id, BaseResource):
            self.volume_id = self.volume_id.name


@dataclass(eq=False)
class GCPSSLCertificate(GCPResource, BaseCertificate):
    resource_type: ClassVar[str] = "gcp_ssl_certificate"
    api_identifier: ClassVar[str] = "sslCertificate"


@dataclass(eq=False)
class GCPMachineType(GCPResource, BaseInstanceType):
    resource_type: ClassVar[str] = "gcp_machine_type"
    api_identifier: ClassVar[str] = "machineType"

    def __post_init__(self) -> None:
        super().__post_init__()
        self.instance_type = self.name


@dataclass(eq=False)
class GCPNetworkEndpointGroup(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_network_endpoint_group"
    api_identifier: ClassVar[str] = "networkEndpointGroup"

    default_port: int = -1
    neg_type: str = ""


@dataclass(eq=False)
class GCPGlobalNetworkEndpointGroup(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_global_network_endpoint_group"
    api_identifier: ClassVar[str] = "globalNetworkEndpointGroup"

    default_port: int = -1
    neg_type: str = ""


@dataclass(eq=False)
class GCPInstanceGroup(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_instance_group"
    api_identifier: ClassVar[str] = "instanceGroup"


@dataclass(eq=False)
class GCPInstanceGroupManager(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_instance_group_manager"
    api_identifier: ClassVar[str] = "instanceGroupManager"


@dataclass(eq=False)
class GCPAutoscaler(GCPResource, BaseAutoScalingGroup):
    resource_type: ClassVar[str] = "gcp_autoscaler"
    api_identifier: ClassVar[str] = "autoscaler"


@dataclass(eq=False)
class GCPHealthCheck(GCPResource, BaseHealthCheck):
    resource_type: ClassVar[str] = "gcp_health_check"
    api_identifier: ClassVar[str] = "healthCheck"


@dataclass(eq=False)
class GCPHTTPHealthCheck(GCPResource, BaseHealthCheck):
    resource_type: ClassVar[str] = "gcp_http_health_check"
    api_identifier: ClassVar[str] = "httpHealthCheck"

    host: str = ""
    request_path: str = ""
    port: int = -1


@dataclass(eq=False)
class GCPHTTPSHealthCheck(GCPHTTPHealthCheck):
    resource_type: ClassVar[str] = "gcp_https_health_check"
    api_identifier: ClassVar[str] = "httpsHealthCheck"


@dataclass(eq=False)
class GCPUrlMap(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_url_map"
    api_identifier: ClassVar[str] = "urlMap"


@dataclass(eq=False)
class GCPTargetPool(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_target_pool"
    api_identifier: ClassVar[str] = "targetPool"

    session_affinity: str = ""
    failover_ratio: float = -1.0


@dataclass(eq=False)
class GCPTargetHttpProxy(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_target_http_proxy"
    api_identifier: ClassVar[str] = "targetHttpProxy"

    def __post_init__(self) -> None:
        super().__post_init__()
        self._client_method = "targetHttpProxies"
        self._check_region_resource()


@dataclass(eq=False)
class GCPTargetHttpsProxy(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_target_https_proxy"
    api_identifier: ClassVar[str] = "targetHttpsProxy"

    def __post_init__(self) -> None:
        super().__post_init__()
        self._client_method = "targetHttpsProxies"
        self._check_region_resource()


@dataclass(eq=False)
class GCPTargetSslProxy(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_target_ssl_proxy"
    api_identifier: ClassVar[str] = "targetSslProxy"

    def __post_init__(self) -> None:
        super().__post_init__()
        self._client_method = "targetSslProxies"


@dataclass(eq=False)
class GCPTargetTcpProxy(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_target_tcp_proxy"
    api_identifier: ClassVar[str] = "targetTcpProxy"

    def __post_init__(self) -> None:
        super().__post_init__()
        self._client_method = "targetTcpProxies"


@dataclass(eq=False)
class GCPTargetGrpcProxy(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_target_grpc_proxy"
    api_identifier: ClassVar[str] = "targetGrpcProxy"

    def __post_init__(self) -> None:
        super().__post_init__()
        self._client_method = "targetGrpcProxies"


@dataclass(eq=False)
class GCPTargetInstance(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_target_instance"
    api_identifier: ClassVar[str] = "targetInstance"


@dataclass(eq=False)
class GCPQuota(GCPResource, BaseQuota):
    resource_type: ClassVar[str] = "gcp_quota"
    api_identifier: ClassVar[str] = "dummy"


@dataclass(eq=False)
class GCPBackendService(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_backend_service"
    api_identifier: ClassVar[str] = "backendService"


@dataclass(eq=False)
class GCPForwardingRule(GCPResource, BaseLoadBalancer):
    resource_type: ClassVar[str] = "gcp_forwarding_rule"
    api_identifier: ClassVar[str] = "forwardingRule"

    ip_address: str = ""
    ip_protocol: str = ""
    load_balancing_scheme: str = ""
    network_tier: str = ""
    port_range: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        self.lb_type = "gcp"


@dataclass(eq=False)
class GCPGlobalForwardingRule(GCPForwardingRule):
    resource_type: ClassVar[str] = "gcp_global_forwarding_rule"
    api_identifier: ClassVar[str] = "globalForwardingRule"


@dataclass(eq=False)
class GCPBucket(GCPResource, BaseBucket):
    resource_type: ClassVar[str] = "gcp_bucket"
    api_identifier: ClassVar[str] = "bucket"
    client = "storage"

    bucket_location: str = ""
    bucket_location_type: str = ""
    storage_class: str = ""
    zone_separation: bool = False

    def pre_delete(self, graph: Graph) -> bool:
        kwargs = {str(self._list_identifier): self.name}
        gs = gcp_service(self, graph=graph)
        for document in paginate(
            gcp_resource=gs.objects(),
            method_name="list",
            items_name="items",
            **kwargs,
        ):
            log.debug(
                f"Removing {document['name']} in {self.rtdname} before resource cleanup"
            )
            request = gs.objects().delete(object=document["name"], **kwargs)
            request.execute()
        return True

    def delete(self, graph: Graph) -> bool:
        kwargs = {str(self._delete_identifier): self.name}
        gr = gcp_resource(self, graph=graph)
        request = gr.delete(**kwargs)
        request.execute()
        return True

    def update_tag(self, key, value) -> bool:
        kwargs = {str(self._patch_identifier): self.name}
        gr = gcp_resource(self)
        labels = dict(self.tags)
        labels[key] = value
        kwargs["body"] = {"labels": labels}
        request = gr.patch(**kwargs)
        request.execute()
        return True

    def delete_tag(self, key) -> bool:
        return self.update_tag(key, None)


@dataclass(eq=False)
class GCPDatabase(GCPResource, BaseDatabase):
    resource_type: ClassVar[str] = "gcp_database"
    api_identifier: ClassVar[str] = "instance"
    client: ClassVar[str] = "sqladmin"
    api_version: ClassVar[str] = "v1beta4"
    resource_args: ClassVar[List[str]] = ["project"]

    def update_tag(self, key, value) -> bool:
        kwargs = {str(self._patch_identifier): self.name}
        common_kwargs = common_resource_kwargs(self)
        kwargs.update(common_kwargs)
        gr = gcp_resource(self)
        labels = dict(self.tags)
        labels[key] = value
        kwargs["body"] = {"settings": {"userLabels": labels}}
        request = gr.patch(**kwargs)
        request.execute()
        return True

    def delete_tag(self, key) -> bool:
        return self.update_tag(key, None)


@dataclass(eq=False)
class GCPService(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_service"
    api_identifier: ClassVar[str] = "service"
    client: ClassVar[str] = "cloudbilling"
    api_version: ClassVar[str] = "v1"
    resource_args: ClassVar[List[str]] = []


@dataclass(eq=False)
class GCPServiceSKU(GCPResource, BaseResource):
    resource_type: ClassVar[str] = "gcp_service_sku"
    api_identifier: ClassVar[str] = "service"
    client: ClassVar[str] = "cloudbilling"
    api_version: ClassVar[str] = "v1"
    resource_args: ClassVar[List[str]] = []

    service: str = ""
    resource_family: Optional[str] = ""
    resource_group: Optional[str] = ""
    usage_type: Optional[str] = ""
    pricing_info: List = field(default_factory=list)
    service_provider_name: Optional[str] = ""
    geo_taxonomy_type: Optional[str] = None
    geo_taxonomy_regions: List = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.pricing_info is None:
            self.pricing_info = []
        if self.geo_taxonomy_regions is None:
            self.geo_taxonomy_regions = []
        self.usage_unit_nanos = -1
        if len(self.pricing_info) > 0:
            tiered_rates = (
                self.pricing_info[0].get("pricingExpression", {}).get("tieredRates", [])
            )
            cost = -1
            if len(tiered_rates) == 1:
                cost = tiered_rates[0].get("unitPrice", {}).get("nanos", -1)
            else:
                for tiered_rate in tiered_rates:
                    if tiered_rate.get("startUsageAmount", -1) > 0:
                        cost = tiered_rate.get("unitPrice", {}).get("nanos", -1)
                        break
            if cost > -1:
                self.usage_unit_nanos = cost
