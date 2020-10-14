from typing import List
from datetime import datetime, timezone, timedelta
from cloudkeeper.graph import Graph
from cloudkeeper.utils import make_valid_timestamp
import cloudkeeper.logging
from cloudkeeper.baseresources import (
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


class GCPResource:
    api_identifier = NotImplemented
    client = "compute"
    api_version = "v1"
    resource_args = ["project", "zone", "region"]

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

    instance_status_map = {
        "PROVISIONING": InstanceStatus.BUSY,
        "STAGING": InstanceStatus.BUSY,
        "RUNNING": InstanceStatus.RUNNING,
        "STOPPING": InstanceStatus.BUSY,
        "SUSPENDING": InstanceStatus.BUSY,
        "SUSPENDED": InstanceStatus.STOPPED,
        "REPAIRING": InstanceStatus.BUSY,
        "TERMINATED": InstanceStatus.TERMINATED,
    }

    @BaseInstance.instance_status.setter
    def instance_status(self, value: str) -> None:
        self._instance_status = self.instance_status_map.get(
            value, InstanceStatus.UNKNOWN
        )

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


class GCPGlobalNetworkEndpointGroup(GCPResource, BaseResource):
    resource_type = "gcp_global_network_endpoint_group"
    api_identifier = "globalNetworkEndpointGroup"

    def __init__(
        self, *args, default_port: int = -1, neg_type: str = "", **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.default_port = int(default_port)
        self.neg_type = neg_type


class GCPInstanceGroup(GCPResource, BaseResource):
    resource_type = "gcp_instance_group"
    api_identifier = "instanceGroup"


class GCPInstanceGroupManager(GCPResource, BaseResource):
    resource_type = "gcp_instance_group_manager"
    api_identifier = "instanceGroupManager"


class GCPAutoscaler(GCPResource, BaseAutoScalingGroup):
    resource_type = "gcp_autoscaler"
    api_identifier = "autoscaler"


class GCPHealthCheck(GCPResource, BaseHealthCheck):
    resource_type = "gcp_health_check"
    api_identifier = "healthCheck"


class GCPHTTPHealthCheck(GCPResource, BaseHealthCheck):
    resource_type = "gcp_http_health_check"
    api_identifier = "httpHealthCheck"

    def __init__(
        self, *args, host: str = "", request_path: str = "", port: int = -1, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.host = host
        self.request_path = request_path
        self.port = int(port)


class GCPHTTPSHealthCheck(GCPHTTPHealthCheck):
    resource_type = "gcp_https_health_check"
    api_identifier = "httpsHealthCheck"


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
        self.failover_ratio = float(failover_ratio)


class GCPTargetHttpProxy(GCPResource, BaseResource):
    resource_type = "gcp_target_http_proxy"
    api_identifier = "targetHttpProxy"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._client_method = "targetHttpProxies"
        self._check_region_resource()


class GCPTargetHttpsProxy(GCPResource, BaseResource):
    resource_type = "gcp_target_https_proxy"
    api_identifier = "targetHttpsProxy"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._client_method = "targetHttpsProxies"
        self._check_region_resource()


class GCPTargetSslProxy(GCPResource, BaseResource):
    resource_type = "gcp_target_ssl_proxy"
    api_identifier = "targetSslProxy"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._client_method = "targetSslProxies"


class GCPTargetTcpProxy(GCPResource, BaseResource):
    resource_type = "gcp_target_tcp_proxy"
    api_identifier = "targetTcpProxy"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._client_method = "targetTcpProxies"


class GCPTargetGrpcProxy(GCPResource, BaseResource):
    resource_type = "gcp_target_grpc_proxy"
    api_identifier = "targetGrpcProxy"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._client_method = "targetGrpcProxies"


class GCPTargetInstance(GCPResource, BaseResource):
    resource_type = "gcp_target_instance"
    api_identifier = "targetInstance"


class GCPBackendService(GCPResource, BaseResource):
    resource_type = "gcp_backend_service"
    api_identifier = "backendService"


class GCPForwardingRule(GCPResource, BaseLoadBalancer):
    resource_type = "gcp_forwarding_rule"
    api_identifier = "forwardingRule"

    def __init__(
        self,
        *args,
        ip_address: str = "",
        ip_protocol: str = "",
        load_balancing_scheme: str = "",
        network_tier: str = "",
        port_range: str = "",
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.ip_address = ip_address
        self.ip_protocol = ip_protocol
        self.load_balancing_scheme = load_balancing_scheme
        self.network_tier = network_tier
        self.port_range = port_range
        self.lb_type = "gcp"


class GCPGlobalForwardingRule(GCPForwardingRule):
    resource_type = "gcp_global_forwarding_rule"
    api_identifier = "globalForwardingRule"


class GCPBucket(GCPResource, BaseBucket):
    resource_type = "gcp_bucket"
    api_identifier = "bucket"
    client = "storage"

    def __init__(
        self,
        *args,
        location: str = "",
        location_type: str = "",
        storage_class: str = "",
        zone_separation: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.location = location
        self.location_type = location_type
        self.storage_class = storage_class
        self.zone_separation = zone_separation

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


class GCPDatabase(GCPResource, BaseDatabase):
    resource_type = "gcp_database"
    api_identifier = "instance"
    client = "sqladmin"
    api_version = "v1beta4"
    resource_args = ["project"]

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


class GCPService(GCPResource, BaseResource):
    resource_type = "gcp_service"
    api_identifier = "service"
    client = "cloudbilling"
    api_version = "v1"
    resource_args = []


class GCPServiceSKU(GCPResource, BaseResource):
    resource_type = "gcp_service_sku"
    api_identifier = "service"
    client = "cloudbilling"
    api_version = "v1"
    resource_args = []

    def __init__(
        self,
        *args,
        service: str = "",
        resource_family: str = "",
        resource_group: str = "",
        usage_type: str = "",
        pricing_info: List = None,
        service_provider_name: str = "",
        geo_taxonomy_type: str = "",
        geo_taxonomy_regions: List = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        if pricing_info is None:
            pricing_info = []
        if geo_taxonomy_regions is None:
            geo_taxonomy_regions = []
        self.pricing_info = pricing_info
        self.service_provider_name = service_provider_name
        self.service = service
        self.resource_family = resource_family
        self.resource_group = resource_group
        self.usage_type = usage_type
        self.geo_taxonomy_type = geo_taxonomy_type
        self.geo_taxonomy_regions = geo_taxonomy_regions
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
