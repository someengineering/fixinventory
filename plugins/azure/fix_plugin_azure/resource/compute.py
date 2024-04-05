from datetime import datetime
import logging
from typing import ClassVar, Dict, Optional, List, Any, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureApiSpec
from fix_plugin_azure.resource.base import (
    AzureResource,
    AzureResourceType,
    GraphBuilder,
    AzureSubResource,
    AzureSystemData,
    AzureSku,
    AzureExtendedLocation,
    AzurePrincipalidClientid,
    AzurePrivateLinkServiceConnectionState,
)
from fix_plugin_azure.resource.metrics import AzureMetricData, AzureMetricQuery, update_resource_metrics
from fix_plugin_azure.resource.network import (
    AzureNetworkSecurityGroup,
    AzureSubnet,
    AzureNetworkInterface,
    AzureLoadBalancer,
)
from fix_plugin_azure.utils import MetricNormalization, rgetvalue
from fixlib.json_bender import Bender, S, Bend, MapEnum, MapValue, ForallBend, K, F
from fixlib.types import Json
from fixlib.baseresources import (
    BaseInstance,
    BaseVolume,
    BaseInstanceType,
    BaseSnapshot,
    BaseVolumeType,
    MetricName,
    MetricUnit,
    VolumeStatus,
    BaseAutoScalingGroup,
    InstanceStatus,
    ModelReference,
    EdgeType,
)

log = logging.getLogger("fix.plugins.azure")


@define(eq=False, slots=False)
class AzureInstanceViewStatus:
    kind: ClassVar[str] = "azure_instance_view_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "display_status": S("displayStatus"),
        "level": S("level"),
        "message": S("message"),
        "time": S("time"),
    }
    code: Optional[str] = field(default=None, metadata={"description": "The status code."})
    display_status: Optional[str] = field(default=None, metadata={'description': 'The short localizable label for the status.'})  # fmt: skip
    level: Optional[str] = field(default=None, metadata={"description": "The level code."})
    message: Optional[str] = field(default=None, metadata={'description': 'The detailed status message, including for alerts and error messages.'})  # fmt: skip
    time: Optional[datetime] = field(default=None, metadata={"description": "The time of the status."})


@define(eq=False, slots=False)
class AzureAvailabilitySet(AzureResource):
    kind: ClassVar[str] = "azure_availability_set"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/availabilitySets",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_proximity_placement_group", "azure_virtual_machine_base"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "platform_fault_domain_count": S("properties", "platformFaultDomainCount"),
        "platform_update_domain_count": S("properties", "platformUpdateDomainCount"),
        "proximity_placement_group": S("properties", "proximityPlacementGroup", "id"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "statuses": S("properties", "statuses") >> ForallBend(AzureInstanceViewStatus.mapping),
        "virtual_machines_availability": S("properties") >> S("virtualMachines", default=[]) >> ForallBend(S("id")),
    }
    platform_fault_domain_count: Optional[int] = field(default=None, metadata={"description": "Fault domain count."})
    platform_update_domain_count: Optional[int] = field(default=None, metadata={"description": "Update domain count."})
    proximity_placement_group: Optional[str] = field(default=None, metadata={"description": ""})
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Describes a virtual machine scale set sku. Note: if the new vm sku is not supported on the hardware the scale set is currently on, you need to deallocate the vms in the scale set before you modify the sku name.'})  # fmt: skip
    statuses: Optional[List[AzureInstanceViewStatus]] = field(default=None, metadata={'description': 'The resource status information.'})  # fmt: skip
    virtual_machines_availability: Optional[List[str]] = field(default=None, metadata={'description': 'A list of references to all virtual machines in the availability set.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if placement_group_id := self.proximity_placement_group:
            builder.add_edge(
                self, edge_type=EdgeType.default, clazz=AzureProximityPlacementGroup, id=placement_group_id
            )
        if virtual_machines := self.virtual_machines_availability:
            for vm_id in virtual_machines:
                builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureVirtualMachineBase, id=vm_id)


@define(eq=False, slots=False)
class AzureCapacityReservationGroupInstanceView:
    kind: ClassVar[str] = "azure_capacity_reservation_group_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_reservations": S("capacityReservations", default=[]) >> ForallBend(S("name"))
    }
    capacity_reservations: Optional[List[str]] = field(default=None, metadata={'description': 'List of instance view of the capacity reservations under the capacity reservation group.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCapacityReservationGroup(AzureResource):
    kind: ClassVar[str] = "azure_capacity_reservation_group"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/capacityReservationGroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_virtual_machine_base"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "capacity_reservations": S("properties") >> S("capacityReservations", default=[]) >> ForallBend(S("id")),
        "reservation_group_instance_view": S("properties", "instanceView")
        >> Bend(AzureCapacityReservationGroupInstanceView.mapping),
        "virtual_machines_associated": S("properties")
        >> S("virtualMachinesAssociated", default=[])
        >> ForallBend(S("id")),
    }
    capacity_reservations: Optional[List[str]] = field(default=None, metadata={'description': 'A list of all capacity reservation resource ids that belong to capacity reservation group.'})  # fmt: skip
    reservation_group_instance_view: Optional[AzureCapacityReservationGroupInstanceView] = field(default=None, metadata={'description': ''})  # fmt: skip
    virtual_machines_associated: Optional[List[str]] = field(default=None, metadata={'description': 'A list of references to all virtual machines associated to the capacity reservation group.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if virtual_machines := self.virtual_machines_associated:
            for vm_id in virtual_machines:
                builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureVirtualMachineBase, id=vm_id)


@define(eq=False, slots=False)
class AzureCloudServiceRoleSku:
    kind: ClassVar[str] = "azure_cloud_service_role_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"capacity": S("capacity"), "name": S("name"), "tier": S("tier")}
    capacity: Optional[int] = field(default=None, metadata={'description': 'Specifies the number of role instances in the cloud service.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The sku name. Note: if the new sku is not supported on the hardware the cloud service is currently on, you need to delete and recreate the cloud service or move back to the old sku.'})  # fmt: skip
    tier: Optional[str] = field(default=None, metadata={'description': 'Specifies the tier of the cloud service. Possible values are **standard** **basic**.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCloudServiceRoleProfileProperties:
    kind: ClassVar[str] = "azure_cloud_service_role_profile_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "sku": S("sku") >> Bend(AzureCloudServiceRoleSku.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})
    sku: Optional[AzureCloudServiceRoleSku] = field(default=None, metadata={'description': 'Describes the cloud service role sku.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCloudServiceRoleProfile:
    kind: ClassVar[str] = "azure_cloud_service_role_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "roles": S("roles") >> ForallBend(AzureCloudServiceRoleProfileProperties.mapping)
    }
    roles: Optional[List[AzureCloudServiceRoleProfileProperties]] = field(default=None, metadata={'description': 'List of roles for the cloud service.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCloudServiceVaultSecretGroup:
    kind: ClassVar[str] = "azure_cloud_service_vault_secret_group"
    mapping: ClassVar[Dict[str, Bender]] = {
        "source_vault": S("sourceVault", "id"),
        "vault_certificates": S("vaultCertificates", default=[]) >> ForallBend(S("certificateUrl")),
    }
    source_vault: Optional[str] = field(default=None, metadata={"description": ""})
    vault_certificates: Optional[List[str]] = field(default=None, metadata={'description': 'The list of key vault references in sourcevault which contain certificates.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCloudServiceOsProfile:
    kind: ClassVar[str] = "azure_cloud_service_os_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "secrets": S("secrets") >> ForallBend(AzureCloudServiceVaultSecretGroup.mapping)
    }
    secrets: Optional[List[AzureCloudServiceVaultSecretGroup]] = field(default=None, metadata={'description': 'Specifies set of certificates that should be installed onto the role instances.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLoadBalancerFrontendIpConfiguration:
    kind: ClassVar[str] = "azure_load_balancer_frontend_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "private_ip_address": S("properties", "privateIPAddress"),
        "public_ip_address": S("properties", "publicIPAddress", "id"),
        "subnet": S("properties", "subnet", "id"),
    }
    name: Optional[str] = field(default=None, metadata={'description': 'The name of the resource that is unique within the set of frontend ip configurations used by the load balancer. This name can be used to access the resource.'})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={'description': 'The virtual network private ip address of the ip configuration.'})  # fmt: skip
    public_ip_address: Optional[str] = field(default=None, metadata={"description": ""})
    subnet: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureLoadBalancerConfiguration:
    kind: ClassVar[str] = "azure_load_balancer_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "frontend_ip_configurations": S("properties", "frontendIpConfigurations")
        >> ForallBend(AzureLoadBalancerFrontendIpConfiguration.mapping),
        "id": S("id"),
        "name": S("name"),
    }
    frontend_ip_configurations: Optional[List[AzureLoadBalancerFrontendIpConfiguration]] = field(default=None, metadata={'description': 'Specifies the frontend ip to be used for the load balancer. Only ipv4 frontend ip address is supported. Each load balancer configuration must have exactly one frontend ip configuration.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Resource id."})
    name: Optional[str] = field(default=None, metadata={"description": "The name of the load balancer."})


@define(eq=False, slots=False)
class AzureCloudServiceNetworkProfile:
    kind: ClassVar[str] = "azure_cloud_service_network_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "load_balancer_configurations": S("loadBalancerConfigurations")
        >> ForallBend(AzureLoadBalancerConfiguration.mapping),
        "slot_type": S("slotType"),
        "swappable_cloud_service": S("swappableCloudService", "id"),
    }
    load_balancer_configurations: Optional[List[AzureLoadBalancerConfiguration]] = field(default=None, metadata={'description': 'List of load balancer configurations. Cloud service can have up to two load balancer configurations, corresponding to a public load balancer and an internal load balancer.'})  # fmt: skip
    slot_type: Optional[str] = field(default=None, metadata={'description': 'Slot type for the cloud service. Possible values are **production** **staging** if not specified, the default value is production.'})  # fmt: skip
    swappable_cloud_service: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureCloudServiceVaultAndSecretReference:
    kind: ClassVar[str] = "azure_cloud_service_vault_and_secret_reference"
    mapping: ClassVar[Dict[str, Bender]] = {"secret_url": S("secretUrl"), "source_vault": S("sourceVault", "id")}
    secret_url: Optional[str] = field(default=None, metadata={'description': 'Secret url which contains the protected settings of the extension.'})  # fmt: skip
    source_vault: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureExtension:
    kind: ClassVar[str] = "azure_extension"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_upgrade_minor_version": S("properties", "autoUpgradeMinorVersion"),
        "force_update_tag": S("properties", "forceUpdateTag"),
        "name": S("name"),
        "protected_settings": S("properties", "protectedSettings"),
        "protected_settings_from_key_vault": S("properties", "protectedSettingsFromKeyVault")
        >> Bend(AzureCloudServiceVaultAndSecretReference.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "publisher": S("properties", "publisher"),
        "roles_applied_to": S("properties", "rolesAppliedTo"),
        "settings": S("properties", "settings"),
        "type": S("properties", "type"),
        "type_handler_version": S("properties", "typeHandlerVersion"),
    }
    auto_upgrade_minor_version: Optional[bool] = field(default=None, metadata={'description': 'Explicitly specify whether platform can automatically upgrade typehandlerversion to higher minor versions when they become available.'})  # fmt: skip
    force_update_tag: Optional[str] = field(default=None, metadata={'description': 'Tag to force apply the provided public and protected settings. Changing the tag value allows for re-running the extension without changing any of the public or protected settings. If forceupdatetag is not changed, updates to public or protected settings would still be applied by the handler. If neither forceupdatetag nor any of public or protected settings change, extension would flow to the role instance with the same sequence-number, and it is up to handler implementation whether to re-run it or not.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the extension."})
    protected_settings: Optional[Any] = field(default=None, metadata={'description': 'Protected settings for the extension which are encrypted before sent to the role instance.'})  # fmt: skip
    protected_settings_from_key_vault: Optional[AzureCloudServiceVaultAndSecretReference] = field(default=None, metadata={'description': 'Protected settings for the extension, referenced using keyvault which are encrypted before sent to the role instance.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state, which only appears in the response.'})  # fmt: skip
    publisher: Optional[str] = field(default=None, metadata={'description': 'The name of the extension handler publisher.'})  # fmt: skip
    roles_applied_to: Optional[List[str]] = field(default=None, metadata={'description': 'Optional list of roles to apply this extension. If property is not specified or * is specified, extension is applied to all roles in the cloud service.'})  # fmt: skip
    settings: Optional[Any] = field(default=None, metadata={'description': 'Public settings for the extension. For json extensions, this is the json settings for the extension. For xml extension (like rdp), this is the xml setting for the extension.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Specifies the type of the extension."})
    type_handler_version: Optional[str] = field(default=None, metadata={'description': 'Specifies the version of the extension. Specifies the version of the extension. If this element is not specified or an asterisk (*) is used as the value, the latest version of the extension is used. If the value is specified with a major version number and an asterisk as the minor version number (x. ), the latest minor version of the specified major version is selected. If a major version number and a minor version number are specified (x. Y), the specific extension version is selected. If a version is specified, an auto-upgrade is performed on the role instance.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCloudServiceExtensionProfile:
    kind: ClassVar[str] = "azure_cloud_service_extension_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"extensions": S("extensions") >> ForallBend(AzureExtension.mapping)}
    extensions: Optional[List[AzureExtension]] = field(default=None, metadata={'description': 'List of extensions for the cloud service.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCloudService(AzureResource):
    kind: ClassVar[str] = "azure_cloud_service"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2022-09-04",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/cloudServices",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "allow_model_override": S("properties", "allowModelOverride"),
        "configuration": S("properties", "configuration"),
        "configuration_url": S("properties", "configurationUrl"),
        "extension_profile": S("properties", "extensionProfile") >> Bend(AzureCloudServiceExtensionProfile.mapping),
        "cloud_service_network_profile": S("properties", "networkProfile")
        >> Bend(AzureCloudServiceNetworkProfile.mapping),
        "os_profile": S("properties", "osProfile") >> Bend(AzureCloudServiceOsProfile.mapping),
        "package_url": S("properties", "packageUrl"),
        "provisioning_state": S("properties", "provisioningState"),
        "role_profile": S("properties", "roleProfile") >> Bend(AzureCloudServiceRoleProfile.mapping),
        "start_cloud_service": S("properties", "startCloudService"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "unique_id": S("properties", "uniqueId"),
        "upgrade_mode": S("properties", "upgradeMode"),
    }
    allow_model_override: Optional[bool] = field(default=None, metadata={'description': '(optional) indicates whether the role sku properties (roleprofile. Roles. Sku) specified in the model/template should override the role instance count and vm size specified in the. Cscfg and. Csdef respectively. The default value is `false`.'})  # fmt: skip
    configuration: Optional[str] = field(default=None, metadata={'description': 'Specifies the xml service configuration (. Cscfg) for the cloud service.'})  # fmt: skip
    configuration_url: Optional[str] = field(default=None, metadata={'description': 'Specifies a url that refers to the location of the service configuration in the blob service. The service package url can be shared access signature (sas) uri from any storage account. This is a write-only property and is not returned in get calls.'})  # fmt: skip
    extension_profile: Optional[AzureCloudServiceExtensionProfile] = field(default=None, metadata={'description': 'Describes a cloud service extension profile.'})  # fmt: skip
    cloud_service_network_profile: Optional[AzureCloudServiceNetworkProfile] = field(default=None, metadata={'description': 'Network profile for the cloud service.'})  # fmt: skip
    os_profile: Optional[AzureCloudServiceOsProfile] = field(default=None, metadata={'description': 'Describes the os profile for the cloud service.'})  # fmt: skip
    package_url: Optional[str] = field(default=None, metadata={'description': 'Specifies a url that refers to the location of the service package in the blob service. The service package url can be shared access signature (sas) uri from any storage account. This is a write-only property and is not returned in get calls.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state, which only appears in the response.'})  # fmt: skip
    role_profile: Optional[AzureCloudServiceRoleProfile] = field(default=None, metadata={'description': 'Describes the role profile for the cloud service.'})  # fmt: skip
    start_cloud_service: Optional[bool] = field(default=None, metadata={'description': '(optional) indicates whether to start the cloud service immediately after it is created. The default value is `true`. If false, the service model is still deployed, but the code is not run immediately. Instead, the service is poweredoff until you call start, at which time the service will be started. A deployed service still incurs charges, even if it is poweredoff.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'The system meta data relating to this resource.'})  # fmt: skip
    unique_id: Optional[str] = field(default=None, metadata={'description': 'The unique identifier for the cloud service.'})  # fmt: skip
    upgrade_mode: Optional[str] = field(default=None, metadata={'description': 'Upgrade mode for the cloud service. Role instances are allocated to update domains when the service is deployed. Updates can be initiated manually in each update domain or initiated automatically in all update domains. Possible values are **auto** **manual** **simultaneous** if not specified, the default value is auto. If set to manual, put updatedomain must be called to apply the update. If set to auto, the update is automatically applied to each update domain in sequence.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerServiceServicePrincipalProfile:
    kind: ClassVar[str] = "azure_container_service_service_principal_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"client_id": S("clientId"), "secret": S("secret")}
    client_id: Optional[str] = field(default=None, metadata={"description": "The id for the service principal."})
    secret: Optional[str] = field(default=None, metadata={'description': 'The secret password associated with the service principal.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerServiceMasterProfile:
    kind: ClassVar[str] = "azure_container_service_master_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"count": S("count"), "dns_prefix": S("dnsPrefix"), "fqdn": S("fqdn")}
    count: Optional[int] = field(default=None, metadata={'description': 'Number of masters (vms) in the container service cluster. Allowed values are 1, 3, and 5. The default value is 1.'})  # fmt: skip
    dns_prefix: Optional[str] = field(default=None, metadata={'description': 'Dns prefix to be used to create the fqdn for master.'})  # fmt: skip
    fqdn: Optional[str] = field(default=None, metadata={"description": "Fqdn for the master."})


@define(eq=False, slots=False)
class AzureContainerServiceWindowsProfile:
    kind: ClassVar[str] = "azure_container_service_windows_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"admin_password": S("adminPassword"), "admin_username": S("adminUsername")}
    admin_password: Optional[str] = field(default=None, metadata={'description': 'The administrator password to use for windows vms.'})  # fmt: skip
    admin_username: Optional[str] = field(default=None, metadata={'description': 'The administrator username to use for windows vms.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerServiceSshConfiguration:
    kind: ClassVar[str] = "azure_container_service_ssh_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"public_keys": S("publicKeys", default=[]) >> ForallBend(S("keyData"))}
    public_keys: Optional[List[str]] = field(default=None, metadata={'description': 'The list of ssh public keys used to authenticate with linux-based vms.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerServiceLinuxProfile:
    kind: ClassVar[str] = "azure_container_service_linux_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "admin_username": S("adminUsername"),
        "ssh": S("ssh") >> Bend(AzureContainerServiceSshConfiguration.mapping),
    }
    admin_username: Optional[str] = field(default=None, metadata={'description': 'The administrator username to use for linux vms.'})  # fmt: skip
    ssh: Optional[AzureContainerServiceSshConfiguration] = field(default=None, metadata={'description': 'Ssh configuration for linux-based vms running on azure.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerServiceVMDiagnostics:
    kind: ClassVar[str] = "azure_container_service_vm_diagnostics"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "storage_uri": S("storageUri")}
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether the vm diagnostic agent is provisioned on the vm.'})  # fmt: skip
    storage_uri: Optional[str] = field(default=None, metadata={'description': 'The uri of the storage account where diagnostics are stored.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDedicatedHostGroupInstanceView:
    kind: ClassVar[str] = "azure_dedicated_host_group_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {"hosts": S("hosts", default=[]) >> ForallBend(S("name"))}
    hosts: Optional[List[str]] = field(default=None, metadata={'description': 'List of instance view of the dedicated hosts under the dedicated host group.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDedicatedHostGroup(AzureResource):
    kind: ClassVar[str] = "azure_dedicated_host_group"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/hostGroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ultra_ssd_enabled": S("properties", "additionalCapabilities", "ultraSSDEnabled"),
        "hosts": S("properties") >> S("hosts", default=[]) >> ForallBend(S("id")),
        "host_group_instance_view": S("properties", "instanceView")
        >> Bend(AzureDedicatedHostGroupInstanceView.mapping),
        "platform_fault_domain_count": S("properties", "platformFaultDomainCount"),
        "support_automatic_placement": S("properties", "supportAutomaticPlacement"),
    }
    ultra_ssd_enabled: Optional[bool] = field(default=None, metadata={'description': 'Enables or disables a capability on the dedicated host group. Minimum api-version: 2022-03-01.'})  # fmt: skip
    hosts: Optional[List[str]] = field(default=None, metadata={'description': 'A list of references to all dedicated hosts in the dedicated host group.'})  # fmt: skip
    host_group_instance_view: Optional[AzureDedicatedHostGroupInstanceView] = field(
        default=None, metadata={"description": ""}
    )
    platform_fault_domain_count: Optional[int] = field(default=None, metadata={'description': 'Number of fault domains that the host group can span.'})  # fmt: skip
    support_automatic_placement: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether virtual machines or virtual machine scale sets can be placed automatically on the dedicated host group. Automatic placement means resources are allocated on dedicated hosts, that are chosen by azure, under the dedicated host group. The value is defaulted to false when not provided. Minimum api-version: 2020-06-01.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDiskSku:
    kind: ClassVar[str] = "azure_disk_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "tier": S("tier")}
    name: Optional[str] = field(default=None, metadata={"description": "The sku name."})
    tier: Optional[str] = field(default=None, metadata={"description": "The sku tier."})


@define(eq=False, slots=False)
class AzurePurchasePlan:
    kind: ClassVar[str] = "azure_purchase_plan"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "product": S("product"),
        "promotion_code": S("promotionCode"),
        "publisher": S("publisher"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The plan id."})
    product: Optional[str] = field(default=None, metadata={'description': 'Specifies the product of the image from the marketplace. This is the same value as offer under the imagereference element.'})  # fmt: skip
    promotion_code: Optional[str] = field(default=None, metadata={"description": "The offer promotion code."})
    publisher: Optional[str] = field(default=None, metadata={"description": "The publisher id."})


@define(eq=False, slots=False)
class AzureSupportedCapabilities:
    kind: ClassVar[str] = "azure_supported_capabilities"
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerated_network": S("acceleratedNetwork"),
        "architecture": S("architecture"),
        "disk_controller_types": S("diskControllerTypes"),
    }
    accelerated_network: Optional[bool] = field(default=None, metadata={'description': 'True if the image from which the os disk is created supports accelerated networking.'})  # fmt: skip
    architecture: Optional[str] = field(default=None, metadata={'description': 'Cpu architecture supported by an os disk.'})  # fmt: skip
    disk_controller_types: Optional[str] = field(default=None, metadata={'description': 'The disk controllers that an os disk supports. If set it can be scsi or scsi, nvme or nvme, scsi.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureImageDiskReference:
    kind: ClassVar[str] = "azure_image_disk_reference"
    mapping: ClassVar[Dict[str, Bender]] = {
        "community_gallery_image_id": S("communityGalleryImageId"),
        "id": S("id"),
        "lun": S("lun"),
        "shared_gallery_image_id": S("sharedGalleryImageId"),
    }
    community_gallery_image_id: Optional[str] = field(default=None, metadata={'description': 'A relative uri containing a community azure compute gallery image reference.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'A relative uri containing either a platform image repository, user image, or azure compute gallery image reference.'})  # fmt: skip
    lun: Optional[int] = field(default=None, metadata={'description': 'If the disk is created from an image s data disk, this is an index that indicates which of the data disks in the image to use. For os disks, this field is null.'})  # fmt: skip
    shared_gallery_image_id: Optional[str] = field(default=None, metadata={'description': 'A relative uri containing a direct shared azure compute gallery image reference.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCreationData:
    kind: ClassVar[str] = "azure_creation_data"
    mapping: ClassVar[Dict[str, Bender]] = {
        "create_option": S("createOption"),
        "gallery_image_reference": S("galleryImageReference") >> Bend(AzureImageDiskReference.mapping),
        "image_reference": S("imageReference") >> Bend(AzureImageDiskReference.mapping),
        "logical_sector_size": S("logicalSectorSize"),
        "performance_plus": S("performancePlus"),
        "security_data_uri": S("securityDataUri"),
        "source_resource_id": S("sourceResourceId"),
        "source_unique_id": S("sourceUniqueId"),
        "source_uri": S("sourceUri"),
        "storage_account_id": S("storageAccountId"),
        "upload_size_bytes": S("uploadSizeBytes"),
    }
    create_option: Optional[str] = field(default=None, metadata={'description': 'This enumerates the possible sources of a disk s creation.'})  # fmt: skip
    gallery_image_reference: Optional[AzureImageDiskReference] = field(default=None, metadata={'description': 'The source image used for creating the disk.'})  # fmt: skip
    image_reference: Optional[AzureImageDiskReference] = field(default=None, metadata={'description': 'The source image used for creating the disk.'})  # fmt: skip
    logical_sector_size: Optional[int] = field(default=None, metadata={'description': 'Logical sector size in bytes for ultra disks. Supported values are 512 ad 4096. 4096 is the default.'})  # fmt: skip
    performance_plus: Optional[bool] = field(default=None, metadata={'description': 'Set this flag to true to get a boost on the performance target of the disk deployed, see here on the respective performance target. This flag can only be set on disk creation time and cannot be disabled after enabled.'})  # fmt: skip
    security_data_uri: Optional[str] = field(default=None, metadata={'description': 'If createoption is importsecure, this is the uri of a blob to be imported into vm guest state.'})  # fmt: skip
    source_resource_id: Optional[str] = field(default=None, metadata={'description': 'If createoption is copy, this is the arm id of the source snapshot or disk.'})  # fmt: skip
    source_unique_id: Optional[str] = field(default=None, metadata={'description': 'If this field is set, this is the unique id identifying the source of this resource.'})  # fmt: skip
    source_uri: Optional[str] = field(default=None, metadata={'description': 'If createoption is import, this is the uri of a blob to be imported into a managed disk.'})  # fmt: skip
    storage_account_id: Optional[str] = field(default=None, metadata={'description': 'Required if createoption is import. The azure resource manager identifier of the storage account containing the blob to import as a disk.'})  # fmt: skip
    upload_size_bytes: Optional[int] = field(default=None, metadata={'description': 'If createoption is upload, this is the size of the contents of the upload including the vhd footer. This value should be between 20972032 (20 mib + 512 bytes for the vhd footer) and 35183298347520 bytes (32 tib + 512 bytes for the vhd footer).'})  # fmt: skip


@define(eq=False, slots=False)
class AzureKeyVaultAndSecretReference:
    kind: ClassVar[str] = "azure_key_vault_and_secret_reference"
    mapping: ClassVar[Dict[str, Bender]] = {"secret_url": S("secretUrl"), "source_vault": S("sourceVault", "id")}
    secret_url: Optional[str] = field(default=None, metadata={'description': 'Url pointing to a key or secret in keyvault.'})  # fmt: skip
    source_vault: Optional[str] = field(default=None, metadata={'description': 'The vault id is an azure resource manager resource id in the form /subscriptions/{subscriptionid}/resourcegroups/{resourcegroupname}/providers/microsoft. Keyvault/vaults/{vaultname}.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureKeyVaultAndKeyReference:
    kind: ClassVar[str] = "azure_key_vault_and_key_reference"
    mapping: ClassVar[Dict[str, Bender]] = {"key_url": S("keyUrl"), "source_vault": S("sourceVault", "id")}
    key_url: Optional[str] = field(default=None, metadata={'description': 'Url pointing to a key or secret in keyvault.'})  # fmt: skip
    source_vault: Optional[str] = field(default=None, metadata={'description': 'The vault id is an azure resource manager resource id in the form /subscriptions/{subscriptionid}/resourcegroups/{resourcegroupname}/providers/microsoft. Keyvault/vaults/{vaultname}.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionSettingsElement:
    kind: ClassVar[str] = "azure_encryption_settings_element"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_encryption_key": S("diskEncryptionKey") >> Bend(AzureKeyVaultAndSecretReference.mapping),
        "key_encryption_key": S("keyEncryptionKey") >> Bend(AzureKeyVaultAndKeyReference.mapping),
    }
    disk_encryption_key: Optional[AzureKeyVaultAndSecretReference] = field(default=None, metadata={'description': 'Key vault secret url and vault id of the encryption key.'})  # fmt: skip
    key_encryption_key: Optional[AzureKeyVaultAndKeyReference] = field(default=None, metadata={'description': 'Key vault key url and vault id of kek, kek is optional and when provided is used to unwrap the encryptionkey.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionSettingsCollection:
    kind: ClassVar[str] = "azure_encryption_settings_collection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "encryption_settings": S("encryptionSettings") >> ForallBend(AzureEncryptionSettingsElement.mapping),
        "encryption_settings_version": S("encryptionSettingsVersion"),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Set this flag to true and provide diskencryptionkey and optional keyencryptionkey to enable encryption. Set this flag to false and remove diskencryptionkey and keyencryptionkey to disable encryption. If encryptionsettings is null in the request object, the existing settings remain unchanged.'})  # fmt: skip
    encryption_settings: Optional[List[AzureEncryptionSettingsElement]] = field(default=None, metadata={'description': 'A collection of encryption settings, one for each disk volume.'})  # fmt: skip
    encryption_settings_version: Optional[str] = field(default=None, metadata={'description': 'Describes what type of encryption is used for the disks. Once this field is set, it cannot be overwritten. 1. 0 corresponds to azure disk encryption with aad app. 1. 1 corresponds to azure disk encryption.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryption:
    kind: ClassVar[str] = "azure_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {"disk_encryption_set_id": S("diskEncryptionSetId"), "type": S("type")}
    disk_encryption_set_id: Optional[str] = field(default=None, metadata={'description': 'Resourceid of the disk encryption set to use for enabling encryption at rest.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of key used to encrypt the data of the disk.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDiskSecurityProfile:
    kind: ClassVar[str] = "azure_disk_security_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "secure_vm_disk_encryption_set_id": S("secureVMDiskEncryptionSetId"),
        "security_type": S("securityType"),
    }
    secure_vm_disk_encryption_set_id: Optional[str] = field(default=None, metadata={'description': 'Resourceid of the disk encryption set associated to confidential vm supported disk encrypted with customer managed key.'})  # fmt: skip
    security_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the securitytype of the vm. Applicable for os disks only.'})  # fmt: skip


resource_group_map = {
    "Premium_SSD_LRS": "Premium_LRS",
    "Premium_SSD_ZRS": "Premium_ZRS",
    "Standard_HDD_LRS": "Standard_LRS",
    "Standard_SSD_LRS": "StandardSSD_LRS",
    "Standard_SSD_ZRS": "StandardSSD_ZRS",
}

storage_sku_info = {
    "Premium_SSD": {
        "P1": {"size": 4, "maxIOPS": 120, "maxThroughput": 25},
        "P2": {"size": 8, "maxIOPS": 120, "maxThroughput": 25},
        "P3": {"size": 16, "maxIOPS": 120, "maxThroughput": 25},
        "P4": {"size": 32, "maxIOPS": 120, "maxThroughput": 25},
        "P6": {"size": 64, "maxIOPS": 240, "maxThroughput": 50},
        "P10": {"size": 128, "maxIOPS": 500, "maxThroughput": 100},
        "P15": {"size": 256, "maxIOPS": 1100, "maxThroughput": 125},
        "P20": {"size": 512, "maxIOPS": 2300, "maxThroughput": 150},
        "P30": {"size": 1024, "maxIOPS": 5000, "maxThroughput": 200},
        "P40": {"size": 2048, "maxIOPS": 7500, "maxThroughput": 250},
        "P50": {"size": 4096, "maxIOPS": 7500, "maxThroughput": 250},
        "P60": {"size": 8192, "maxIOPS": 16000, "maxThroughput": 500},
        "P70": {"size": 16384, "maxIOPS": 18000, "maxThroughput": 750},
        "P80": {"size": 32768, "maxIOPS": 20000, "maxThroughput": 900},
    },
    "Standard_SSD": {
        "E1": {"size": 4, "maxIOPS": 120, "maxThroughput": 25},
        "E2": {"size": 8, "maxIOPS": 120, "maxThroughput": 25},
        "E3": {"size": 16, "maxIOPS": 120, "maxThroughput": 25},
        "E4": {"size": 32, "maxIOPS": 120, "maxThroughput": 25},
        "E6": {"size": 64, "maxIOPS": 240, "maxThroughput": 50},
        "E10": {"size": 128, "maxIOPS": 500, "maxThroughput": 60},
        "E15": {"size": 256, "maxIOPS": 500, "maxThroughput": 60},
        "E20": {"size": 512, "maxIOPS": 500, "maxThroughput": 60},
        "E30": {"size": 1024, "maxIOPS": 500, "maxThroughput": 60},
        "E40": {"size": 2048, "maxIOPS": 500, "maxThroughput": 60},
        "E50": {"size": 4096, "maxIOPS": 500, "maxThroughput": 60},
        "E60": {"size": 8192, "maxIOPS": 2000, "maxThroughput": 400},
        "E70": {"size": 16384, "maxIOPS": 4000, "maxThroughput": 600},
        "E80": {"size": 32768, "maxIOPS": 6000, "maxThroughput": 750},
    },
    "Standard_HDD": {
        "S4": {"size": 32, "maxIOPS": 500, "maxThroughput": 60},
        "S6": {"size": 64, "maxIOPS": 500, "maxThroughput": 60},
        "S10": {"size": 128, "maxIOPS": 500, "maxThroughput": 60},
        "S15": {"size": 256, "maxIOPS": 500, "maxThroughput": 60},
        "S20": {"size": 512, "maxIOPS": 500, "maxThroughput": 60},
        "S30": {"size": 1024, "maxIOPS": 500, "maxThroughput": 60},
        "S40": {"size": 2048, "maxIOPS": 500, "maxThroughput": 60},
        "S50": {"size": 4096, "maxIOPS": 500, "maxThroughput": 60},
        "S60": {"size": 8192, "maxIOPS": 1300, "maxThroughput": 300},
        "S70": {"size": 16384, "maxIOPS": 2000, "maxThroughput": 500},
        "S80": {"size": 32768, "maxIOPS": 2000, "maxThroughput": 500},
    },
}

storage_sku_tier_by_size = {
    "Premium": {
        4: "P1",
        8: "P2",
        16: "P3",
        32: "P4",
        64: "P6",
        128: "P10",
        256: "P15",
        512: "P20",
        1024: "P30",
        2048: "P40",
        4096: "P50",
        8192: "P60",
        16384: "P70",
        32768: "P80",
    },
    "StandardSSD": {
        4: "E1",
        8: "E2",
        16: "E3",
        32: "E4",
        64: "E6",
        128: "E10",
        256: "E15",
        512: "E20",
        1024: "E30",
        2048: "E40",
        4096: "E50",
        8192: "E60",
        16384: "E70",
        32768: "E80",
    },
    "Standard": {
        32: "S4",
        64: "S6",
        128: "S10",
        256: "S15",
        512: "S20",
        1024: "S30",
        2048: "S40",
        4096: "S50",
        8192: "S60",
        16384: "S70",
        32768: "S80",
    },
}

ultra_disk_sku_info = {
    4: {"maxIOPS": 1200, "maxThroughput": 300},
    8: {"maxIOPS": 2400, "maxThroughput": 600},
    16: {"maxIOPS": 4800, "maxThroughput": 1200},
    32: {"maxIOPS": 9600, "maxThroughput": 2400},
    64: {"maxIOPS": 19200, "maxThroughput": 4900},
    128: {"maxIOPS": 38400, "maxThroughput": 9800},
    256: {"maxIOPS": 76800, "maxThroughput": 10000},
    512: {"maxIOPS": 153600, "maxThroughput": 10000},
}

ultra_disk_sku_info.update({size: {"maxIOPS": 400000, "maxThroughput": 10000} for size in range(1024, 65537, 1024)})

# Map for mathcing location between Azure API and pricing API
pricing_lookup_locations = {
    "australiacentral": "australia-central",
    "australiaeast": "australia-east",
    "brazilsouth": "brazil-south",
    "canadacentral": "canada-central",
    "centralindia": "central-india",
    "centralus": "us-central",
    "eastasia": "asia-pacific-east",
    "eastus": "us-east",
    "eastus2": "us-east-2",
    "francecentral": "france-central",
    "germanywestcentral": "germany-west-central",
    "italynorth": "italy-north",
    "japaneast": "japan-east",
    "koreacentral": "korea-central",
    "koreasouth": "korea-south",
    "northcentralus": "us-north-central",
    "northeurope": "europe-north",
    "norwayeast": "norway-east",
    "polandcentral": "poland-central",
    "qatarcentral": "qatar-central",
    "southafricanorth": "south-africa-north",
    "southcentralus": "us-south-central",
    "southeastasia": "asia-pacific-southeast",
    "swedencentral": "sweden-central",
    "switzerlandnorth": "switzerland-north",
    "uaenorth": "uae-north",
    "uksouth": "united-kingdom-south",
    "ukwest": "united-kingdom-west",
    "usgov-arizona": "usgov-arizona",
    "usgov-virginia": "usgov-virginia",
    "westeurope": "europe-west",
    "westus": "us-west",
    "westus2": "us-west-2",
    "westus3": "us-west-3",
    "brazilsoutheast": "brazil-southeast",
    "usgov-texas": "usgov-texas",
    "australiacentral2": "australia-central-2",
    "canadaeast": "canada-east",
    "japanwest": "japan-west",
    "southafricawest": "south-africa-west",
    "southindia": "south-india",
    "swedensouth": "sweden-south",
    "switzerlandwest": "switzerland-west",
    "westcentralus": "us-west-central",
}


@define(eq=False, slots=False)
class AzurePricingGraduatedOffers:
    kind: ClassVar[str] = "azure_pricing_graduated_offers"
    mapping: ClassVar[Dict[str, Bender]] = {
        "premium_ssd_v2_iops": S("premiumssdv2-iops"),
        "premium_ssd_v2_throughput": S("premiumssdv2-throughput"),
    }
    premium_ssd_v2_iops: Optional[Dict[str, Any]] = None
    premium_ssd_v2_throughput: Optional[Dict[str, Any]] = None


@define(eq=False, slots=False)
class AzurePricingOffers:
    kind: ClassVar[str] = "azure_pricing_offers"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ultra_ssd_iops": S("ultrassd-iops", "prices"),
        "ultra_ssd_stored": S("ultrassd-stored", "prices"),
        "ultra_ssd_throughput": S("ultrassd-throughput", "prices"),
        "premium_ssd_v2_capacity": S("premiumssdv2-capacity", "prices"),
    }
    ultra_ssd_iops: Optional[Dict[str, Any]] = None
    ultra_ssd_stored: Optional[Dict[str, Any]] = None
    ultra_ssd_throughput: Optional[Dict[str, Any]] = None
    premium_ssd_v2_capacity: Optional[Dict[str, Any]] = None


@define(eq=False, slots=False)
class AzureDiskTypePricing(AzureResource):
    kind: ClassVar[str] = "azure_disk_type_pricing"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="",
        path="https://azure.microsoft.com/api/v2/pricing/managed-disks/calculator/",
        # Define path param 'subscriptionId' to collect as global resources
        path_parameters=["subscriptionId"],
        query_parameters=[],
        access_path=None,
        expect_array=False,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": K(None),
        "offers": S("offers") >> Bend(AzurePricingOffers.mapping),
        "graduated_offers": S("graduatedOffers") >> Bend(AzurePricingGraduatedOffers.mapping),
    }
    offers: Optional[AzurePricingOffers] = None
    graduated_offers: Optional[AzurePricingGraduatedOffers] = None


@define(eq=False, slots=False)
class AzureDiskType(AzureResource, BaseVolumeType):
    kind: ClassVar[str] = "azure_disk_type"
    # Define api spec to collect as regional resources
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-01-01-preview",
        path="",
        path_parameters=["subscriptionId", "location"],
        query_parameters=[],
        access_path="Items",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("skuName"),
        "name": S("skuName"),
        "full_name": S("armSkuName"),
        "product_name": S("productName"),
        "tier": S("skuName") >> F(lambda sku: sku.split(" ")[0]),
        "redundancy": S("skuName") >> F(lambda sku: sku.split(" ")[1]),
        "information_name": S("productName") >> F(lambda name: "_".join(name.split(" ")[:2])),
        "ondemand_cost": S("unitPrice") >> F(lambda price: (price / 30) / 24),
        "volume_type": (
            (
                (S("productName") >> F(lambda name: "_".join(name.split(" ")[:2])))
                + K("_")
                + (S("skuName") >> F(lambda sku: sku.split(" ")[1]))
            )
            >> MapValue(resource_group_map)
        ).or_else(S("type")),
        "volume_size": S("size"),
        "volume_iops": S("maxIOPS").or_else(S("volume_iops")),
        "volume_throughput": S("maxThroughput").or_else(S("volume_throughput")),
        "location": S("armRegionName"),
    }
    full_name: Optional[str] = None
    product_name: Optional[str] = None
    tier: Optional[str] = field(default=None, metadata={'description': 'Performance tier of the disk (e. G, p4, s10) as described here: https://azure. Microsoft. Com/en-us/pricing/details/managed-disks/. Does not apply to ultra disks.'})  # fmt: skip
    redundancy: Optional[str] = None
    information_name: Optional[str] = None
    volume_iops: Optional[int] = None
    volume_throughput: Optional[int] = None
    volume_size: Optional[int] = None
    location: Optional[str] = None
    iops_price: Optional[float] = None
    size_price: Optional[float] = None
    throughput_price: Optional[float] = None
    _is_provider_link: bool = False

    def after_collect(self, builder: GraphBuilder, source: Json) -> None:
        location = self.location
        volume_type = self.volume_type

        if location and volume_type in ("UltraSSD_LRS", "PremiumV2_LRS"):
            # Fetch price for Ultra SSD and Premium SSD V2
            pricing_node = builder.nodes(AzureDiskTypePricing)[0]

            offers = pricing_node.offers
            grad_offers = pricing_node.graduated_offers

            # Set pricing based on location and volume type
            if offers and grad_offers and (location_data := pricing_lookup_locations.get(location)):
                if volume_type == "UltraSSD_LRS":
                    if offers.ultra_ssd_iops:
                        self.iops_price = rgetvalue(offers.ultra_ssd_iops, f"{location_data}.value", None)
                    if offers.ultra_ssd_stored:
                        self.size_price = rgetvalue(offers.ultra_ssd_stored, f"{location_data}.value", None)
                    if offers.ultra_ssd_throughput:
                        self.throughput_price = rgetvalue(offers.ultra_ssd_throughput, f"{location_data}.value", None)
                elif volume_type == "PremiumV2_LRS":
                    if offers.premium_ssd_v2_capacity:
                        self.size_price = rgetvalue(offers.premium_ssd_v2_capacity, f"{location_data}.value", None)
                    if grad_offers.premium_ssd_v2_iops:
                        self.iops_price = rgetvalue(grad_offers.premium_ssd_v2_iops, f"{location_data}.prices", None)[
                            1
                        ]["price"]["value"]
                    if grad_offers.premium_ssd_v2_throughput:
                        self.throughput_price = rgetvalue(
                            grad_offers.premium_ssd_v2_throughput, f"{location_data}.prices", None
                        )[1]["price"]["value"]

            volume_iops = self.volume_iops
            volume_throughput = self.volume_throughput
            volume_size = self.volume_size

            # Set ondemand cost
            if (
                volume_iops
                and volume_throughput
                and volume_size
                and self.iops_price
                and self.size_price
                and self.throughput_price
            ):

                ondemand_cost = volume_size * self.size_price
                if volume_type == "UltraSSD_LRS":
                    ondemand_cost += volume_iops * self.iops_price + volume_throughput * self.throughput_price

                if volume_type == "PremiumV2_LRS":
                    # Add cost for exceeding Premium V2 SSD IOPS/throughput limits
                    ondemand_cost += max(0, volume_iops - 3000) * self.iops_price
                    ondemand_cost += max(0, volume_throughput - 125) * self.throughput_price

                self.ondemand_cost = ondemand_cost

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        # Set common storage types except Premium V2 SSD and Ultra Disk
        if (volume_type := self.volume_type) and (volume_type not in ["UltraSSD_LRS", "PremiumV2_LRS"]):
            if not (information_name := self.information_name) or not (tier := self.tier):
                return
            disk_configuration = storage_sku_info.get(information_name)
            if not disk_configuration:
                return

            disk_info = disk_configuration.get(tier)
            if not disk_info:
                return

            self.volume_size = disk_info.get("size")
            self.volume_iops = disk_info.get("maxIOPS")
            self.volume_throughput = disk_info.get("maxThroughput")

    @staticmethod
    def build_custom_disk_size(
        location: str, disk_type: str, disk_size: int, disk_iops: int, disk_throughput: int
    ) -> Json:
        if disk_type == "UltraSSD_LRS":
            nearest_ultra_disk_size = AzureDisk._get_nearest_size(disk_size, ultra_disk_sku_info)
            ultra_disk_config = ultra_disk_sku_info.get(nearest_ultra_disk_size, {})
            ulta_ssd_object = {
                "size": disk_size,
                "skuName": "Ultra SSD",
                "type": disk_type,
                "armRegionName": location,
                "volume_iops": disk_iops,
                "volume_throughput": disk_throughput,
                **ultra_disk_config,
            }
            return ulta_ssd_object

        premium_ssd_v2_object = {
            "size": disk_size,
            "skuName": "Premium SSD V2",
            "type": disk_type,
            "armRegionName": location,
            "volume_iops": disk_iops,
            "volume_throughput": disk_throughput,
        }
        return premium_ssd_v2_object

    @staticmethod
    def create_unique_disk_sizes(collected_disks: List[AzureResourceType], builder: GraphBuilder) -> None:
        disk_sizes: List[Json] = []
        seen_hashes = set()  # Set to keep track of unique hashes
        for disk in collected_disks:
            if not isinstance(disk, AzureDisk):
                continue
            if (
                (volume_type := disk.volume_type)
                and (location := disk.location)
                and (size := disk.volume_size)
                and (iops := disk.volume_iops)
                and (throughput := disk.volume_throughput)
            ):
                if volume_type not in ["UltraSSD_LRS", "PremiumV2_LRS"]:
                    continue

                generic_size = AzureDiskType.build_custom_disk_size(location, volume_type, size, iops, throughput)
                hash_value = hash(tuple(generic_size.items()))
                if hash_value not in seen_hashes:
                    disk_sizes.append(generic_size)
                    seen_hashes.add(hash_value)
        AzureDiskType.collect(disk_sizes, builder)

    @classmethod
    def collect_resources(
        cls: Type[AzureResourceType], builder: GraphBuilder, **kwargs: Any
    ) -> List[AzureResourceType]:
        log.debug(f"[Azure:{builder.subscription.id}] Collecting {cls.__name__} with ({kwargs})")
        product_names = {"Standard SSD Managed Disks", "Premium SSD Managed Disks", "Standard HDD Managed Disks"}
        sku_items = []
        for product_name in product_names:
            api_spec = AzureApiSpec(
                service="compute",
                version="2023-01-01-preview",
                path=f"https://prices.azure.com/api/retail/prices?$filter=productName eq '{product_name}' and armRegionName eq "
                + "'{location}' and unitOfMeasure eq '1/Month' and serviceFamily eq 'Storage' and type eq 'Consumption' and isPrimaryMeterRegion eq true",
                path_parameters=["location"],
                query_parameters=["api-version"],
                access_path="Items",
                expect_array=True,
            )

            items = builder.client.list(api_spec, **kwargs)
            sku_items.extend(items)
        return cls.collect(sku_items, builder)


VolumeStatusMapping = {
    "ActiveSAS": VolumeStatus.IN_USE,
    "ActiveSASFrozen": VolumeStatus.IN_USE,
    "ActiveUpload": VolumeStatus.BUSY,
    "Attached": VolumeStatus.IN_USE,
    "Frozen": VolumeStatus.IN_USE,
    "ReadyToUpload": VolumeStatus.BUSY,
    "Reserved": VolumeStatus.IN_USE,
    "Unattached": VolumeStatus.AVAILABLE,
}


@define(eq=False, slots=False)
class AzureDisk(AzureResource, BaseVolume):
    kind: ClassVar[str] = "azure_disk"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-01-02",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/disks",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_disk_access"]},
        "successors": {"default": ["azure_disk_encryption_set", "azure_disk_type"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("properties", "timeCreated"),
        "mtime": S("LastOwnershipUpdateTime"),
        "bursting_enabled": S("properties", "burstingEnabled"),
        "bursting_enabled_time": S("properties", "burstingEnabledTime"),
        "completion_percent": S("properties", "completionPercent"),
        "creation_data": S("properties", "creationData") >> Bend(AzureCreationData.mapping),
        "data_access_auth_mode": S("properties", "dataAccessAuthMode"),
        "disk_access_id": S("properties", "diskAccessId"),
        "disk_iops_read_only": S("properties", "diskIOPSReadOnly"),
        "disk_iops_read_write": S("properties", "diskIOPSReadWrite"),
        "disk_m_bps_read_only": S("properties", "diskMBpsReadOnly"),
        "disk_m_bps_read_write": S("properties", "diskMBpsReadWrite"),
        "disk_size_bytes": S("properties", "diskSizeBytes"),
        "disk_size_gb": S("properties", "diskSizeGB"),
        "disk_state": S("properties", "diskState"),
        "disk_encryption": S("properties", "encryption") >> Bend(AzureEncryption.mapping),
        "encryption_settings_collection": S("properties", "encryptionSettingsCollection")
        >> Bend(AzureEncryptionSettingsCollection.mapping),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "hyper_v_generation": S("properties", "hyperVGeneration"),
        "managed_by": S("managedBy"),
        "managed_by_extended": S("managedByExtended"),
        "max_shares": S("properties", "maxShares"),
        "network_access_policy": S("properties", "networkAccessPolicy"),
        "optimized_for_frequent_attach": S("properties", "optimizedForFrequentAttach"),
        "os_type": S("properties", "osType"),
        "property_updates_in_progress": S("properties", "propertyUpdatesInProgress", "targetTier"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "purchase_plan": S("properties", "purchasePlan") >> Bend(AzurePurchasePlan.mapping),
        "disk_security_profile": S("properties", "securityProfile") >> Bend(AzureDiskSecurityProfile.mapping),
        "share_info": S("properties") >> S("shareInfo", default=[]) >> ForallBend(S("vmUri")),
        "disk_sku": S("sku") >> Bend(AzureDiskSku.mapping),
        "supported_capabilities": S("properties", "supportedCapabilities") >> Bend(AzureSupportedCapabilities.mapping),
        "supports_hibernation": S("properties", "supportsHibernation"),
        "tier": S("properties", "tier"),
        "time_created": S("properties", "timeCreated"),
        "location": S("location"),
        "tier_name": S("sku", "tier"),
        "unique_id": S("properties", "uniqueId"),
        "volume_size": S("properties", "diskSizeGB"),
        "volume_type": S("sku", "name"),
        "volume_status": S("properties", "diskState") >> MapEnum(VolumeStatusMapping, default=VolumeStatus.UNKNOWN),
        "volume_iops": S("properties", "diskIOPSReadWrite"),
        "volume_throughput": S("properties", "diskMBpsReadWrite"),
        "volume_encrypted": S("properties", "encryptionSettingsCollection", "enabled"),
    }
    bursting_enabled: Optional[bool] = field(default=None, metadata={'description': 'Set to true to enable bursting beyond the provisioned performance target of the disk. Bursting is disabled by default. Does not apply to ultra disks.'})  # fmt: skip
    bursting_enabled_time: Optional[datetime] = field(default=None, metadata={'description': 'Latest time when bursting was last enabled on a disk.'})  # fmt: skip
    completion_percent: Optional[float] = field(default=None, metadata={'description': 'Percentage complete for the background copy when a resource is created via the copystart operation.'})  # fmt: skip
    creation_data: Optional[AzureCreationData] = field(default=None, metadata={'description': 'Data used when creating a disk.'})  # fmt: skip
    data_access_auth_mode: Optional[str] = field(default=None, metadata={'description': 'Additional authentication requirements when exporting or uploading to a disk or snapshot.'})  # fmt: skip
    disk_access_id: Optional[str] = field(default=None, metadata={'description': 'Arm id of the diskaccess resource for using private endpoints on disks.'})  # fmt: skip
    disk_iops_read_only: Optional[int] = field(default=None, metadata={'description': 'The total number of iops that will be allowed across all vms mounting the shared disk as readonly. One operation can transfer between 4k and 256k bytes.'})  # fmt: skip
    disk_iops_read_write: Optional[int] = field(default=None, metadata={'description': 'The number of iops allowed for this disk; only settable for ultrassd disks. One operation can transfer between 4k and 256k bytes.'})  # fmt: skip
    disk_m_bps_read_only: Optional[int] = field(default=None, metadata={'description': 'The total throughput (mbps) that will be allowed across all vms mounting the shared disk as readonly. Mbps means millions of bytes per second - mb here uses the iso notation, of powers of 10.'})  # fmt: skip
    disk_m_bps_read_write: Optional[int] = field(default=None, metadata={'description': 'The bandwidth allowed for this disk; only settable for ultrassd disks. Mbps means millions of bytes per second - mb here uses the iso notation, of powers of 10.'})  # fmt: skip
    disk_size_bytes: Optional[int] = field(default=None, metadata={'description': 'The size of the disk in bytes. This field is read only.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'If creationdata. Createoption is empty, this field is mandatory and it indicates the size of the disk to create. If this field is present for updates or creation with other options, it indicates a resize. Resizes are only allowed if the disk is not attached to a running vm, and can only increase the disk s size.'})  # fmt: skip
    disk_state: Optional[str] = field(default=None, metadata={'description': 'This enumerates the possible state of the disk.'})  # fmt: skip
    disk_encryption: Optional[AzureEncryption] = field(default=None, metadata={'description': 'Encryption at rest settings for disk or snapshot.'})  # fmt: skip
    encryption_settings_collection: Optional[AzureEncryptionSettingsCollection] = field(default=None, metadata={'description': 'Encryption settings for disk or snapshot.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The complex type of the extended location.'})  # fmt: skip
    hyper_v_generation: Optional[str] = field(default=None, metadata={'description': 'The hypervisor generation of the virtual machine. Applicable to os disks only.'})  # fmt: skip
    managed_by: Optional[str] = field(default=None, metadata={'description': 'A relative uri containing the id of the vm that has the disk attached.'})  # fmt: skip
    managed_by_extended: Optional[List[str]] = field(default=None, metadata={'description': 'List of relative uris containing the ids of the vms that have the disk attached. Maxshares should be set to a value greater than one for disks to allow attaching them to multiple vms.'})  # fmt: skip
    max_shares: Optional[int] = field(default=None, metadata={'description': 'The maximum number of vms that can attach to the disk at the same time. Value greater than one indicates a disk that can be mounted on multiple vms at the same time.'})  # fmt: skip
    network_access_policy: Optional[str] = field(default=None, metadata={'description': 'Policy for accessing the disk via network.'})  # fmt: skip
    optimized_for_frequent_attach: Optional[bool] = field(default=None, metadata={'description': 'Setting this property to true improves reliability and performance of data disks that are frequently (more than 5 times a day) by detached from one virtual machine and attached to another. This property should not be set for disks that are not detached and attached frequently as it causes the disks to not align with the fault domain of the virtual machine.'})  # fmt: skip
    os_type: Optional[str] = field(default=None, metadata={"description": "The operating system type."})
    property_updates_in_progress: Optional[str] = field(default=None, metadata={'description': 'Properties of the disk for which update is pending.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={"description": "The disk provisioning state."})
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Policy for controlling export on the disk.'})  # fmt: skip
    purchase_plan: Optional[AzurePurchasePlan] = field(default=None, metadata={'description': 'Used for establishing the purchase context of any 3rd party artifact through marketplace.'})  # fmt: skip
    disk_security_profile: Optional[AzureDiskSecurityProfile] = field(default=None, metadata={'description': 'Contains the security related information for the resource.'})  # fmt: skip
    share_info: Optional[List[str]] = field(default=None, metadata={'description': 'Details of the list of all vms that have the disk attached. Maxshares should be set to a value greater than one for disks to allow attaching them to multiple vms.'})  # fmt: skip
    disk_sku: Optional[AzureDiskSku] = field(default=None, metadata={'description': 'The disks sku name. Can be standard_lrs, premium_lrs, standardssd_lrs, ultrassd_lrs, premium_zrs, standardssd_zrs, or premiumv2_lrs.'})  # fmt: skip
    supported_capabilities: Optional[AzureSupportedCapabilities] = field(default=None, metadata={'description': 'List of supported capabilities persisted on the disk resource for vm use.'})  # fmt: skip
    supports_hibernation: Optional[bool] = field(default=None, metadata={'description': 'Indicates the os on a disk supports hibernation.'})  # fmt: skip
    tier: Optional[str] = field(default=None, metadata={'description': 'Performance tier of the disk (e. G, p4, s10) as described here: https://azure. Microsoft. Com/en-us/pricing/details/managed-disks/. Does not apply to ultra disks.'})  # fmt: skip
    time_created: Optional[datetime] = field(default=None, metadata={'description': 'The time when the disk was created.'})  # fmt: skip
    unique_id: Optional[str] = field(default=None, metadata={"description": "Unique guid identifying the resource."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location"})
    tier_name: Optional[str] = field(default=None, metadata={"description": "The sku tier."})

    @classmethod
    def collect_resources(
        cls: Type[AzureResourceType], builder: GraphBuilder, **kwargs: Any
    ) -> List[AzureResourceType]:
        log.debug(f"[Azure:{builder.subscription.id}] Collecting {cls.__name__} with ({kwargs})")
        if spec := cls.api_spec:
            items = builder.client.list(spec, **kwargs)
            collected = cls.collect(items, builder)
            # Create additional custom disk sizes for disks with Ultra SSD or Premium SSD v2 types
            AzureDiskType.create_unique_disk_sizes(collected, builder)
            if builder.config.collect_usage_metrics:
                try:
                    cls.collect_usage_metrics(builder, collected)
                except Exception as e:
                    log.warning(f"Failed to collect usage metrics for {cls.__name__}: {e}")
            return collected
        return []

    @classmethod
    def collect_usage_metrics(
        cls: Type[AzureResource], builder: GraphBuilder, collected_resources: List[AzureResourceType]
    ) -> None:
        volumes = {volume.id: volume for volume in collected_resources if volume}
        queries = []
        start = builder.metrics_start
        now = builder.created_at
        delta = builder.metrics_delta
        for volume_id in volumes:
            queries.extend(
                [
                    AzureMetricQuery.create(
                        metric_name=metric_name,
                        metric_namespace="microsoft.compute/disks",
                        instance_id=volume_id,
                        aggregation=("average",),
                        ref_id=volume_id,
                        unit="BytesPerSecond",
                    )
                    for metric_name in ["Composite Disk Write Bytes/sec", "Composite Disk Read Bytes/sec"]
                ]
            )
            queries.extend(
                [
                    AzureMetricQuery.create(
                        metric_name=metric_name,
                        metric_namespace="microsoft.compute/disks",
                        instance_id=volume_id,
                        aggregation=("average",),
                        ref_id=volume_id,
                        unit="CountPerSecond",
                    )
                    for metric_name in ["Composite Disk Write Operations/sec", "Composite Disk Read Operations/sec"]
                ]
            )

        metric_normalizers = {
            "Composite Disk Write Bytes/sec": MetricNormalization(
                metric_name=MetricName.VolumeWrite, unit=MetricUnit.Bytes
            ),
            "Composite Disk Read Bytes/sec": MetricNormalization(
                metric_name=MetricName.VolumeRead, unit=MetricUnit.Bytes
            ),
            "Composite Disk Write Operations/sec": MetricNormalization(
                metric_name=MetricName.VolumeWrite, unit=MetricUnit.IOPS
            ),
            "Composite Disk Read Operations/sec": MetricNormalization(
                metric_name=MetricName.VolumeRead, unit=MetricUnit.IOPS
            ),
        }

        metric_result = AzureMetricData.query_for(builder, queries, start, now, delta)

        update_resource_metrics(volumes, metric_result, metric_normalizers)

    @staticmethod
    def _get_nearest_size(size: int, lookup_map: Dict[int, Any]) -> int:
        list_sizes = list(lookup_map.keys())
        target = size

        return min(list_sizes, key=lambda x: abs(x - target))

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (volume_type := self.volume_type) and (location := self.location) and (size := self.volume_size):
            # Connect disk types, excluding "UltraSSD_LRS" and "PremiumV2_LRS"
            if volume_type not in ["UltraSSD_LRS", "PremiumV2_LRS"]:
                tier_name = self.tier_name

                if volume_type.startswith("StandardSSD"):
                    tier_map = storage_sku_tier_by_size.get("StandardSSD")
                elif tier_name:
                    tier_map = storage_sku_tier_by_size.get(tier_name)
                else:
                    return

                if tier_map:
                    tier = tier_map.get(self._get_nearest_size(size, tier_map))
                    builder.add_edge(
                        self,
                        edge_type=EdgeType.default,
                        clazz=AzureDiskType,
                        location=location,
                        volume_type=volume_type,
                        tier=tier,
                    )
            else:
                if (iops := self.volume_iops) and (throughput := self.volume_throughput):
                    # Create edge between Ultra(or Premium V2) SSD disk type and disk
                    builder.add_edge(
                        self,
                        edge_type=EdgeType.default,
                        clazz=AzureDiskType,
                        location=location,
                        volume_type=volume_type,
                        volume_size=size,
                        volume_throughput=throughput,
                        volume_iops=iops,
                    )
        if disk_id := self.id:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureDiskAccess, id=disk_id)
        if (disk_encryption := self.disk_encryption) and (disk_en_set_id := disk_encryption.disk_encryption_set_id):
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureDiskEncryptionSet, id=disk_en_set_id)


@define(eq=False, slots=False)
class AzureDiskAccessPrivateEndpointConnection:
    kind: ClassVar[str] = "azure_disk_access_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "private_endpoint": S("properties", "privateEndpoint", "id"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "Private endpoint connection id."})
    name: Optional[str] = field(default=None, metadata={"description": "Private endpoint connection name."})
    private_endpoint: Optional[str] = field(default=None, metadata={"description": "The private endpoint resource."})
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Private endpoint connection type."})


@define(eq=False, slots=False)
class AzureDiskAccess(AzureResource):
    kind: ClassVar[str] = "azure_disk_access"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-01-02",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/diskAccesses",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("time_created"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzureDiskAccessPrivateEndpointConnection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "time_created": S("properties", "timeCreated"),
    }
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The complex type of the extended location.'})  # fmt: skip
    private_endpoint_connections: Optional[List[AzureDiskAccessPrivateEndpointConnection]] = field(default=None, metadata={'description': 'A readonly collection of private endpoint connections created on the disk. Currently only one endpoint connection is supported.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The disk access resource provisioning state.'})  # fmt: skip
    time_created: Optional[datetime] = field(default=None, metadata={'description': 'The time when the disk access was created.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureEncryptionSetIdentity:
    kind: ClassVar[str] = "azure_encryption_set_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The object id of the managed identity resource. This will be sent to the rp from arm via the x-ms-identity-principal-id header in the put request if the resource has a systemassigned(implicit) identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id of the managed identity resource. This will be sent to the rp from arm via the x-ms-client-tenant-id header in the put request if the resource has a systemassigned(implicit) identity.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of managed identity used by the diskencryptionset. Only systemassigned is supported for new creations. Disk encryption sets can be updated with identity type none during migration of subscription to a new azure active directory tenant; it will cause the encrypted resources to lose access to the keys.'})  # fmt: skip
    user_assigned_identities: Optional[Dict[str, AzurePrincipalidClientid]] = field(default=None, metadata={'description': 'The list of user identities associated with the virtual machine. The user identity dictionary key references will be arm resource ids in the form: /subscriptions/{subscriptionid}/resourcegroups/{resourcegroupname}/providers/microsoft. Managedidentity/userassignedidentities/{identityname}.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureKeyForDiskEncryptionSet:
    kind: ClassVar[str] = "azure_key_for_disk_encryption_set"
    mapping: ClassVar[Dict[str, Bender]] = {"key_url": S("keyUrl"), "source_vault": S("sourceVault", "id")}
    key_url: Optional[str] = field(default=None, metadata={'description': 'Fully versioned key url pointing to a key in keyvault. Version segment of the url is required regardless of rotationtolatestkeyversionenabled value.'})  # fmt: skip
    source_vault: Optional[str] = field(default=None, metadata={'description': 'The vault id is an azure resource manager resource id in the form /subscriptions/{subscriptionid}/resourcegroups/{resourcegroupname}/providers/microsoft. Keyvault/vaults/{vaultname}.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApiErrorBase:
    kind: ClassVar[str] = "azure_api_error_base"
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("code"), "message": S("message"), "target": S("target")}
    code: Optional[str] = field(default=None, metadata={"description": "The error code."})
    message: Optional[str] = field(default=None, metadata={"description": "The error message."})
    target: Optional[str] = field(default=None, metadata={"description": "The target of the particular error."})


@define(eq=False, slots=False)
class AzureInnerError:
    kind: ClassVar[str] = "azure_inner_error"
    mapping: ClassVar[Dict[str, Bender]] = {"errordetail": S("errordetail"), "exceptiontype": S("exceptiontype")}
    errordetail: Optional[str] = field(default=None, metadata={'description': 'The internal error message or exception dump.'})  # fmt: skip
    exceptiontype: Optional[str] = field(default=None, metadata={"description": "The exception type."})


@define(eq=False, slots=False)
class AzureApiError:
    kind: ClassVar[str] = "azure_api_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "details": S("details") >> ForallBend(AzureApiErrorBase.mapping),
        "innererror": S("innererror") >> Bend(AzureInnerError.mapping),
        "message": S("message"),
        "target": S("target"),
    }
    code: Optional[str] = field(default=None, metadata={"description": "The error code."})
    details: Optional[List[AzureApiErrorBase]] = field(default=None, metadata={"description": "The api error details."})
    innererror: Optional[AzureInnerError] = field(default=None, metadata={"description": "Inner error details."})
    message: Optional[str] = field(default=None, metadata={"description": "The error message."})
    target: Optional[str] = field(default=None, metadata={"description": "The target of the particular error."})


@define(eq=False, slots=False)
class AzureDiskEncryptionSet(AzureResource):
    kind: ClassVar[str] = "azure_disk_encryption_set"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-01-02",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/diskEncryptionSets",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "active_key": S("properties", "activeKey") >> Bend(AzureKeyForDiskEncryptionSet.mapping),
        "auto_key_rotation_error": S("properties", "autoKeyRotationError") >> Bend(AzureApiError.mapping),
        "encryption_type": S("properties", "encryptionType"),
        "federated_client_id": S("properties", "federatedClientId"),
        "encryption_set_identity": S("identity") >> Bend(AzureEncryptionSetIdentity.mapping),
        "last_key_rotation_timestamp": S("properties", "lastKeyRotationTimestamp"),
        "previous_keys": S("properties", "previousKeys") >> ForallBend(AzureKeyForDiskEncryptionSet.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "rotation_to_latest_key_version_enabled": S("properties", "rotationToLatestKeyVersionEnabled"),
    }
    active_key: Optional[AzureKeyForDiskEncryptionSet] = field(default=None, metadata={'description': 'Key vault key url to be used for server side encryption of managed disks and snapshots.'})  # fmt: skip
    auto_key_rotation_error: Optional[AzureApiError] = field(default=None, metadata={"description": "Api error."})
    encryption_type: Optional[str] = field(default=None, metadata={'description': 'The type of key used to encrypt the data of the disk.'})  # fmt: skip
    federated_client_id: Optional[str] = field(default=None, metadata={'description': 'Multi-tenant application client id to access key vault in a different tenant. Setting the value to none will clear the property.'})  # fmt: skip
    encryption_set_identity: Optional[AzureEncryptionSetIdentity] = field(default=None, metadata={'description': 'The managed identity for the disk encryption set. It should be given permission on the key vault before it can be used to encrypt disks.'})  # fmt: skip
    last_key_rotation_timestamp: Optional[datetime] = field(default=None, metadata={'description': 'The time when the active key of this disk encryption set was updated.'})  # fmt: skip
    previous_keys: Optional[List[AzureKeyForDiskEncryptionSet]] = field(default=None, metadata={'description': 'A readonly collection of key vault keys previously used by this disk encryption set while a key rotation is in progress. It will be empty if there is no ongoing key rotation.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The disk encryption set provisioning state.'})  # fmt: skip
    rotation_to_latest_key_version_enabled: Optional[bool] = field(default=None, metadata={'description': 'Set this flag to true to enable auto-updating of this disk encryption set to the latest key version.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSharingProfileGroup:
    kind: ClassVar[str] = "azure_sharing_profile_group"
    mapping: ClassVar[Dict[str, Bender]] = {"ids": S("ids"), "type": S("type")}
    ids: Optional[List[str]] = field(default=None, metadata={'description': 'A list of subscription/tenant ids the gallery is aimed to be shared to.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'This property allows you to specify the type of sharing group. Possible values are: **subscriptions** **aadtenants**.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCommunityGalleryInfo:
    kind: ClassVar[str] = "azure_community_gallery_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "community_gallery_enabled": S("communityGalleryEnabled"),
        "eula": S("eula"),
        "public_name_prefix": S("publicNamePrefix"),
        "public_names": S("publicNames"),
        "publisher_contact": S("publisherContact"),
        "publisher_uri": S("publisherUri"),
    }
    community_gallery_enabled: Optional[bool] = field(default=None, metadata={'description': 'Contains info about whether community gallery sharing is enabled.'})  # fmt: skip
    eula: Optional[str] = field(default=None, metadata={'description': 'End-user license agreement for community gallery image.'})  # fmt: skip
    public_name_prefix: Optional[str] = field(default=None, metadata={'description': 'The prefix of the gallery name that will be displayed publicly. Visible to all users.'})  # fmt: skip
    public_names: Optional[List[str]] = field(
        default=None, metadata={"description": "Community gallery public name list."}
    )
    publisher_contact: Optional[str] = field(default=None, metadata={'description': 'Community gallery publisher support email. The email address of the publisher. Visible to all users.'})  # fmt: skip
    publisher_uri: Optional[str] = field(default=None, metadata={'description': 'The link to the publisher website. Visible to all users.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSharingProfile:
    kind: ClassVar[str] = "azure_sharing_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "community_gallery_info": S("communityGalleryInfo") >> Bend(AzureCommunityGalleryInfo.mapping),
        "groups": S("groups") >> ForallBend(AzureSharingProfileGroup.mapping),
        "permissions": S("permissions"),
    }
    community_gallery_info: Optional[AzureCommunityGalleryInfo] = field(default=None, metadata={'description': 'Information of community gallery if current gallery is shared to community.'})  # fmt: skip
    groups: Optional[List[AzureSharingProfileGroup]] = field(default=None, metadata={'description': 'A list of sharing profile groups.'})  # fmt: skip
    permissions: Optional[str] = field(default=None, metadata={'description': 'This property allows you to specify the permission of sharing gallery. Possible values are: **private** **groups** **community**.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRegionalSharingStatus:
    kind: ClassVar[str] = "azure_regional_sharing_status"
    mapping: ClassVar[Dict[str, Bender]] = {"details": S("details"), "region": S("region"), "state": S("state")}
    details: Optional[str] = field(default=None, metadata={'description': 'Details of gallery regional sharing failure.'})  # fmt: skip
    region: Optional[str] = field(default=None, metadata={"description": "Region name."})
    state: Optional[str] = field(default=None, metadata={'description': 'The sharing state of the gallery, which only appears in the response.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSharingStatus:
    kind: ClassVar[str] = "azure_sharing_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aggregated_state": S("aggregatedState"),
        "summary": S("summary") >> ForallBend(AzureRegionalSharingStatus.mapping),
    }
    aggregated_state: Optional[str] = field(default=None, metadata={'description': 'The sharing state of the gallery, which only appears in the response.'})  # fmt: skip
    summary: Optional[List[AzureRegionalSharingStatus]] = field(default=None, metadata={'description': 'Summary of all regional sharing status.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureGallery(AzureResource):
    kind: ClassVar[str] = "azure_gallery"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2022-03-03",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/galleries",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "description": S("properties", "description"),
        "identifier": S("properties", "identifier", "uniqueName"),
        "provisioning_state": S("properties", "provisioningState"),
        "sharing_profile": S("properties", "sharingProfile") >> Bend(AzureSharingProfile.mapping),
        "sharing_status": S("properties", "sharingStatus") >> Bend(AzureSharingStatus.mapping),
        "soft_delete_policy": S("properties", "softDeletePolicy", "isSoftDeleteEnabled"),
    }
    description: Optional[str] = field(default=None, metadata={'description': 'The description of this shared image gallery resource. This property is updatable.'})  # fmt: skip
    identifier: Optional[str] = field(default=None, metadata={"description": "Describes the gallery unique name."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state, which only appears in the response.'})  # fmt: skip
    sharing_profile: Optional[AzureSharingProfile] = field(default=None, metadata={'description': 'Profile for gallery sharing to subscription or tenant.'})  # fmt: skip
    sharing_status: Optional[AzureSharingStatus] = field(default=None, metadata={'description': 'Sharing status of current gallery.'})  # fmt: skip
    soft_delete_policy: Optional[bool] = field(default=None, metadata={'description': 'Contains information about the soft deletion policy of the gallery.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureImageDisk:
    kind: ClassVar[str] = "azure_image_disk"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blob_uri": S("blobUri"),
        "caching": S("caching"),
        "disk_encryption_set": S("diskEncryptionSet") >> Bend(AzureSubResource.mapping),
        "disk_size_gb": S("diskSizeGB"),
        "managed_disk": S("managedDisk", "id"),
        "snapshot": S("snapshot", "id"),
        "storage_account_type": S("storageAccountType"),
    }
    blob_uri: Optional[str] = field(default=None, metadata={"description": "The virtual hard disk."})
    caching: Optional[str] = field(default=None, metadata={'description': 'Specifies the caching requirements. Possible values are: **none,** **readonly,** **readwrite. ** the default values are: **none for standard storage. Readonly for premium storage. **.'})  # fmt: skip
    disk_encryption_set: Optional[AzureSubResource] = field(default=None, metadata={'description': 'Describes the parameter of customer managed disk encryption set resource id that can be specified for disk. **note:** the disk encryption set resource id can only be specified for managed disk. Please refer https://aka. Ms/mdssewithcmkoverview for more details.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'Specifies the size of empty data disks in gigabytes. This element can be used to overwrite the name of the disk in a virtual machine image. This value cannot be larger than 1023 gb.'})  # fmt: skip
    managed_disk: Optional[str] = field(default=None, metadata={"description": ""})
    snapshot: Optional[str] = field(default=None, metadata={"description": ""})
    storage_account_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the storage account type for the managed disk. Managed os disk storage account type can only be set when you create the scale set. Note: ultrassd_lrs can only be used with data disks. It cannot be used with os disk. Standard_lrs uses standard hdd. Standardssd_lrs uses standard ssd. Premium_lrs uses premium ssd. Ultrassd_lrs uses ultra disk. Premium_zrs uses premium ssd zone redundant storage. Standardssd_zrs uses standard ssd zone redundant storage. For more information regarding disks supported for windows virtual machines, refer to https://docs. Microsoft. Com/azure/virtual-machines/windows/disks-types and, for linux virtual machines, refer to https://docs. Microsoft. Com/azure/virtual-machines/linux/disks-types.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureImageOSDisk(AzureImageDisk):
    kind: ClassVar[str] = "azure_image_os_disk"
    mapping: ClassVar[Dict[str, Bender]] = AzureImageDisk.mapping | {"os_state": S("osState"), "os_type": S("osType")}
    os_state: Optional[str] = field(default=None, metadata={'description': 'The os state. For managed images, use generalized.'})  # fmt: skip
    os_type: Optional[str] = field(default=None, metadata={'description': 'This property allows you to specify the type of the os that is included in the disk if creating a vm from a custom image. Possible values are: **windows,** **linux. **.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureImageStorageProfile:
    kind: ClassVar[str] = "azure_image_storage_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_disks": S("dataDisks", default=[]) >> ForallBend(S("lun")),
        "os_disk": S("osDisk") >> Bend(AzureImageOSDisk.mapping),
        "zone_resilient": S("zoneResilient"),
    }
    data_disks: Optional[List[int]] = field(default=None, metadata={'description': 'Specifies the parameters that are used to add a data disk to a virtual machine. For more information about disks, see [about disks and vhds for azure virtual machines](https://docs. Microsoft. Com/azure/virtual-machines/managed-disks-overview).'})  # fmt: skip
    os_disk: Optional[AzureImageOSDisk] = field(default=None, metadata={'description': 'Describes an operating system disk.'})  # fmt: skip
    zone_resilient: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether an image is zone resilient or not. Default is false. Zone resilient images can be created only in regions that provide zone redundant storage (zrs).'})  # fmt: skip


@define(eq=False, slots=False)
class AzureImage(AzureResource):
    kind: ClassVar[str] = "azure_image"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/images",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "hyper_v_generation": S("properties", "hyperVGeneration"),
        "provisioning_state": S("properties", "provisioningState"),
        "source_virtual_machine": S("properties", "sourceVirtualMachine", "id"),
        "storage_profile": S("properties", "storageProfile") >> Bend(AzureImageStorageProfile.mapping),
    }
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The complex type of the extended location.'})  # fmt: skip
    hyper_v_generation: Optional[str] = field(default=None, metadata={'description': 'Specifies the hypervgeneration type.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={"description": "The provisioning state."})
    source_virtual_machine: Optional[str] = field(default=None, metadata={"description": ""})
    storage_profile: Optional[AzureImageStorageProfile] = field(default=None, metadata={'description': 'Describes a storage profile.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSubResourceWithColocationStatus(AzureSubResource):
    kind: ClassVar[str] = "azure_sub_resource_with_colocation_status"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "colocation_status": S("colocationStatus") >> Bend(AzureInstanceViewStatus.mapping)
    }
    colocation_status: Optional[AzureInstanceViewStatus] = field(default=None, metadata={'description': 'Instance view status.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVmSizes:
    kind: ClassVar[str] = "azure_vm_sizes"
    mapping: ClassVar[Dict[str, Bender]] = {"vm_sizes": S("vmSizes")}
    vm_sizes: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies possible sizes of virtual machines that can be created in the proximity placement group.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureProximityPlacementGroup(AzureResource):
    kind: ClassVar[str] = "azure_proximity_placement_group"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/proximityPlacementGroups",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_virtual_machine_scale_set"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "availability_sets": S("properties", "availabilitySets")
        >> ForallBend(AzureSubResourceWithColocationStatus.mapping),
        "colocation_status": S("properties", "colocationStatus") >> Bend(AzureInstanceViewStatus.mapping),
        "intent": S("properties", "intent") >> Bend(AzureVmSizes.mapping),
        "proximity_placement_group_type": S("properties", "proximityPlacementGroupType"),
        "virtual_machine_scale_sets": S("properties", "virtualMachineScaleSets")
        >> ForallBend(AzureSubResourceWithColocationStatus.mapping),
        "virtual_machines_status": S("properties", "virtualMachines")
        >> ForallBend(AzureSubResourceWithColocationStatus.mapping),
    }
    availability_sets: Optional[List[AzureSubResourceWithColocationStatus]] = field(default=None, metadata={'description': 'A list of references to all availability sets in the proximity placement group.'})  # fmt: skip
    colocation_status: Optional[AzureInstanceViewStatus] = field(default=None, metadata={'description': 'Instance view status.'})  # fmt: skip
    intent: Optional[AzureVmSizes] = field(default=None, metadata={'description': 'Specifies the user intent of the proximity placement group.'})  # fmt: skip
    proximity_placement_group_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the type of the proximity placement group. Possible values are: **standard** : co-locate resources within an azure region or availability zone. **ultra** : for future use.'})  # fmt: skip
    virtual_machine_scale_sets: Optional[List[AzureSubResourceWithColocationStatus]] = field(default=None, metadata={'description': 'A list of references to all virtual machine scale sets in the proximity placement group.'})  # fmt: skip
    virtual_machines_status: Optional[List[AzureSubResourceWithColocationStatus]] = field(default=None, metadata={'description': 'A list of references to all virtual machines in the proximity placement group.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vmsss := self.virtual_machine_scale_sets:
            for vmss in vmsss:
                if vmss_id := vmss.id:
                    builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureVirtualMachineScaleSet, id=vmss_id)


@define(eq=False, slots=False)
class AzureResourceSkuCapacity:
    kind: ClassVar[str] = "azure_resource_sku_capacity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default": S("default"),
        "maximum": S("maximum"),
        "minimum": S("minimum"),
        "scale_type": S("scaleType"),
    }
    default: Optional[int] = field(default=None, metadata={"description": "The default capacity."})
    maximum: Optional[int] = field(default=None, metadata={"description": "The maximum capacity that can be set."})
    minimum: Optional[int] = field(default=None, metadata={"description": "The minimum capacity."})
    scale_type: Optional[str] = field(default=None, metadata={"description": "The scale type applicable to the sku."})


@define(eq=False, slots=False)
class AzureResourceSkuCapabilities:
    kind: ClassVar[str] = "azure_resource_sku_capabilities"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None, metadata={"description": "An invariant to describe the feature."})
    value: Optional[str] = field(default=None, metadata={'description': 'An invariant if the feature is measured by quantity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceSkuZoneDetails:
    kind: ClassVar[str] = "azure_resource_sku_zone_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capabilities": S("capabilities") >> ForallBend(AzureResourceSkuCapabilities.mapping),
        "name": S("name"),
    }
    capabilities: Optional[List[AzureResourceSkuCapabilities]] = field(default=None, metadata={'description': 'A list of capabilities that are available for the sku in the specified list of zones.'})  # fmt: skip
    name: Optional[List[str]] = field(default=None, metadata={'description': 'The set of zones that the sku is available in with the specified capabilities.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceSkuLocationInfo:
    kind: ClassVar[str] = "azure_resource_sku_location_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "extended_locations": S("extendedLocations"),
        "location": S("location"),
        "type": S("type"),
        "zone_details": S("zoneDetails") >> ForallBend(AzureResourceSkuZoneDetails.mapping),
        "zones": S("zones"),
    }
    extended_locations: Optional[List[str]] = field(default=None, metadata={'description': 'The names of extended locations.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Location of the sku."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of the extended location."})
    zone_details: Optional[List[AzureResourceSkuZoneDetails]] = field(default=None, metadata={'description': 'Details of capabilities available to a sku in specific zones.'})  # fmt: skip
    zones: Optional[List[str]] = field(default=None, metadata={'description': 'List of availability zones where the sku is supported.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceSkuCosts:
    kind: ClassVar[str] = "azure_resource_sku_costs"
    mapping: ClassVar[Dict[str, Bender]] = {
        "extended_unit": S("extendedUnit"),
        "meter_id": S("meterID"),
        "quantity": S("quantity"),
    }
    extended_unit: Optional[str] = field(default=None, metadata={'description': 'An invariant to show the extended unit.'})  # fmt: skip
    meter_id: Optional[str] = field(default=None, metadata={"description": "Used for querying price from commerce."})
    quantity: Optional[int] = field(default=None, metadata={'description': 'The multiplier is needed to extend the base metered cost.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceSkuRestrictionInfo:
    kind: ClassVar[str] = "azure_resource_sku_restriction_info"
    mapping: ClassVar[Dict[str, Bender]] = {"locations": S("locations"), "zones": S("zones")}
    locations: Optional[List[str]] = field(
        default=None, metadata={"description": "Locations where the sku is restricted."}
    )
    zones: Optional[List[str]] = field(default=None, metadata={'description': 'List of availability zones where the sku is restricted.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceSkuRestrictions:
    kind: ClassVar[str] = "azure_resource_sku_restrictions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "reason_code": S("reasonCode"),
        "restriction_info": S("restrictionInfo") >> Bend(AzureResourceSkuRestrictionInfo.mapping),
        "type": S("type"),
        "values": S("values"),
    }
    reason_code: Optional[str] = field(default=None, metadata={"description": "The reason for restriction."})
    restriction_info: Optional[AzureResourceSkuRestrictionInfo] = field(default=None, metadata={'description': 'Describes an available compute sku restriction information.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of restrictions."})
    values: Optional[List[str]] = field(default=None, metadata={'description': 'The value of restrictions. If the restriction type is set to location. This would be different locations where the sku is restricted.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceSku(AzureResource):
    kind: ClassVar[str] = "azure_resource_sku"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2021-07-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/skus",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": K(None),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "api_versions": S("apiVersions"),
        "capabilities": S("capabilities") >> ForallBend(AzureResourceSkuCapabilities.mapping),
        "sku_capacity": S("capacity") >> Bend(AzureResourceSkuCapacity.mapping),
        "costs": S("costs") >> ForallBend(AzureResourceSkuCosts.mapping),
        "family": S("family"),
        "sku_kind": S("kind"),
        "location_info": S("locationInfo") >> ForallBend(AzureResourceSkuLocationInfo.mapping),
        "locations": S("locations"),
        "resource_type": S("resourceType"),
        "restrictions": S("restrictions") >> ForallBend(AzureResourceSkuRestrictions.mapping),
        "sku_size": S("size"),
        "sku_tier": S("tier"),
    }
    api_versions: Optional[List[str]] = field(default=None, metadata={'description': 'The api versions that support this sku.'})  # fmt: skip
    capabilities: Optional[List[AzureResourceSkuCapabilities]] = field(default=None, metadata={'description': 'A name value pair to describe the capability.'})  # fmt: skip
    sku_capacity: Optional[AzureResourceSkuCapacity] = field(default=None, metadata={'description': 'Describes scaling information of a sku.'})  # fmt: skip
    costs: Optional[List[AzureResourceSkuCosts]] = field(default=None, metadata={'description': 'Metadata for retrieving price info.'})  # fmt: skip
    family: Optional[str] = field(default=None, metadata={"description": "The family of this particular sku."})
    sku_kind: Optional[str] = field(default=None, metadata={'description': 'The kind of resources that are supported in this sku.'})  # fmt: skip
    location_info: Optional[List[AzureResourceSkuLocationInfo]] = field(default=None, metadata={'description': 'A list of locations and availability zones in those locations where the sku is available.'})  # fmt: skip
    locations: Optional[List[str]] = field(default=None, metadata={'description': 'The set of locations that the sku is available.'})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={'description': 'The type of resource the sku applies to.'})  # fmt: skip
    restrictions: Optional[List[AzureResourceSkuRestrictions]] = field(default=None, metadata={'description': 'The restrictions because of which sku cannot be used. This is empty if there are no restrictions.'})  # fmt: skip
    sku_size: Optional[str] = field(default=None, metadata={"description": "The size of the sku."})
    sku_tier: Optional[str] = field(default=None, metadata={'description': 'Specifies the tier of virtual machines in a scale set. Possible values: **standard** **basic**.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorePointCollectionSourceProperties:
    kind: ClassVar[str] = "azure_restore_point_collection_source_properties"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "location": S("location")}
    id: Optional[str] = field(default=None, metadata={'description': 'Resource id of the source resource used to create this restore point collection.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'Location of the source resource used to create this restore point collection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureProxyResource:
    kind: ClassVar[str] = "azure_proxy_resource"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name"), "type": S("type")}
    id: Optional[str] = field(default=None, metadata={"description": "Resource id."})
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureVMSizeProperties:
    kind: ClassVar[str] = "azure_vm_size_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "v_cp_us_available": S("vCPUsAvailable"),
        "v_cp_us_per_core": S("vCPUsPerCore"),
    }
    v_cp_us_available: Optional[int] = field(default=None, metadata={'description': 'Specifies the number of vcpus available for the vm. When this property is not specified in the request body the default behavior is to set it to the value of vcpus available for that vm size exposed in api response of [list all available virtual machine sizes in a region](https://docs. Microsoft. Com/en-us/rest/api/compute/resource-skus/list).'})  # fmt: skip
    v_cp_us_per_core: Optional[int] = field(default=None, metadata={'description': 'Specifies the vcpu to physical core ratio. When this property is not specified in the request body the default behavior is set to the value of vcpuspercore for the vm size exposed in api response of [list all available virtual machine sizes in a region](https://docs. Microsoft. Com/en-us/rest/api/compute/resource-skus/list). **setting this property to 1 also means that hyper-threading is disabled. **.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureHardwareProfile:
    kind: ClassVar[str] = "azure_hardware_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "vm_size": S("vmSize"),
        "vm_size_properties": S("vmSizeProperties") >> Bend(AzureVMSizeProperties.mapping),
    }
    vm_size: Optional[str] = field(default=None, metadata={'description': 'Specifies the size of the virtual machine. The enum data type is currently deprecated and will be removed by december 23rd 2023. The recommended way to get the list of available sizes is using these apis: [list all available virtual machine sizes in an availability set](https://docs. Microsoft. Com/rest/api/compute/availabilitysets/listavailablesizes), [list all available virtual machine sizes in a region]( https://docs. Microsoft. Com/rest/api/compute/resourceskus/list), [list all available virtual machine sizes for resizing](https://docs. Microsoft. Com/rest/api/compute/virtualmachines/listavailablesizes). For more information about virtual machine sizes, see [sizes for virtual machines](https://docs. Microsoft. Com/azure/virtual-machines/sizes). The available vm sizes depend on region and availability set.'})  # fmt: skip
    vm_size_properties: Optional[AzureVMSizeProperties] = field(default=None, metadata={'description': 'Specifies vm size property settings on the virtual machine.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureKeyVaultSecretReference:
    kind: ClassVar[str] = "azure_key_vault_secret_reference"
    mapping: ClassVar[Dict[str, Bender]] = {"secret_url": S("secretUrl"), "source_vault": S("sourceVault", "id")}
    secret_url: Optional[str] = field(default=None, metadata={'description': 'The url referencing a secret in a key vault.'})  # fmt: skip
    source_vault: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureKeyVaultKeyReference:
    kind: ClassVar[str] = "azure_key_vault_key_reference"
    mapping: ClassVar[Dict[str, Bender]] = {"key_url": S("keyUrl"), "source_vault": S("sourceVault", "id")}
    key_url: Optional[str] = field(default=None, metadata={'description': 'The url referencing a key encryption key in key vault.'})  # fmt: skip
    source_vault: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureDiskEncryptionSettings:
    kind: ClassVar[str] = "azure_disk_encryption_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_encryption_key": S("diskEncryptionKey") >> Bend(AzureKeyVaultSecretReference.mapping),
        "enabled": S("enabled"),
        "key_encryption_key": S("keyEncryptionKey") >> Bend(AzureKeyVaultKeyReference.mapping),
    }
    disk_encryption_key: Optional[AzureKeyVaultSecretReference] = field(default=None, metadata={'description': 'Describes a reference to key vault secret.'})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether disk encryption should be enabled on the virtual machine.'})  # fmt: skip
    key_encryption_key: Optional[AzureKeyVaultKeyReference] = field(default=None, metadata={'description': 'Describes a reference to key vault key.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVMDiskSecurityProfile:
    kind: ClassVar[str] = "azure_vm_disk_security_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_encryption_set": S("diskEncryptionSet") >> Bend(AzureSubResource.mapping),
        "security_encryption_type": S("securityEncryptionType"),
    }
    disk_encryption_set: Optional[AzureSubResource] = field(default=None, metadata={'description': 'Describes the parameter of customer managed disk encryption set resource id that can be specified for disk. **note:** the disk encryption set resource id can only be specified for managed disk. Please refer https://aka. Ms/mdssewithcmkoverview for more details.'})  # fmt: skip
    security_encryption_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the encryptiontype of the managed disk. It is set to diskwithvmgueststate for encryption of the managed disk along with vmgueststate blob, and vmgueststateonly for encryption of just the vmgueststate blob. **note:** it can be set for only confidential vms.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedDiskParameters(AzureSubResource):
    kind: ClassVar[str] = "azure_managed_disk_parameters"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "disk_encryption_set": S("diskEncryptionSet") >> Bend(AzureSubResource.mapping),
        "disk_parameters_security_profile": S("securityProfile") >> Bend(AzureVMDiskSecurityProfile.mapping),
        "storage_account_type": S("storageAccountType"),
    }
    disk_encryption_set: Optional[AzureSubResource] = field(default=None, metadata={'description': 'Describes the parameter of customer managed disk encryption set resource id that can be specified for disk. **note:** the disk encryption set resource id can only be specified for managed disk. Please refer https://aka. Ms/mdssewithcmkoverview for more details.'})  # fmt: skip
    disk_parameters_security_profile: Optional[AzureVMDiskSecurityProfile] = field(default=None, metadata={'description': 'Specifies the security profile settings for the managed disk. **note:** it can only be set for confidential vms.'})  # fmt: skip
    storage_account_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the storage account type for the managed disk. Managed os disk storage account type can only be set when you create the scale set. Note: ultrassd_lrs can only be used with data disks. It cannot be used with os disk. Standard_lrs uses standard hdd. Standardssd_lrs uses standard ssd. Premium_lrs uses premium ssd. Ultrassd_lrs uses ultra disk. Premium_zrs uses premium ssd zone redundant storage. Standardssd_zrs uses standard ssd zone redundant storage. For more information regarding disks supported for windows virtual machines, refer to https://docs. Microsoft. Com/azure/virtual-machines/windows/disks-types and, for linux virtual machines, refer to https://docs. Microsoft. Com/azure/virtual-machines/linux/disks-types.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSubResourceReadOnly:
    kind: ClassVar[str] = "azure_sub_resource_read_only"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id")}
    id: Optional[str] = field(default=None, metadata={"description": "Resource id."})


@define(eq=False, slots=False)
class AzureRestorePointEncryption:
    kind: ClassVar[str] = "azure_restore_point_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_encryption_set": S("diskEncryptionSet") >> Bend(AzureSubResource.mapping),
        "type": S("type"),
    }
    disk_encryption_set: Optional[AzureSubResource] = field(default=None, metadata={'description': 'Describes the parameter of customer managed disk encryption set resource id that can be specified for disk. **note:** the disk encryption set resource id can only be specified for managed disk. Please refer https://aka. Ms/mdssewithcmkoverview for more details.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of key used to encrypt the data of the disk restore point.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDiskRestorePointAttributes(AzureSubResourceReadOnly):
    kind: ClassVar[str] = "azure_disk_restore_point_attributes"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResourceReadOnly.mapping | {
        "encryption": S("encryption") >> Bend(AzureRestorePointEncryption.mapping),
        "source_disk_restore_point": S("sourceDiskRestorePoint", "id"),
    }
    encryption: Optional[AzureRestorePointEncryption] = field(default=None, metadata={'description': 'Encryption at rest settings for disk restore point. It is an optional property that can be specified in the input while creating a restore point.'})  # fmt: skip
    source_disk_restore_point: Optional[str] = field(default=None, metadata={'description': 'The api entity reference.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorePointSourceVMOSDisk:
    kind: ClassVar[str] = "azure_restore_point_source_vmos_disk"
    mapping: ClassVar[Dict[str, Bender]] = {
        "caching": S("caching"),
        "disk_restore_point": S("diskRestorePoint") >> Bend(AzureDiskRestorePointAttributes.mapping),
        "disk_size_gb": S("diskSizeGB"),
        "encryption_settings": S("encryptionSettings") >> Bend(AzureDiskEncryptionSettings.mapping),
        "managed_disk": S("managedDisk") >> Bend(AzureManagedDiskParameters.mapping),
        "name": S("name"),
        "os_type": S("osType"),
        "write_accelerator_enabled": S("writeAcceleratorEnabled"),
    }
    caching: Optional[str] = field(default=None, metadata={'description': 'Specifies the caching requirements. Possible values are: **none,** **readonly,** **readwrite. ** the default values are: **none for standard storage. Readonly for premium storage**.'})  # fmt: skip
    disk_restore_point: Optional[AzureDiskRestorePointAttributes] = field(default=None, metadata={'description': 'Disk restore point details.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={"description": "Gets the disk size in gb."})
    encryption_settings: Optional[AzureDiskEncryptionSettings] = field(default=None, metadata={'description': 'Describes a encryption settings for a disk.'})  # fmt: skip
    managed_disk: Optional[AzureManagedDiskParameters] = field(default=None, metadata={'description': 'The parameters of a managed disk.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Gets the disk name."})
    os_type: Optional[str] = field(default=None, metadata={"description": "Gets the operating system type."})
    write_accelerator_enabled: Optional[bool] = field(default=None, metadata={'description': 'Shows true if the disk is write-accelerator enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorePointSourceVMDataDisk:
    kind: ClassVar[str] = "azure_restore_point_source_vm_data_disk"
    mapping: ClassVar[Dict[str, Bender]] = {
        "caching": S("caching"),
        "disk_restore_point": S("diskRestorePoint") >> Bend(AzureDiskRestorePointAttributes.mapping),
        "disk_size_gb": S("diskSizeGB"),
        "lun": S("lun"),
        "managed_disk": S("managedDisk") >> Bend(AzureManagedDiskParameters.mapping),
        "name": S("name"),
        "write_accelerator_enabled": S("writeAcceleratorEnabled"),
    }
    caching: Optional[str] = field(default=None, metadata={'description': 'Specifies the caching requirements. Possible values are: **none,** **readonly,** **readwrite. ** the default values are: **none for standard storage. Readonly for premium storage**.'})  # fmt: skip
    disk_restore_point: Optional[AzureDiskRestorePointAttributes] = field(default=None, metadata={'description': 'Disk restore point details.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'Gets the initial disk size in gb for blank data disks, and the new desired size for existing os and data disks.'})  # fmt: skip
    lun: Optional[int] = field(default=None, metadata={"description": "Gets the logical unit number."})
    managed_disk: Optional[AzureManagedDiskParameters] = field(default=None, metadata={'description': 'The parameters of a managed disk.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Gets the disk name."})
    write_accelerator_enabled: Optional[bool] = field(default=None, metadata={'description': 'Shows true if the disk is write-accelerator enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorePointSourceVMStorageProfile:
    kind: ClassVar[str] = "azure_restore_point_source_vm_storage_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_disks": S("dataDisks") >> ForallBend(AzureRestorePointSourceVMDataDisk.mapping),
        "os_disk": S("osDisk") >> Bend(AzureRestorePointSourceVMOSDisk.mapping),
    }
    data_disks: Optional[List[AzureRestorePointSourceVMDataDisk]] = field(default=None, metadata={'description': 'Gets the data disks of the vm captured at the time of the restore point creation.'})  # fmt: skip
    os_disk: Optional[AzureRestorePointSourceVMOSDisk] = field(default=None, metadata={'description': 'Describes an operating system disk.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAdditionalUnattendContent:
    kind: ClassVar[str] = "azure_additional_unattend_content"
    mapping: ClassVar[Dict[str, Bender]] = {
        "component_name": S("componentName"),
        "content": S("content"),
        "pass_name": S("passName"),
        "setting_name": S("settingName"),
    }
    component_name: Optional[str] = field(default=None, metadata={'description': 'The component name. Currently, the only allowable value is microsoft-windows-shell-setup.'})  # fmt: skip
    content: Optional[str] = field(default=None, metadata={'description': 'Specifies the xml formatted content that is added to the unattend. Xml file for the specified path and component. The xml must be less than 4kb and must include the root element for the setting or feature that is being inserted.'})  # fmt: skip
    pass_name: Optional[str] = field(default=None, metadata={'description': 'The pass name. Currently, the only allowable value is oobesystem.'})  # fmt: skip
    setting_name: Optional[str] = field(default=None, metadata={'description': 'Specifies the name of the setting to which the content applies. Possible values are: firstlogoncommands and autologon.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWindowsVMGuestPatchAutomaticByPlatformSettings:
    kind: ClassVar[str] = "azure_windows_vm_guest_patch_automatic_by_platform_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bypass_platform_safety_checks_on_user_schedule": S("bypassPlatformSafetyChecksOnUserSchedule"),
        "reboot_setting": S("rebootSetting"),
    }
    bypass_platform_safety_checks_on_user_schedule: Optional[bool] = field(default=None, metadata={'description': 'Enables customer to schedule patching without accidental upgrades.'})  # fmt: skip
    reboot_setting: Optional[str] = field(default=None, metadata={'description': 'Specifies the reboot setting for all automaticbyplatform patch installation operations.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePatchSettings:
    kind: ClassVar[str] = "azure_patch_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "assessment_mode": S("assessmentMode"),
        "automatic_by_platform_settings": S("automaticByPlatformSettings")
        >> Bend(AzureWindowsVMGuestPatchAutomaticByPlatformSettings.mapping),
        "enable_hotpatching": S("enableHotpatching"),
        "patch_mode": S("patchMode"),
    }
    assessment_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the mode of vm guest patch assessment for the iaas virtual machine. Possible values are: **imagedefault** - you control the timing of patch assessments on a virtual machine. **automaticbyplatform** - the platform will trigger periodic patch assessments. The property provisionvmagent must be true.'})  # fmt: skip
    automatic_by_platform_settings: Optional[AzureWindowsVMGuestPatchAutomaticByPlatformSettings] = field(default=None, metadata={'description': 'Specifies additional settings to be applied when patch mode automaticbyplatform is selected in windows patch settings.'})  # fmt: skip
    enable_hotpatching: Optional[bool] = field(default=None, metadata={'description': 'Enables customers to patch their azure vms without requiring a reboot. For enablehotpatching, the provisionvmagent must be set to true and patchmode must be set to automaticbyplatform.'})  # fmt: skip
    patch_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the mode of vm guest patching to iaas virtual machine or virtual machines associated to virtual machine scale set with orchestrationmode as flexible. Possible values are: **manual** - you control the application of patches to a virtual machine. You do this by applying patches manually inside the vm. In this mode, automatic updates are disabled; the property windowsconfiguration. Enableautomaticupdates must be false **automaticbyos** - the virtual machine will automatically be updated by the os. The property windowsconfiguration. Enableautomaticupdates must be true. **automaticbyplatform** - the virtual machine will automatically updated by the platform. The properties provisionvmagent and windowsconfiguration. Enableautomaticupdates must be true.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWinRMListener:
    kind: ClassVar[str] = "azure_win_rm_listener"
    mapping: ClassVar[Dict[str, Bender]] = {"certificate_url": S("certificateUrl"), "protocol": S("protocol")}
    certificate_url: Optional[str] = field(default=None, metadata={'description': 'This is the url of a certificate that has been uploaded to key vault as a secret. For adding a secret to the key vault, see [add a key or secret to the key vault](https://docs. Microsoft. Com/azure/key-vault/key-vault-get-started/#add). In this case, your certificate needs to be the base64 encoding of the following json object which is encoded in utf-8: { data : <base64-encoded-certificate> , datatype : pfx , password : <pfx-file-password> } to install certificates on a virtual machine it is recommended to use the [azure key vault virtual machine extension for linux](https://docs. Microsoft. Com/azure/virtual-machines/extensions/key-vault-linux) or the [azure key vault virtual machine extension for windows](https://docs. Microsoft. Com/azure/virtual-machines/extensions/key-vault-windows).'})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={'description': 'Specifies the protocol of winrm listener. Possible values are: **http,** **https. **.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWinRMConfiguration:
    kind: ClassVar[str] = "azure_win_rm_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"listeners": S("listeners") >> ForallBend(AzureWinRMListener.mapping)}
    listeners: Optional[List[AzureWinRMListener]] = field(default=None, metadata={'description': 'The list of windows remote management listeners.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureWindowsConfiguration:
    kind: ClassVar[str] = "azure_windows_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "additional_unattend_content": S("additionalUnattendContent")
        >> ForallBend(AzureAdditionalUnattendContent.mapping),
        "enable_automatic_updates": S("enableAutomaticUpdates"),
        "enable_vm_agent_platform_updates": S("enableVMAgentPlatformUpdates"),
        "patch_settings": S("patchSettings") >> Bend(AzurePatchSettings.mapping),
        "provision_vm_agent": S("provisionVMAgent"),
        "time_zone": S("timeZone"),
        "win_rm": S("winRM") >> Bend(AzureWinRMConfiguration.mapping),
    }
    additional_unattend_content: Optional[List[AzureAdditionalUnattendContent]] = field(default=None, metadata={'description': 'Specifies additional base-64 encoded xml formatted information that can be included in the unattend. Xml file, which is used by windows setup.'})  # fmt: skip
    enable_automatic_updates: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether automatic updates is enabled for the windows virtual machine. Default value is true. For virtual machine scale sets, this property can be updated and updates will take effect on os reprovisioning.'})  # fmt: skip
    enable_vm_agent_platform_updates: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether vmagent platform updates is enabled for the windows virtual machine. Default value is false.'})  # fmt: skip
    patch_settings: Optional[AzurePatchSettings] = field(default=None, metadata={'description': 'Specifies settings related to vm guest patching on windows.'})  # fmt: skip
    provision_vm_agent: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether virtual machine agent should be provisioned on the virtual machine. When this property is not specified in the request body, it is set to true by default. This will ensure that vm agent is installed on the vm so that extensions can be added to the vm later.'})  # fmt: skip
    time_zone: Optional[str] = field(default=None, metadata={'description': 'Specifies the time zone of the virtual machine. E. G. Pacific standard time. Possible values can be [timezoneinfo. Id](https://docs. Microsoft. Com/dotnet/api/system. Timezoneinfo. Id?#system_timezoneinfo_id) value from time zones returned by [timezoneinfo. Getsystemtimezones](https://docs. Microsoft. Com/dotnet/api/system. Timezoneinfo. Getsystemtimezones).'})  # fmt: skip
    win_rm: Optional[AzureWinRMConfiguration] = field(default=None, metadata={'description': 'Describes windows remote management configuration of the vm.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSshPublicKey:
    kind: ClassVar[str] = "azure_ssh_public_key"
    mapping: ClassVar[Dict[str, Bender]] = {"key_data": S("keyData"), "path": S("path")}
    key_data: Optional[str] = field(default=None, metadata={'description': 'Ssh public key certificate used to authenticate with the vm through ssh. The key needs to be at least 2048-bit and in ssh-rsa format. For creating ssh keys, see [create ssh keys on linux and mac for linux vms in azure]https://docs. Microsoft. Com/azure/virtual-machines/linux/create-ssh-keys-detailed).'})  # fmt: skip
    path: Optional[str] = field(default=None, metadata={'description': 'Specifies the full path on the created vm where ssh public key is stored. If the file already exists, the specified key is appended to the file. Example: /home/user/. Ssh/authorized_keys.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSshConfiguration:
    kind: ClassVar[str] = "azure_ssh_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"public_keys": S("publicKeys") >> ForallBend(AzureSshPublicKey.mapping)}
    public_keys: Optional[List[AzureSshPublicKey]] = field(default=None, metadata={'description': 'The list of ssh public keys used to authenticate with linux based vms.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLinuxVMGuestPatchAutomaticByPlatformSettings:
    kind: ClassVar[str] = "azure_linux_vm_guest_patch_automatic_by_platform_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bypass_platform_safety_checks_on_user_schedule": S("bypassPlatformSafetyChecksOnUserSchedule"),
        "reboot_setting": S("rebootSetting"),
    }
    bypass_platform_safety_checks_on_user_schedule: Optional[bool] = field(default=None, metadata={'description': 'Enables customer to schedule patching without accidental upgrades.'})  # fmt: skip
    reboot_setting: Optional[str] = field(default=None, metadata={'description': 'Specifies the reboot setting for all automaticbyplatform patch installation operations.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLinuxPatchSettings:
    kind: ClassVar[str] = "azure_linux_patch_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "assessment_mode": S("assessmentMode"),
        "automatic_by_platform_settings": S("automaticByPlatformSettings")
        >> Bend(AzureLinuxVMGuestPatchAutomaticByPlatformSettings.mapping),
        "patch_mode": S("patchMode"),
    }
    assessment_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the mode of vm guest patch assessment for the iaas virtual machine. Possible values are: **imagedefault** - you control the timing of patch assessments on a virtual machine. **automaticbyplatform** - the platform will trigger periodic patch assessments. The property provisionvmagent must be true.'})  # fmt: skip
    automatic_by_platform_settings: Optional[AzureLinuxVMGuestPatchAutomaticByPlatformSettings] = field(default=None, metadata={'description': 'Specifies additional settings to be applied when patch mode automaticbyplatform is selected in linux patch settings.'})  # fmt: skip
    patch_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the mode of vm guest patching to iaas virtual machine or virtual machines associated to virtual machine scale set with orchestrationmode as flexible. Possible values are: **imagedefault** - the virtual machine s default patching configuration is used. **automaticbyplatform** - the virtual machine will be automatically updated by the platform. The property provisionvmagent must be true.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLinuxConfiguration:
    kind: ClassVar[str] = "azure_linux_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disable_password_authentication": S("disablePasswordAuthentication"),
        "enable_vm_agent_platform_updates": S("enableVMAgentPlatformUpdates"),
        "patch_settings": S("patchSettings") >> Bend(AzureLinuxPatchSettings.mapping),
        "provision_vm_agent": S("provisionVMAgent"),
        "ssh": S("ssh") >> Bend(AzureSshConfiguration.mapping),
    }
    disable_password_authentication: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether password authentication should be disabled.'})  # fmt: skip
    enable_vm_agent_platform_updates: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether vmagent platform updates is enabled for the linux virtual machine. Default value is false.'})  # fmt: skip
    patch_settings: Optional[AzureLinuxPatchSettings] = field(default=None, metadata={'description': 'Specifies settings related to vm guest patching on linux.'})  # fmt: skip
    provision_vm_agent: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether virtual machine agent should be provisioned on the virtual machine. When this property is not specified in the request body, default behavior is to set it to true. This will ensure that vm agent is installed on the vm so that extensions can be added to the vm later.'})  # fmt: skip
    ssh: Optional[AzureSshConfiguration] = field(default=None, metadata={'description': 'Ssh configuration for linux based vms running on azure.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVaultCertificate:
    kind: ClassVar[str] = "azure_vault_certificate"
    mapping: ClassVar[Dict[str, Bender]] = {
        "certificate_store": S("certificateStore"),
        "certificate_url": S("certificateUrl"),
    }
    certificate_store: Optional[str] = field(default=None, metadata={'description': 'For windows vms, specifies the certificate store on the virtual machine to which the certificate should be added. The specified certificate store is implicitly in the localmachine account. For linux vms, the certificate file is placed under the /var/lib/waagent directory, with the file name &lt;uppercasethumbprint&gt;. Crt for the x509 certificate file and &lt;uppercasethumbprint&gt;. Prv for private key. Both of these files are. Pem formatted.'})  # fmt: skip
    certificate_url: Optional[str] = field(default=None, metadata={'description': 'This is the url of a certificate that has been uploaded to key vault as a secret. For adding a secret to the key vault, see [add a key or secret to the key vault](https://docs. Microsoft. Com/azure/key-vault/key-vault-get-started/#add). In this case, your certificate needs to be it is the base64 encoding of the following json object which is encoded in utf-8: { data : <base64-encoded-certificate> , datatype : pfx , password : <pfx-file-password> } to install certificates on a virtual machine it is recommended to use the [azure key vault virtual machine extension for linux](https://docs. Microsoft. Com/azure/virtual-machines/extensions/key-vault-linux) or the [azure key vault virtual machine extension for windows](https://docs. Microsoft. Com/azure/virtual-machines/extensions/key-vault-windows).'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVaultSecretGroup:
    kind: ClassVar[str] = "azure_vault_secret_group"
    mapping: ClassVar[Dict[str, Bender]] = {
        "source_vault": S("sourceVault", "id"),
        "vault_certificates": S("vaultCertificates") >> ForallBend(AzureVaultCertificate.mapping),
    }
    source_vault: Optional[str] = field(default=None, metadata={"description": ""})
    vault_certificates: Optional[List[AzureVaultCertificate]] = field(default=None, metadata={'description': 'The list of key vault references in sourcevault which contain certificates.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureOSProfile:
    kind: ClassVar[str] = "azure_os_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "admin_password": S("adminPassword"),
        "admin_username": S("adminUsername"),
        "allow_extension_operations": S("allowExtensionOperations"),
        "computer_name": S("computerName"),
        "custom_data": S("customData"),
        "linux_configuration": S("linuxConfiguration") >> Bend(AzureLinuxConfiguration.mapping),
        "require_guest_provision_signal": S("requireGuestProvisionSignal"),
        "secrets": S("secrets") >> ForallBend(AzureVaultSecretGroup.mapping),
        "windows_configuration": S("windowsConfiguration") >> Bend(AzureWindowsConfiguration.mapping),
    }
    admin_password: Optional[str] = field(default=None, metadata={'description': 'Specifies the password of the administrator account. **minimum-length (windows):** 8 characters **minimum-length (linux):** 6 characters **max-length (windows):** 123 characters **max-length (linux):** 72 characters **complexity requirements:** 3 out of 4 conditions below need to be fulfilled has lower characters has upper characters has a digit has a special character (regex match [\\w_]) **disallowed values:** abc@123 , p@$$w0rd , p@ssw0rd , p@ssword123 , pa$$word , pass@word1 , password! , password1 , password22 , iloveyou! for resetting the password, see [how to reset the remote desktop service or its login password in a windows vm](https://docs. Microsoft. Com/troubleshoot/azure/virtual-machines/reset-rdp) for resetting root password, see [manage users, ssh, and check or repair disks on azure linux vms using the vmaccess extension](https://docs. Microsoft. Com/troubleshoot/azure/virtual-machines/troubleshoot-ssh-connection).'})  # fmt: skip
    admin_username: Optional[str] = field(default=None, metadata={'description': 'Specifies the name of the administrator account. This property cannot be updated after the vm is created. **windows-only restriction:** cannot end in. **disallowed values:** administrator , admin , user , user1 , test , user2 , test1 , user3 , admin1 , 1 , 123 , a , actuser , adm , admin2 , aspnet , backup , console , david , guest , john , owner , root , server , sql , support , support_388945a0 , sys , test2 , test3 , user4 , user5. **minimum-length (linux):** 1 character **max-length (linux):** 64 characters **max-length (windows):** 20 characters.'})  # fmt: skip
    allow_extension_operations: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether extension operations should be allowed on the virtual machine. This may only be set to false when no extensions are present on the virtual machine.'})  # fmt: skip
    computer_name: Optional[str] = field(default=None, metadata={'description': 'Specifies the host os name of the virtual machine. This name cannot be updated after the vm is created. **max-length (windows):** 15 characters. **max-length (linux):** 64 characters. For naming conventions and restrictions see [azure infrastructure services implementation guidelines](https://docs. Microsoft. Com/azure/azure-resource-manager/management/resource-name-rules).'})  # fmt: skip
    custom_data: Optional[str] = field(default=None, metadata={'description': 'Specifies a base-64 encoded string of custom data. The base-64 encoded string is decoded to a binary array that is saved as a file on the virtual machine. The maximum length of the binary array is 65535 bytes. **note: do not pass any secrets or passwords in customdata property. ** this property cannot be updated after the vm is created. The property customdata is passed to the vm to be saved as a file, for more information see [custom data on azure vms](https://azure. Microsoft. Com/blog/custom-data-and-cloud-init-on-windows-azure/). For using cloud-init for your linux vm, see [using cloud-init to customize a linux vm during creation](https://docs. Microsoft. Com/azure/virtual-machines/linux/using-cloud-init).'})  # fmt: skip
    linux_configuration: Optional[AzureLinuxConfiguration] = field(default=None, metadata={'description': 'Specifies the linux operating system settings on the virtual machine. For a list of supported linux distributions, see [linux on azure-endorsed distributions](https://docs. Microsoft. Com/azure/virtual-machines/linux/endorsed-distros).'})  # fmt: skip
    require_guest_provision_signal: Optional[bool] = field(default=None, metadata={'description': 'Optional property which must either be set to true or omitted.'})  # fmt: skip
    secrets: Optional[List[AzureVaultSecretGroup]] = field(default=None, metadata={'description': 'Specifies set of certificates that should be installed onto the virtual machine. To install certificates on a virtual machine it is recommended to use the [azure key vault virtual machine extension for linux](https://docs. Microsoft. Com/azure/virtual-machines/extensions/key-vault-linux) or the [azure key vault virtual machine extension for windows](https://docs. Microsoft. Com/azure/virtual-machines/extensions/key-vault-windows).'})  # fmt: skip
    windows_configuration: Optional[AzureWindowsConfiguration] = field(default=None, metadata={'description': 'Specifies windows operating system settings on the virtual machine.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBootDiagnostics:
    kind: ClassVar[str] = "azure_boot_diagnostics"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "storage_uri": S("storageUri")}
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether boot diagnostics should be enabled on the virtual machine.'})  # fmt: skip
    storage_uri: Optional[str] = field(default=None, metadata={'description': 'Uri of the storage account to use for placing the console output and screenshot. If storageuri is not specified while enabling boot diagnostics, managed storage will be used.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDiagnosticsProfile:
    kind: ClassVar[str] = "azure_diagnostics_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "boot_diagnostics": S("bootDiagnostics") >> Bend(AzureBootDiagnostics.mapping)
    }
    boot_diagnostics: Optional[AzureBootDiagnostics] = field(default=None, metadata={'description': 'Boot diagnostics is a debugging feature which allows you to view console output and screenshot to diagnose vm status. You can easily view the output of your console log. Azure also enables you to see a screenshot of the vm from the hypervisor.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureUefiSettings:
    kind: ClassVar[str] = "azure_uefi_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "secure_boot_enabled": S("secureBootEnabled"),
        "v_tpm_enabled": S("vTpmEnabled"),
    }
    secure_boot_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether secure boot should be enabled on the virtual machine. Minimum api-version: 2020-12-01.'})  # fmt: skip
    v_tpm_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether vtpm should be enabled on the virtual machine. Minimum api-version: 2020-12-01.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSecurityProfile:
    kind: ClassVar[str] = "azure_security_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "encryption_at_host": S("encryptionAtHost"),
        "security_type": S("securityType"),
        "uefi_settings": S("uefiSettings") >> Bend(AzureUefiSettings.mapping),
    }
    encryption_at_host: Optional[bool] = field(default=None, metadata={'description': 'This property can be used by user in the request to enable or disable the host encryption for the virtual machine or virtual machine scale set. This will enable the encryption for all the disks including resource/temp disk at host itself. The default behavior is: the encryption at host will be disabled unless this property is set to true for the resource.'})  # fmt: skip
    security_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the securitytype of the virtual machine. It has to be set to any specified value to enable uefisettings. The default behavior is: uefisettings will not be enabled unless this property is set.'})  # fmt: skip
    uefi_settings: Optional[AzureUefiSettings] = field(default=None, metadata={'description': 'Specifies the security settings like secure boot and vtpm used while creating the virtual machine. Minimum api-version: 2020-12-01.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorePointSourceMetadata:
    kind: ClassVar[str] = "azure_restore_point_source_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "diagnostics_profile": S("diagnosticsProfile") >> Bend(AzureDiagnosticsProfile.mapping),
        "hardware_profile": S("hardwareProfile") >> Bend(AzureHardwareProfile.mapping),
        "hyper_v_generation": S("hyperVGeneration"),
        "license_type": S("licenseType"),
        "location": S("location"),
        "os_profile": S("osProfile") >> Bend(AzureOSProfile.mapping),
        "security_profile": S("securityProfile") >> Bend(AzureSecurityProfile.mapping),
        "storage_profile": S("storageProfile") >> Bend(AzureRestorePointSourceVMStorageProfile.mapping),
        "user_data": S("userData"),
        "vm_id": S("vmId"),
    }
    diagnostics_profile: Optional[AzureDiagnosticsProfile] = field(default=None, metadata={'description': 'Specifies the boot diagnostic settings state. Minimum api-version: 2015-06-15.'})  # fmt: skip
    hardware_profile: Optional[AzureHardwareProfile] = field(default=None, metadata={'description': 'Specifies the hardware settings for the virtual machine.'})  # fmt: skip
    hyper_v_generation: Optional[str] = field(default=None, metadata={'description': 'Specifies the hypervgeneration type.'})  # fmt: skip
    license_type: Optional[str] = field(default=None, metadata={'description': 'Gets the license type, which is for bring your own license scenario.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'Location of the vm from which the restore point was created.'})  # fmt: skip
    os_profile: Optional[AzureOSProfile] = field(default=None, metadata={'description': 'Specifies the operating system settings for the virtual machine. Some of the settings cannot be changed once vm is provisioned.'})  # fmt: skip
    security_profile: Optional[AzureSecurityProfile] = field(default=None, metadata={'description': 'Specifies the security profile settings for the virtual machine or virtual machine scale set.'})  # fmt: skip
    storage_profile: Optional[AzureRestorePointSourceVMStorageProfile] = field(default=None, metadata={'description': 'Describes the storage profile.'})  # fmt: skip
    user_data: Optional[str] = field(default=None, metadata={'description': 'Userdata associated with the source vm for which restore point is captured, which is a base-64 encoded value.'})  # fmt: skip
    vm_id: Optional[str] = field(default=None, metadata={"description": "Gets the virtual machine unique id."})


@define(eq=False, slots=False)
class AzureDiskRestorePointReplicationStatus:
    kind: ClassVar[str] = "azure_disk_restore_point_replication_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "completion_percent": S("completionPercent"),
        "status": S("status") >> Bend(AzureInstanceViewStatus.mapping),
    }
    completion_percent: Optional[int] = field(default=None, metadata={'description': 'Replication completion percentage.'})  # fmt: skip
    status: Optional[AzureInstanceViewStatus] = field(default=None, metadata={"description": "Instance view status."})


@define(eq=False, slots=False)
class AzureDiskRestorePointInstanceView:
    kind: ClassVar[str] = "azure_disk_restore_point_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "replication_status": S("replicationStatus") >> Bend(AzureDiskRestorePointReplicationStatus.mapping),
    }
    id: Optional[str] = field(default=None, metadata={"description": "Disk restore point id."})
    replication_status: Optional[AzureDiskRestorePointReplicationStatus] = field(default=None, metadata={'description': 'The instance view of a disk restore point.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorePointInstanceView:
    kind: ClassVar[str] = "azure_restore_point_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_restore_points": S("diskRestorePoints") >> ForallBend(AzureDiskRestorePointInstanceView.mapping),
        "statuses": S("statuses") >> ForallBend(AzureInstanceViewStatus.mapping),
    }
    disk_restore_points: Optional[List[AzureDiskRestorePointInstanceView]] = field(default=None, metadata={'description': 'The disk restore points information.'})  # fmt: skip
    statuses: Optional[List[AzureInstanceViewStatus]] = field(default=None, metadata={'description': 'The resource status information.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorePoint(AzureProxyResource):
    kind: ClassVar[str] = "azure_restore_point"
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "consistency_mode": S("properties", "consistencyMode"),
        "exclude_disks": S("properties") >> S("excludeDisks", default=[]) >> ForallBend(S("id")),
        "restore_point_instance_view": S("properties", "instanceView") >> Bend(AzureRestorePointInstanceView.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "source_metadata": S("properties", "sourceMetadata") >> Bend(AzureRestorePointSourceMetadata.mapping),
        "source_restore_point": S("properties", "sourceRestorePoint", "id"),
        "time_created": S("properties", "timeCreated"),
    }
    consistency_mode: Optional[str] = field(default=None, metadata={'description': 'Consistencymode of the restorepoint. Can be specified in the input while creating a restore point. For now, only crashconsistent is accepted as a valid input. Please refer to https://aka. Ms/restorepoints for more details.'})  # fmt: skip
    exclude_disks: Optional[List[str]] = field(default=None, metadata={'description': 'List of disk resource ids that the customer wishes to exclude from the restore point. If no disks are specified, all disks will be included.'})  # fmt: skip
    restore_point_instance_view: Optional[AzureRestorePointInstanceView] = field(default=None, metadata={'description': 'The instance view of a restore point.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Gets the provisioning state of the restore point.'})  # fmt: skip
    source_metadata: Optional[AzureRestorePointSourceMetadata] = field(default=None, metadata={'description': 'Describes the properties of the virtual machine for which the restore point was created. The properties provided are a subset and the snapshot of the overall virtual machine properties captured at the time of the restore point creation.'})  # fmt: skip
    source_restore_point: Optional[str] = field(default=None, metadata={"description": "The api entity reference."})
    time_created: Optional[datetime] = field(default=None, metadata={'description': 'Gets the creation time of the restore point.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorePointCollection(AzureResource):
    kind: ClassVar[str] = "azure_restore_point_collection"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/restorePointCollections",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_virtual_machine_base"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "provisioning_state": S("properties", "provisioningState"),
        "restore_point_collection_id": S("properties", "restorePointCollectionId"),
        "restore_points": S("properties", "restorePoints") >> ForallBend(AzureRestorePoint.mapping),
        "source": S("properties", "source") >> Bend(AzureRestorePointCollectionSourceProperties.mapping),
    }
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state of the restore point collection.'})  # fmt: skip
    restore_point_collection_id: Optional[str] = field(default=None, metadata={'description': 'The unique id of the restore point collection.'})  # fmt: skip
    restore_points: Optional[List[AzureRestorePoint]] = field(default=None, metadata={'description': 'A list containing all restore points created under this restore point collection.'})  # fmt: skip
    source: Optional[AzureRestorePointCollectionSourceProperties] = field(default=None, metadata={'description': 'The properties of the source resource that this restore point collection is created from.'})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (source_id := self.source) and (vm_id := source_id.id):
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureVirtualMachineBase, id=vm_id)


@define(eq=False, slots=False)
class AzureSnapshotSku:
    kind: ClassVar[str] = "azure_snapshot_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "tier": S("tier")}
    name: Optional[str] = field(default=None, metadata={"description": "The sku name."})
    tier: Optional[str] = field(default=None, metadata={"description": "The sku tier."})


@define(eq=False, slots=False)
class AzureCopyCompletionError:
    kind: ClassVar[str] = "azure_copy_completion_error"
    mapping: ClassVar[Dict[str, Bender]] = {"error_code": S("errorCode"), "error_message": S("errorMessage")}
    error_code: Optional[str] = field(default=None, metadata={'description': 'Indicates the error code if the background copy of a resource created via the copystart operation fails.'})  # fmt: skip
    error_message: Optional[str] = field(default=None, metadata={'description': 'Indicates the error message if the background copy of a resource created via the copystart operation fails.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSnapshot(AzureResource, BaseSnapshot):
    kind: ClassVar[str] = "azure_snapshot"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-01-02",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/snapshots",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_disk"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("properties", "timeCreated"),
        "completion_percent": S("properties", "completionPercent"),
        "copy_completion_error": S("properties", "copyCompletionError") >> Bend(AzureCopyCompletionError.mapping),
        "creation_data": S("properties", "creationData") >> Bend(AzureCreationData.mapping),
        "data_access_auth_mode": S("properties", "dataAccessAuthMode"),
        "disk_access_id": S("properties", "diskAccessId"),
        "disk_size_bytes": S("properties", "diskSizeBytes"),
        "disk_size_gb": S("properties", "diskSizeGB"),
        "disk_state": S("properties", "diskState"),
        "snapshot_encryption": S("properties", "encryption") >> Bend(AzureEncryption.mapping),
        "encryption_settings_collection": S("properties", "encryptionSettingsCollection")
        >> Bend(AzureEncryptionSettingsCollection.mapping),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "hyper_v_generation": S("properties", "hyperVGeneration"),
        "incremental": S("properties", "incremental"),
        "incremental_snapshot_family_id": S("properties", "incrementalSnapshotFamilyId"),
        "managed_by": S("managedBy"),
        "network_access_policy": S("properties", "networkAccessPolicy"),
        "os_type": S("properties", "osType"),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "purchase_plan": S("properties", "purchasePlan") >> Bend(AzurePurchasePlan.mapping),
        "snapshot_security_profile": S("properties", "securityProfile") >> Bend(AzureDiskSecurityProfile.mapping),
        "snapshot_sku": S("sku") >> Bend(AzureSnapshotSku.mapping),
        "supported_capabilities": S("properties", "supportedCapabilities") >> Bend(AzureSupportedCapabilities.mapping),
        "supports_hibernation": S("properties", "supportsHibernation"),
        "time_created": S("properties", "timeCreated"),
        "unique_id": S("properties", "uniqueId"),
        "snapshot_status": S("properties", "diskState"),
        "volume_id": S("id"),
        "volume_size": S("properties", "diskSizeGB"),
        "encrypted": S("properties", "encryptionSettingsCollection", "enabled"),
        "owner_id": S("properties", "creationData", "storageAccountId"),
    }
    completion_percent: Optional[float] = field(default=None, metadata={'description': 'Percentage complete for the background copy when a resource is created via the copystart operation.'})  # fmt: skip
    copy_completion_error: Optional[AzureCopyCompletionError] = field(default=None, metadata={'description': 'Indicates the error details if the background copy of a resource created via the copystart operation fails.'})  # fmt: skip
    creation_data: Optional[AzureCreationData] = field(default=None, metadata={'description': 'Data used when creating a disk.'})  # fmt: skip
    data_access_auth_mode: Optional[str] = field(default=None, metadata={'description': 'Additional authentication requirements when exporting or uploading to a disk or snapshot.'})  # fmt: skip
    disk_access_id: Optional[str] = field(default=None, metadata={'description': 'Arm id of the diskaccess resource for using private endpoints on disks.'})  # fmt: skip
    disk_size_bytes: Optional[int] = field(default=None, metadata={'description': 'The size of the disk in bytes. This field is read only.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'If creationdata. Createoption is empty, this field is mandatory and it indicates the size of the disk to create. If this field is present for updates or creation with other options, it indicates a resize. Resizes are only allowed if the disk is not attached to a running vm, and can only increase the disk s size.'})  # fmt: skip
    disk_state: Optional[str] = field(default=None, metadata={'description': 'This enumerates the possible state of the disk.'})  # fmt: skip
    snapshot_encryption: Optional[AzureEncryption] = field(default=None, metadata={'description': 'Encryption at rest settings for disk or snapshot.'})  # fmt: skip
    encryption_settings_collection: Optional[AzureEncryptionSettingsCollection] = field(default=None, metadata={'description': 'Encryption settings for disk or snapshot.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The complex type of the extended location.'})  # fmt: skip
    hyper_v_generation: Optional[str] = field(default=None, metadata={'description': 'The hypervisor generation of the virtual machine. Applicable to os disks only.'})  # fmt: skip
    incremental: Optional[bool] = field(default=None, metadata={'description': 'Whether a snapshot is incremental. Incremental snapshots on the same disk occupy less space than full snapshots and can be diffed.'})  # fmt: skip
    incremental_snapshot_family_id: Optional[str] = field(default=None, metadata={'description': 'Incremental snapshots for a disk share an incremental snapshot family id. The get page range diff api can only be called on incremental snapshots with the same family id.'})  # fmt: skip
    managed_by: Optional[str] = field(default=None, metadata={"description": "Unused. Always null."})
    network_access_policy: Optional[str] = field(default=None, metadata={'description': 'Policy for accessing the disk via network.'})  # fmt: skip
    os_type: Optional[str] = field(default=None, metadata={"description": "The operating system type."})
    provisioning_state: Optional[str] = field(default=None, metadata={"description": "The disk provisioning state."})
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Policy for controlling export on the disk.'})  # fmt: skip
    purchase_plan: Optional[AzurePurchasePlan] = field(default=None, metadata={'description': 'Used for establishing the purchase context of any 3rd party artifact through marketplace.'})  # fmt: skip
    snapshot_security_profile: Optional[AzureDiskSecurityProfile] = field(default=None, metadata={'description': 'Contains the security related information for the resource.'})  # fmt: skip
    snapshot_sku: Optional[AzureSnapshotSku] = field(default=None, metadata={'description': 'The snapshots sku name. Can be standard_lrs, premium_lrs, or standard_zrs. This is an optional parameter for incremental snapshot and the default behavior is the sku will be set to the same sku as the previous snapshot.'})  # fmt: skip
    supported_capabilities: Optional[AzureSupportedCapabilities] = field(default=None, metadata={'description': 'List of supported capabilities persisted on the disk resource for vm use.'})  # fmt: skip
    supports_hibernation: Optional[bool] = field(default=None, metadata={'description': 'Indicates the os on a snapshot supports hibernation.'})  # fmt: skip
    time_created: Optional[datetime] = field(default=None, metadata={'description': 'The time when the snapshot was created.'})  # fmt: skip
    unique_id: Optional[str] = field(default=None, metadata={"description": "Unique guid identifying the resource."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (disk_data := self.creation_data) and (disk_id := disk_data.source_resource_id):
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureDisk, id=disk_id)


@define(eq=False, slots=False)
class AzureSshPublicKeyResource(AzureResource):
    kind: ClassVar[str] = "azure_ssh_public_key_resource"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/sshPublicKeys",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "properties": S("properties", "publicKey"),
    }
    properties: Optional[str] = field(default=None, metadata={"description": "Properties of the ssh public key."})


@define(eq=False, slots=False)
class AzurePlan:
    kind: ClassVar[str] = "azure_plan"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "product": S("product"),
        "promotion_code": S("promotionCode"),
        "publisher": S("publisher"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The plan id."})
    product: Optional[str] = field(default=None, metadata={'description': 'Specifies the product of the image from the marketplace. This is the same value as offer under the imagereference element.'})  # fmt: skip
    promotion_code: Optional[str] = field(default=None, metadata={"description": "The promotion code."})
    publisher: Optional[str] = field(default=None, metadata={"description": "The publisher id."})


@define(eq=False, slots=False)
class AzureImageReference(AzureSubResource):
    kind: ClassVar[str] = "azure_image_reference"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "community_gallery_image_id": S("communityGalleryImageId"),
        "exact_version": S("exactVersion"),
        "offer": S("offer"),
        "publisher": S("publisher"),
        "shared_gallery_image_id": S("sharedGalleryImageId"),
        "image_reference_sku": S("sku"),
        "version": S("version"),
    }
    community_gallery_image_id: Optional[str] = field(default=None, metadata={'description': 'Specified the community gallery image unique id for vm deployment. This can be fetched from community gallery image get call.'})  # fmt: skip
    exact_version: Optional[str] = field(default=None, metadata={'description': 'Specifies in decimal numbers, the version of platform image or marketplace image used to create the virtual machine. This readonly field differs from version , only if the value specified in version field is latest.'})  # fmt: skip
    offer: Optional[str] = field(default=None, metadata={'description': 'Specifies the offer of the platform image or marketplace image used to create the virtual machine.'})  # fmt: skip
    publisher: Optional[str] = field(default=None, metadata={"description": "The image publisher."})
    shared_gallery_image_id: Optional[str] = field(default=None, metadata={'description': 'Specified the shared gallery image unique id for vm deployment. This can be fetched from shared gallery image get call.'})  # fmt: skip
    image_reference_sku: Optional[str] = field(default=None, metadata={"description": "The image sku."})
    version: Optional[str] = field(default=None, metadata={'description': 'Specifies the version of the platform image or marketplace image used to create the virtual machine. The allowed formats are major. Minor. Build or latest. Major, minor, and build are decimal numbers. Specify latest to use the latest version of an image available at deploy time. Even if you use latest , the vm image will not automatically update after deploy time even if a new version becomes available. Please do not use field version for gallery image deployment, gallery image should always use id field for deployment, to use latest version of gallery image, just set /subscriptions/{subscriptionid}/resourcegroups/{resourcegroupname}/providers/microsoft. Compute/galleries/{galleryname}/images/{imagename} in the id field without version input.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDiffDiskSettings:
    kind: ClassVar[str] = "azure_diff_disk_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"option": S("option"), "placement": S("placement")}
    option: Optional[str] = field(default=None, metadata={'description': 'Specifies the ephemeral disk option for operating system disk.'})  # fmt: skip
    placement: Optional[str] = field(default=None, metadata={'description': 'Specifies the ephemeral disk placement for operating system disk. This property can be used by user in the request to choose the location i. E, cache disk or resource disk space for ephemeral os disk provisioning. For more information on ephemeral os disk size requirements, please refer ephemeral os disk size requirements for windows vm at https://docs. Microsoft. Com/azure/virtual-machines/windows/ephemeral-os-disks#size-requirements and linux vm at https://docs. Microsoft. Com/azure/virtual-machines/linux/ephemeral-os-disks#size-requirements.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureOSDisk:
    kind: ClassVar[str] = "azure_os_disk"
    mapping: ClassVar[Dict[str, Bender]] = {
        "caching": S("caching"),
        "create_option": S("createOption"),
        "delete_option": S("deleteOption"),
        "diff_disk_settings": S("diffDiskSettings") >> Bend(AzureDiffDiskSettings.mapping),
        "disk_size_gb": S("diskSizeGB"),
        "encryption_settings": S("encryptionSettings") >> Bend(AzureDiskEncryptionSettings.mapping),
        "image": S("image", "uri"),
        "managed_disk": S("managedDisk") >> Bend(AzureManagedDiskParameters.mapping),
        "name": S("name"),
        "os_type": S("osType"),
        "vhd": S("vhd", "uri"),
        "write_accelerator_enabled": S("writeAcceleratorEnabled"),
    }
    caching: Optional[str] = field(default=None, metadata={'description': 'Specifies the caching requirements. Possible values are: **none,** **readonly,** **readwrite. ** the default values are: **none for standard storage. Readonly for premium storage**.'})  # fmt: skip
    create_option: Optional[str] = field(default=None, metadata={'description': 'Specifies how the virtual machine should be created. Possible values are: **attach. ** this value is used when you are using a specialized disk to create the virtual machine. **fromimage. ** this value is used when you are using an image to create the virtual machine. If you are using a platform image, you also use the imagereference element described above. If you are using a marketplace image, you also use the plan element previously described.'})  # fmt: skip
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specifies the behavior of the managed disk when the vm gets deleted, for example whether the managed disk is deleted or detached. Supported values are: **delete. ** if this value is used, the managed disk is deleted when vm gets deleted. **detach. ** if this value is used, the managed disk is retained after vm gets deleted. Minimum api-version: 2021-03-01.'})  # fmt: skip
    diff_disk_settings: Optional[AzureDiffDiskSettings] = field(default=None, metadata={'description': 'Describes the parameters of ephemeral disk settings that can be specified for operating system disk. **note:** the ephemeral disk settings can only be specified for managed disk.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'Specifies the size of an empty data disk in gigabytes. This element can be used to overwrite the size of the disk in a virtual machine image. The property disksizegb is the number of bytes x 1024^3 for the disk and the value cannot be larger than 1023.'})  # fmt: skip
    encryption_settings: Optional[AzureDiskEncryptionSettings] = field(default=None, metadata={'description': 'Describes a encryption settings for a disk.'})  # fmt: skip
    image: Optional[str] = field(default=None, metadata={"description": "Describes the uri of a disk."})
    managed_disk: Optional[AzureManagedDiskParameters] = field(default=None, metadata={'description': 'The parameters of a managed disk.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The disk name."})
    os_type: Optional[str] = field(default=None, metadata={'description': 'This property allows you to specify the type of the os that is included in the disk if creating a vm from user-image or a specialized vhd. Possible values are: **windows,** **linux. **.'})  # fmt: skip
    vhd: Optional[str] = field(default=None, metadata={"description": "Describes the uri of a disk."})
    write_accelerator_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether writeaccelerator should be enabled or disabled on the disk.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDataDisk:
    kind: ClassVar[str] = "azure_data_disk"
    mapping: ClassVar[Dict[str, Bender]] = {
        "caching": S("caching"),
        "create_option": S("createOption"),
        "delete_option": S("deleteOption"),
        "detach_option": S("detachOption"),
        "disk_iops_read_write": S("diskIOPSReadWrite"),
        "disk_m_bps_read_write": S("diskMBpsReadWrite"),
        "disk_size_gb": S("diskSizeGB"),
        "image": S("image", "uri"),
        "lun": S("lun"),
        "managed_disk": S("managedDisk") >> Bend(AzureManagedDiskParameters.mapping),
        "name": S("name"),
        "to_be_detached": S("toBeDetached"),
        "vhd": S("vhd", "uri"),
        "write_accelerator_enabled": S("writeAcceleratorEnabled"),
    }
    caching: Optional[str] = field(default=None, metadata={'description': 'Specifies the caching requirements. Possible values are: **none,** **readonly,** **readwrite. ** the default values are: **none for standard storage. Readonly for premium storage**.'})  # fmt: skip
    create_option: Optional[str] = field(default=None, metadata={'description': 'Specifies how the virtual machine should be created. Possible values are: **attach. ** this value is used when you are using a specialized disk to create the virtual machine. **fromimage. ** this value is used when you are using an image to create the virtual machine. If you are using a platform image, you also use the imagereference element described above. If you are using a marketplace image, you also use the plan element previously described.'})  # fmt: skip
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specifies the behavior of the managed disk when the vm gets deleted, for example whether the managed disk is deleted or detached. Supported values are: **delete. ** if this value is used, the managed disk is deleted when vm gets deleted. **detach. ** if this value is used, the managed disk is retained after vm gets deleted. Minimum api-version: 2021-03-01.'})  # fmt: skip
    detach_option: Optional[str] = field(default=None, metadata={'description': 'Specifies the detach behavior to be used while detaching a disk or which is already in the process of detachment from the virtual machine. Supported values are: **forcedetach. ** detachoption: **forcedetach** is applicable only for managed data disks. If a previous detachment attempt of the data disk did not complete due to an unexpected failure from the virtual machine and the disk is still not released then use force-detach as a last resort option to detach the disk forcibly from the vm. All writes might not have been flushed when using this detach behavior. **this feature is still in preview** mode and is not supported for virtualmachinescaleset. To force-detach a data disk update tobedetached to true along with setting detachoption: forcedetach.'})  # fmt: skip
    disk_iops_read_write: Optional[int] = field(default=None, metadata={'description': 'Specifies the read-write iops for the managed disk when storageaccounttype is ultrassd_lrs. Returned only for virtualmachine scaleset vm disks. Can be updated only via updates to the virtualmachine scale set.'})  # fmt: skip
    disk_m_bps_read_write: Optional[int] = field(default=None, metadata={'description': 'Specifies the bandwidth in mb per second for the managed disk when storageaccounttype is ultrassd_lrs. Returned only for virtualmachine scaleset vm disks. Can be updated only via updates to the virtualmachine scale set.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'Specifies the size of an empty data disk in gigabytes. This element can be used to overwrite the size of the disk in a virtual machine image. The property disksizegb is the number of bytes x 1024^3 for the disk and the value cannot be larger than 1023.'})  # fmt: skip
    image: Optional[str] = field(default=None, metadata={"description": "Describes the uri of a disk."})
    lun: Optional[int] = field(default=None, metadata={'description': 'Specifies the logical unit number of the data disk. This value is used to identify data disks within the vm and therefore must be unique for each data disk attached to a vm.'})  # fmt: skip
    managed_disk: Optional[AzureManagedDiskParameters] = field(default=None, metadata={'description': 'The parameters of a managed disk.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The disk name."})
    to_be_detached: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the data disk is in process of detachment from the virtualmachine/virtualmachinescaleset.'})  # fmt: skip
    vhd: Optional[str] = field(default=None, metadata={"description": "Describes the uri of a disk."})
    write_accelerator_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether writeaccelerator should be enabled or disabled on the disk.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStorageProfile:
    kind: ClassVar[str] = "azure_storage_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_disks": S("dataDisks") >> ForallBend(AzureDataDisk.mapping),
        "disk_controller_type": S("diskControllerType"),
        "image_reference": S("imageReference") >> Bend(AzureImageReference.mapping),
        "os_disk": S("osDisk") >> Bend(AzureOSDisk.mapping),
    }
    data_disks: Optional[List[AzureDataDisk]] = field(default=None, metadata={'description': 'Specifies the parameters that are used to add a data disk to a virtual machine. For more information about disks, see [about disks and vhds for azure virtual machines](https://docs. Microsoft. Com/azure/virtual-machines/managed-disks-overview).'})  # fmt: skip
    disk_controller_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the disk controller type configured for the vm and virtualmachinescaleset. This property is only supported for virtual machines whose operating system disk and vm sku supports generation 2 (https://docs. Microsoft. Com/en-us/azure/virtual-machines/generation-2), please check the hypervgenerations capability returned as part of vm sku capabilities in the response of microsoft. Compute skus api for the region contains v2 (https://docs. Microsoft. Com/rest/api/compute/resourceskus/list). For more information about disk controller types supported please refer to https://aka. Ms/azure-diskcontrollertypes.'})  # fmt: skip
    image_reference: Optional[AzureImageReference] = field(default=None, metadata={'description': 'Specifies information about the image to use. You can specify information about platform images, marketplace images, or virtual machine images. This element is required when you want to use a platform image, marketplace image, or virtual machine image, but is not used in other creation operations. Note: image reference publisher and offer can only be set when you create the scale set.'})  # fmt: skip
    os_disk: Optional[AzureOSDisk] = field(default=None, metadata={'description': 'Specifies information about the operating system disk used by the virtual machine. For more information about disks, see [about disks and vhds for azure virtual machines](https://docs. Microsoft. Com/azure/virtual-machines/managed-disks-overview).'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAdditionalCapabilities:
    kind: ClassVar[str] = "azure_additional_capabilities"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hibernation_enabled": S("hibernationEnabled"),
        "ultra_ssd_enabled": S("ultraSSDEnabled"),
    }
    hibernation_enabled: Optional[bool] = field(default=None, metadata={'description': 'The flag that enables or disables hibernation capability on the vm.'})  # fmt: skip
    ultra_ssd_enabled: Optional[bool] = field(default=None, metadata={'description': 'The flag that enables or disables a capability to have one or more managed data disks with ultrassd_lrs storage account type on the vm or vmss. Managed disks with storage account type ultrassd_lrs can be added to a virtual machine or virtual machine scale set only if this property is enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetworkInterfaceReference(AzureSubResource):
    kind: ClassVar[str] = "azure_network_interface_reference"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResource.mapping | {
        "delete_option": S("properties", "deleteOption"),
        "primary": S("properties", "primary"),
    }
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specify what happens to the network interface when the vm is deleted.'})  # fmt: skip
    primary: Optional[bool] = field(default=None, metadata={'description': 'Specifies the primary network interface in case the virtual machine has more than 1 network interface.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineNetworkInterfaceDnsSettingsConfiguration:
    kind: ClassVar[str] = "azure_virtual_machine_network_interface_dns_settings_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"dns_servers": S("dnsServers")}
    dns_servers: Optional[List[str]] = field(
        default=None, metadata={"description": "List of dns servers ip addresses."}
    )


@define(eq=False, slots=False)
class AzureVirtualMachineIpTag:
    kind: ClassVar[str] = "azure_virtual_machine_ip_tag"
    mapping: ClassVar[Dict[str, Bender]] = {"ip_tag_type": S("ipTagType"), "tag": S("tag")}
    ip_tag_type: Optional[str] = field(default=None, metadata={'description': 'Ip tag type. Example: firstpartyusage.'})  # fmt: skip
    tag: Optional[str] = field(default=None, metadata={'description': 'Ip tag associated with the public ip. Example: sql, storage etc.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePublicIPAddressSku:
    kind: ClassVar[str] = "azure_public_ip_address_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "tier": S("tier")}
    name: Optional[str] = field(default=None, metadata={"description": "Specify public ip sku name."})
    tier: Optional[str] = field(default=None, metadata={"description": "Specify public ip sku tier."})


@define(eq=False, slots=False)
class AzureVirtualMachinePublicIPAddressConfiguration:
    kind: ClassVar[str] = "azure_virtual_machine_public_ip_address_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "delete_option": S("properties", "deleteOption"),
        "dns_settings": S("properties", "dnsSettings", "domainNameLabel"),
        "idle_timeout_in_minutes": S("properties", "idleTimeoutInMinutes"),
        "ip_tags": S("properties", "ipTags") >> ForallBend(AzureVirtualMachineIpTag.mapping),
        "name": S("name"),
        "public_ip_address_version": S("properties", "publicIPAddressVersion"),
        "public_ip_allocation_method": S("properties", "publicIPAllocationMethod"),
        "public_ip_prefix": S("properties", "publicIPPrefix", "id"),
        "sku": S("sku") >> Bend(AzurePublicIPAddressSku.mapping),
    }
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specify what happens to the public ip address when the vm is deleted.'})  # fmt: skip
    dns_settings: Optional[str] = field(default=None, metadata={'description': 'Describes a virtual machines network configuration s dns settings.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The idle timeout of the public ip address.'})  # fmt: skip
    ip_tags: Optional[List[AzureVirtualMachineIpTag]] = field(default=None, metadata={'description': 'The list of ip tags associated with the public ip address.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The publicip address configuration name."})
    public_ip_address_version: Optional[str] = field(default=None, metadata={'description': 'Available from api-version 2019-07-01 onwards, it represents whether the specific ipconfiguration is ipv4 or ipv6. Default is taken as ipv4. Possible values are: ipv4 and ipv6.'})  # fmt: skip
    public_ip_allocation_method: Optional[str] = field(default=None, metadata={'description': 'Specify the public ip allocation type.'})  # fmt: skip
    public_ip_prefix: Optional[str] = field(default=None, metadata={"description": ""})
    sku: Optional[AzurePublicIPAddressSku] = field(default=None, metadata={'description': 'Describes the public ip sku. It can only be set with orchestrationmode as flexible.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineNetworkInterfaceIPConfiguration:
    kind: ClassVar[str] = "azure_virtual_machine_network_interface_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "application_gateway_backend_address_pools": S("properties")
        >> S("applicationGatewayBackendAddressPools", default=[])
        >> ForallBend(S("id")),
        "application_security_groups": S("properties")
        >> S("applicationSecurityGroups", default=[])
        >> ForallBend(S("id")),
        "load_balancer_backend_address_pools": S("properties")
        >> S("loadBalancerBackendAddressPools", default=[])
        >> ForallBend(S("id")),
        "name": S("name"),
        "primary": S("properties", "primary"),
        "private_ip_address_version": S("properties", "privateIPAddressVersion"),
        "public_ip_address_configuration": S("properties", "publicIPAddressConfiguration")
        >> Bend(AzureVirtualMachinePublicIPAddressConfiguration.mapping),
        "subnet": S("properties", "subnet", "id"),
    }
    application_gateway_backend_address_pools: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies an array of references to backend address pools of application gateways. A virtual machine can reference backend address pools of multiple application gateways. Multiple virtual machines cannot use the same application gateway.'})  # fmt: skip
    application_security_groups: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies an array of references to application security group.'})  # fmt: skip
    load_balancer_backend_address_pools: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies an array of references to backend address pools of load balancers. A virtual machine can reference backend address pools of one public and one internal load balancer. [multiple virtual machines cannot use the same basic sku load balancer].'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The ip configuration name."})
    primary: Optional[bool] = field(default=None, metadata={'description': 'Specifies the primary network interface in case the virtual machine has more than 1 network interface.'})  # fmt: skip
    private_ip_address_version: Optional[str] = field(default=None, metadata={'description': 'Available from api-version 2017-03-30 onwards, it represents whether the specific ipconfiguration is ipv4 or ipv6. Default is taken as ipv4. Possible values are: ipv4 and ipv6.'})  # fmt: skip
    public_ip_address_configuration: Optional[AzureVirtualMachinePublicIPAddressConfiguration] = field(default=None, metadata={'description': 'Describes a virtual machines ip configuration s publicipaddress configuration.'})  # fmt: skip
    subnet: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureVirtualMachineNetworkInterfaceConfiguration:
    kind: ClassVar[str] = "azure_virtual_machine_network_interface_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "delete_option": S("properties", "deleteOption"),
        "disable_tcp_state_tracking": S("properties", "disableTcpStateTracking"),
        "dns_settings": S("properties", "dnsSettings")
        >> Bend(AzureVirtualMachineNetworkInterfaceDnsSettingsConfiguration.mapping),
        "dscp_configuration": S("properties", "dscpConfiguration", "id"),
        "enable_accelerated_networking": S("properties", "enableAcceleratedNetworking"),
        "enable_fpga": S("properties", "enableFpga"),
        "enable_ip_forwarding": S("properties", "enableIPForwarding"),
        "ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzureVirtualMachineNetworkInterfaceIPConfiguration.mapping),
        "name": S("name"),
        "network_security_group": S("properties", "networkSecurityGroup", "id"),
        "primary": S("properties", "primary"),
    }
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specify what happens to the network interface when the vm is deleted.'})  # fmt: skip
    disable_tcp_state_tracking: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the network interface is disabled for tcp state tracking.'})  # fmt: skip
    dns_settings: Optional[AzureVirtualMachineNetworkInterfaceDnsSettingsConfiguration] = field(default=None, metadata={'description': 'Describes a virtual machines network configuration s dns settings.'})  # fmt: skip
    dscp_configuration: Optional[str] = field(default=None, metadata={"description": ""})
    enable_accelerated_networking: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the network interface is accelerated networking-enabled.'})  # fmt: skip
    enable_fpga: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the network interface is fpga networking-enabled.'})  # fmt: skip
    enable_ip_forwarding: Optional[bool] = field(default=None, metadata={'description': 'Whether ip forwarding enabled on this nic.'})  # fmt: skip
    ip_configurations: Optional[List[AzureVirtualMachineNetworkInterfaceIPConfiguration]] = field(default=None, metadata={'description': 'Specifies the ip configurations of the network interface.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The network interface configuration name."})
    network_security_group: Optional[str] = field(default=None, metadata={"description": ""})
    primary: Optional[bool] = field(default=None, metadata={'description': 'Specifies the primary network interface in case the virtual machine has more than 1 network interface.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineNetworkProfile:
    kind: ClassVar[str] = "azure_virtual_machine_network_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_api_version": S("networkApiVersion"),
        "network_interface_configurations": S("networkInterfaceConfigurations")
        >> ForallBend(AzureVirtualMachineNetworkInterfaceConfiguration.mapping),
        "network_interfaces": S("networkInterfaces") >> ForallBend(AzureNetworkInterfaceReference.mapping),
    }
    network_api_version: Optional[str] = field(default=None, metadata={'description': 'Specifies the microsoft. Network api version used when creating networking resources in the network interface configurations.'})  # fmt: skip
    network_interface_configurations: Optional[List[AzureVirtualMachineNetworkInterfaceConfiguration]] = field(default=None, metadata={'description': 'Specifies the networking configurations that will be used to create the virtual machine networking resources.'})  # fmt: skip
    network_interfaces: Optional[List[AzureNetworkInterfaceReference]] = field(default=None, metadata={'description': 'Specifies the list of resource ids for the network interfaces associated with the virtual machine.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineExtensionHandlerInstanceView:
    kind: ClassVar[str] = "azure_virtual_machine_extension_handler_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("status") >> Bend(AzureInstanceViewStatus.mapping),
        "type": S("type"),
        "type_handler_version": S("typeHandlerVersion"),
    }
    status: Optional[AzureInstanceViewStatus] = field(default=None, metadata={"description": "Instance view status."})
    type: Optional[str] = field(default=None, metadata={'description': 'Specifies the type of the extension; an example is customscriptextension.'})  # fmt: skip
    type_handler_version: Optional[str] = field(default=None, metadata={'description': 'Specifies the version of the script handler.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineAgentInstanceView:
    kind: ClassVar[str] = "azure_virtual_machine_agent_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "extension_handlers": S("extensionHandlers")
        >> ForallBend(AzureVirtualMachineExtensionHandlerInstanceView.mapping),
        "statuses": S("statuses") >> ForallBend(AzureInstanceViewStatus.mapping),
        "vm_agent_version": S("vmAgentVersion"),
    }
    extension_handlers: Optional[List[AzureVirtualMachineExtensionHandlerInstanceView]] = field(default=None, metadata={'description': 'The virtual machine extension handler instance view.'})  # fmt: skip
    statuses: Optional[List[AzureInstanceViewStatus]] = field(default=None, metadata={'description': 'The resource status information.'})  # fmt: skip
    vm_agent_version: Optional[str] = field(default=None, metadata={"description": "The vm agent full version."})


@define(eq=False, slots=False)
class AzureMaintenanceRedeployStatus:
    kind: ClassVar[str] = "azure_maintenance_redeploy_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "is_customer_initiated_maintenance_allowed": S("isCustomerInitiatedMaintenanceAllowed"),
        "last_operation_message": S("lastOperationMessage"),
        "last_operation_result_code": S("lastOperationResultCode"),
        "maintenance_window_end_time": S("maintenanceWindowEndTime"),
        "maintenance_window_start_time": S("maintenanceWindowStartTime"),
        "pre_maintenance_window_end_time": S("preMaintenanceWindowEndTime"),
        "pre_maintenance_window_start_time": S("preMaintenanceWindowStartTime"),
    }
    is_customer_initiated_maintenance_allowed: Optional[bool] = field(default=None, metadata={'description': 'True, if customer is allowed to perform maintenance.'})  # fmt: skip
    last_operation_message: Optional[str] = field(default=None, metadata={'description': 'Message returned for the last maintenance operation.'})  # fmt: skip
    last_operation_result_code: Optional[str] = field(default=None, metadata={'description': 'The last maintenance operation result code.'})  # fmt: skip
    maintenance_window_end_time: Optional[datetime] = field(default=None, metadata={'description': 'End time for the maintenance window.'})  # fmt: skip
    maintenance_window_start_time: Optional[datetime] = field(default=None, metadata={'description': 'Start time for the maintenance window.'})  # fmt: skip
    pre_maintenance_window_end_time: Optional[datetime] = field(default=None, metadata={'description': 'End time for the pre maintenance window.'})  # fmt: skip
    pre_maintenance_window_start_time: Optional[datetime] = field(default=None, metadata={'description': 'Start time for the pre maintenance window.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDiskInstanceView:
    kind: ClassVar[str] = "azure_disk_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "encryption_settings": S("encryptionSettings") >> ForallBend(AzureDiskEncryptionSettings.mapping),
        "name": S("name"),
        "statuses": S("statuses") >> ForallBend(AzureInstanceViewStatus.mapping),
    }
    encryption_settings: Optional[List[AzureDiskEncryptionSettings]] = field(default=None, metadata={'description': 'Specifies the encryption settings for the os disk. Minimum api-version: 2015-06-15.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The disk name."})
    statuses: Optional[List[AzureInstanceViewStatus]] = field(default=None, metadata={'description': 'The resource status information.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineExtensionInstanceView:
    kind: ClassVar[str] = "azure_virtual_machine_extension_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "statuses": S("statuses") >> ForallBend(AzureInstanceViewStatus.mapping),
        "substatuses": S("substatuses") >> ForallBend(AzureInstanceViewStatus.mapping),
        "type": S("type"),
        "type_handler_version": S("typeHandlerVersion"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The virtual machine extension name."})
    statuses: Optional[List[AzureInstanceViewStatus]] = field(default=None, metadata={'description': 'The resource status information.'})  # fmt: skip
    substatuses: Optional[List[AzureInstanceViewStatus]] = field(default=None, metadata={'description': 'The resource status information.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Specifies the type of the extension; an example is customscriptextension.'})  # fmt: skip
    type_handler_version: Optional[str] = field(default=None, metadata={'description': 'Specifies the version of the script handler.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineHealthStatus:
    kind: ClassVar[str] = "azure_virtual_machine_health_status"
    mapping: ClassVar[Dict[str, Bender]] = {"status": S("status") >> Bend(AzureInstanceViewStatus.mapping)}
    status: Optional[AzureInstanceViewStatus] = field(default=None, metadata={"description": "Instance view status."})


@define(eq=False, slots=False)
class AzureBootDiagnosticsInstanceView:
    kind: ClassVar[str] = "azure_boot_diagnostics_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "console_screenshot_blob_uri": S("consoleScreenshotBlobUri"),
        "serial_console_log_blob_uri": S("serialConsoleLogBlobUri"),
        "status": S("status") >> Bend(AzureInstanceViewStatus.mapping),
    }
    console_screenshot_blob_uri: Optional[str] = field(default=None, metadata={'description': 'The console screenshot blob uri. **note:** this will **not** be set if boot diagnostics is currently enabled with managed storage.'})  # fmt: skip
    serial_console_log_blob_uri: Optional[str] = field(default=None, metadata={'description': 'The serial console log blob uri. **note:** this will **not** be set if boot diagnostics is currently enabled with managed storage.'})  # fmt: skip
    status: Optional[AzureInstanceViewStatus] = field(default=None, metadata={"description": "Instance view status."})


@define(eq=False, slots=False)
class AzureAvailablePatchSummary:
    kind: ClassVar[str] = "azure_available_patch_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "assessment_activity_id": S("assessmentActivityId"),
        "critical_and_security_patch_count": S("criticalAndSecurityPatchCount"),
        "error": S("error") >> Bend(AzureApiError.mapping),
        "last_modified_time": S("lastModifiedTime"),
        "other_patch_count": S("otherPatchCount"),
        "reboot_pending": S("rebootPending"),
        "start_time": S("startTime"),
        "status": S("status"),
    }
    assessment_activity_id: Optional[str] = field(default=None, metadata={'description': 'The activity id of the operation that produced this result. It is used to correlate across crp and extension logs.'})  # fmt: skip
    critical_and_security_patch_count: Optional[int] = field(default=None, metadata={'description': 'The number of critical or security patches that have been detected as available and not yet installed.'})  # fmt: skip
    error: Optional[AzureApiError] = field(default=None, metadata={"description": "Api error."})
    last_modified_time: Optional[datetime] = field(default=None, metadata={'description': 'The utc timestamp when the operation began.'})  # fmt: skip
    other_patch_count: Optional[int] = field(default=None, metadata={'description': 'The number of all available patches excluding critical and security.'})  # fmt: skip
    reboot_pending: Optional[bool] = field(default=None, metadata={'description': 'The overall reboot status of the vm. It will be true when partially installed patches require a reboot to complete installation but the reboot has not yet occurred.'})  # fmt: skip
    start_time: Optional[datetime] = field(default=None, metadata={'description': 'The utc timestamp when the operation began.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'The overall success or failure status of the operation. It remains inprogress until the operation completes. At that point it will become unknown , failed , succeeded , or completedwithwarnings.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureLastPatchInstallationSummary:
    kind: ClassVar[str] = "azure_last_patch_installation_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "error": S("error") >> Bend(AzureApiError.mapping),
        "excluded_patch_count": S("excludedPatchCount"),
        "failed_patch_count": S("failedPatchCount"),
        "installation_activity_id": S("installationActivityId"),
        "installed_patch_count": S("installedPatchCount"),
        "last_modified_time": S("lastModifiedTime"),
        "maintenance_window_exceeded": S("maintenanceWindowExceeded"),
        "not_selected_patch_count": S("notSelectedPatchCount"),
        "pending_patch_count": S("pendingPatchCount"),
        "start_time": S("startTime"),
        "status": S("status"),
    }
    error: Optional[AzureApiError] = field(default=None, metadata={"description": "Api error."})
    excluded_patch_count: Optional[int] = field(default=None, metadata={'description': 'The number of all available patches but excluded explicitly by a customer-specified exclusion list match.'})  # fmt: skip
    failed_patch_count: Optional[int] = field(default=None, metadata={'description': 'The count of patches that failed installation.'})  # fmt: skip
    installation_activity_id: Optional[str] = field(default=None, metadata={'description': 'The activity id of the operation that produced this result. It is used to correlate across crp and extension logs.'})  # fmt: skip
    installed_patch_count: Optional[int] = field(default=None, metadata={'description': 'The count of patches that successfully installed.'})  # fmt: skip
    last_modified_time: Optional[datetime] = field(default=None, metadata={'description': 'The utc timestamp when the operation began.'})  # fmt: skip
    maintenance_window_exceeded: Optional[bool] = field(default=None, metadata={'description': 'Describes whether the operation ran out of time before it completed all its intended actions.'})  # fmt: skip
    not_selected_patch_count: Optional[int] = field(default=None, metadata={'description': 'The number of all available patches but not going to be installed because it didn t match a classification or inclusion list entry.'})  # fmt: skip
    pending_patch_count: Optional[int] = field(default=None, metadata={'description': 'The number of all available patches expected to be installed over the course of the patch installation operation.'})  # fmt: skip
    start_time: Optional[datetime] = field(default=None, metadata={'description': 'The utc timestamp when the operation began.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'The overall success or failure status of the operation. It remains inprogress until the operation completes. At that point it will become unknown , failed , succeeded , or completedwithwarnings.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachinePatchStatus:
    kind: ClassVar[str] = "azure_virtual_machine_patch_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_patch_summary": S("availablePatchSummary") >> Bend(AzureAvailablePatchSummary.mapping),
        "configuration_statuses": S("configurationStatuses") >> ForallBend(AzureInstanceViewStatus.mapping),
        "last_patch_installation_summary": S("lastPatchInstallationSummary")
        >> Bend(AzureLastPatchInstallationSummary.mapping),
    }
    available_patch_summary: Optional[AzureAvailablePatchSummary] = field(default=None, metadata={'description': 'Describes the properties of an virtual machine instance view for available patch summary.'})  # fmt: skip
    configuration_statuses: Optional[List[AzureInstanceViewStatus]] = field(default=None, metadata={'description': 'The enablement status of the specified patchmode.'})  # fmt: skip
    last_patch_installation_summary: Optional[AzureLastPatchInstallationSummary] = field(default=None, metadata={'description': 'Describes the properties of the last installed patch summary.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineInstanceView:
    kind: ClassVar[str] = "azure_virtual_machine_instance_view"
    mapping: ClassVar[Dict[str, Bender]] = {
        "assigned_host": S("assignedHost"),
        "boot_diagnostics": S("bootDiagnostics") >> Bend(AzureBootDiagnosticsInstanceView.mapping),
        "computer_name": S("computerName"),
        "disks": S("disks") >> ForallBend(AzureDiskInstanceView.mapping),
        "extensions": S("extensions") >> ForallBend(AzureVirtualMachineExtensionInstanceView.mapping),
        "hyper_v_generation": S("hyperVGeneration"),
        "maintenance_redeploy_status": S("maintenanceRedeployStatus") >> Bend(AzureMaintenanceRedeployStatus.mapping),
        "os_name": S("osName"),
        "os_version": S("osVersion"),
        "patch_status": S("patchStatus") >> Bend(AzureVirtualMachinePatchStatus.mapping),
        "platform_fault_domain": S("platformFaultDomain"),
        "platform_update_domain": S("platformUpdateDomain"),
        "rdp_thumb_print": S("rdpThumbPrint"),
        "statuses": S("statuses") >> ForallBend(AzureInstanceViewStatus.mapping),
        "vm_agent": S("vmAgent") >> Bend(AzureVirtualMachineAgentInstanceView.mapping),
        "vm_health": S("vmHealth") >> Bend(AzureVirtualMachineHealthStatus.mapping),
    }
    assigned_host: Optional[str] = field(default=None, metadata={'description': 'Resource id of the dedicated host, on which the virtual machine is allocated through automatic placement, when the virtual machine is associated with a dedicated host group that has automatic placement enabled. Minimum api-version: 2020-06-01.'})  # fmt: skip
    boot_diagnostics: Optional[AzureBootDiagnosticsInstanceView] = field(default=None, metadata={'description': 'The instance view of a virtual machine boot diagnostics.'})  # fmt: skip
    computer_name: Optional[str] = field(default=None, metadata={'description': 'The computer name assigned to the virtual machine.'})  # fmt: skip
    disks: Optional[List[AzureDiskInstanceView]] = field(default=None, metadata={'description': 'The virtual machine disk information.'})  # fmt: skip
    extensions: Optional[List[AzureVirtualMachineExtensionInstanceView]] = field(default=None, metadata={'description': 'The extensions information.'})  # fmt: skip
    hyper_v_generation: Optional[str] = field(default=None, metadata={'description': 'Specifies the hypervgeneration type associated with a resource.'})  # fmt: skip
    maintenance_redeploy_status: Optional[AzureMaintenanceRedeployStatus] = field(default=None, metadata={'description': 'Maintenance operation status.'})  # fmt: skip
    os_name: Optional[str] = field(default=None, metadata={'description': 'The operating system running on the virtual machine.'})  # fmt: skip
    os_version: Optional[str] = field(default=None, metadata={'description': 'The version of operating system running on the virtual machine.'})  # fmt: skip
    patch_status: Optional[AzureVirtualMachinePatchStatus] = field(default=None, metadata={'description': 'The status of virtual machine patch operations.'})  # fmt: skip
    platform_fault_domain: Optional[int] = field(default=None, metadata={'description': 'Specifies the fault domain of the virtual machine.'})  # fmt: skip
    platform_update_domain: Optional[int] = field(default=None, metadata={'description': 'Specifies the update domain of the virtual machine.'})  # fmt: skip
    rdp_thumb_print: Optional[str] = field(default=None, metadata={'description': 'The remote desktop certificate thumbprint.'})  # fmt: skip
    statuses: Optional[List[AzureInstanceViewStatus]] = field(default=None, metadata={'description': 'The resource status information.'})  # fmt: skip
    vm_agent: Optional[AzureVirtualMachineAgentInstanceView] = field(default=None, metadata={'description': 'The instance view of the vm agent running on the virtual machine.'})  # fmt: skip
    vm_health: Optional[AzureVirtualMachineHealthStatus] = field(default=None, metadata={'description': 'The health status of the vm.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTerminateNotificationProfile:
    kind: ClassVar[str] = "azure_terminate_notification_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"enable": S("enable"), "not_before_timeout": S("notBeforeTimeout")}
    enable: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the terminate scheduled event is enabled or disabled.'})  # fmt: skip
    not_before_timeout: Optional[str] = field(default=None, metadata={'description': 'Configurable length of time a virtual machine being deleted will have to potentially approve the terminate scheduled event before the event is auto approved (timed out). The configuration must be specified in iso 8601 format, the default value is 5 minutes (pt5m).'})  # fmt: skip


@define(eq=False, slots=False)
class AzureOSImageNotificationProfile:
    kind: ClassVar[str] = "azure_os_image_notification_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"enable": S("enable"), "not_before_timeout": S("notBeforeTimeout")}
    enable: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the os image scheduled event is enabled or disabled.'})  # fmt: skip
    not_before_timeout: Optional[str] = field(default=None, metadata={'description': 'Length of time a virtual machine being reimaged or having its os upgraded will have to potentially approve the os image scheduled event before the event is auto approved (timed out). The configuration is specified in iso 8601 format, and the value must be 15 minutes (pt15m).'})  # fmt: skip


@define(eq=False, slots=False)
class AzureScheduledEventsProfile:
    kind: ClassVar[str] = "azure_scheduled_events_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "os_image_notification_profile": S("osImageNotificationProfile")
        >> Bend(AzureOSImageNotificationProfile.mapping),
        "terminate_notification_profile": S("terminateNotificationProfile")
        >> Bend(AzureTerminateNotificationProfile.mapping),
    }
    os_image_notification_profile: Optional[AzureOSImageNotificationProfile] = field(default=None, metadata={'description': ''})  # fmt: skip
    terminate_notification_profile: Optional[AzureTerminateNotificationProfile] = field(default=None, metadata={'description': ''})  # fmt: skip


@define(eq=False, slots=False)
class AzureCapacityReservationProfile:
    kind: ClassVar[str] = "azure_capacity_reservation_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"capacity_reservation_group": S("capacityReservationGroup", "id")}
    capacity_reservation_group: Optional[str] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureVMGalleryApplication:
    kind: ClassVar[str] = "azure_vm_gallery_application"
    mapping: ClassVar[Dict[str, Bender]] = {
        "configuration_reference": S("configurationReference"),
        "enable_automatic_upgrade": S("enableAutomaticUpgrade"),
        "order": S("order"),
        "package_reference_id": S("packageReferenceId"),
        "tags": S("tags"),
        "treat_failure_as_deployment_failure": S("treatFailureAsDeploymentFailure"),
    }
    configuration_reference: Optional[str] = field(default=None, metadata={'description': 'Optional, specifies the uri to an azure blob that will replace the default configuration for the package if provided.'})  # fmt: skip
    enable_automatic_upgrade: Optional[bool] = field(default=None, metadata={'description': 'If set to true, when a new gallery application version is available in pir/sig, it will be automatically updated for the vm/vmss.'})  # fmt: skip
    order: Optional[int] = field(default=None, metadata={'description': 'Optional, specifies the order in which the packages have to be installed.'})  # fmt: skip
    package_reference_id: Optional[str] = field(default=None, metadata={'description': 'Specifies the galleryapplicationversion resource id on the form of /subscriptions/{subscriptionid}/resourcegroups/{resourcegroupname}/providers/microsoft. Compute/galleries/{galleryname}/applications/{application}/versions/{version}.'})  # fmt: skip
    tags: Optional[str] = field(default=None, metadata={'description': 'Optional, specifies a passthrough value for more generic context.'})  # fmt: skip
    treat_failure_as_deployment_failure: Optional[bool] = field(default=None, metadata={'description': 'Optional, if true, any failure for any operation in the vmapplication will fail the deployment.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureApplicationProfile:
    kind: ClassVar[str] = "azure_application_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "gallery_applications": S("galleryApplications") >> ForallBend(AzureVMGalleryApplication.mapping)
    }
    gallery_applications: Optional[List[AzureVMGalleryApplication]] = field(default=None, metadata={'description': 'Specifies the gallery applications that should be made available to the vm/vmss.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureResourceWithOptionalLocation:
    kind: ClassVar[str] = "azure_resource_with_optional_location"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "location": S("location"),
        "name": S("name"),
        "tags": S("tags"),
        "type": S("type"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "Resource id."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})
    tags: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Resource tags."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureVirtualMachineExtension(AzureResourceWithOptionalLocation):
    kind: ClassVar[str] = "azure_virtual_machine_extension"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_upgrade_minor_version": S("properties", "autoUpgradeMinorVersion"),
        "enable_automatic_upgrade": S("properties", "enableAutomaticUpgrade"),
        "force_update_tag": S("properties", "forceUpdateTag"),
        "machine_extension_instance_view": S("properties", "instanceView")
        >> Bend(AzureVirtualMachineExtensionInstanceView.mapping),
        "protected_settings": S("properties", "protectedSettings"),
        "protected_settings_from_key_vault": S("properties", "protectedSettingsFromKeyVault")
        >> Bend(AzureKeyVaultSecretReference.mapping),
        "provision_after_extensions": S("properties", "provisionAfterExtensions"),
        "provisioning_state": S("properties", "provisioningState"),
        "publisher": S("properties", "publisher"),
        "settings": S("properties", "settings"),
        "suppress_failures": S("properties", "suppressFailures"),
        "type": S("properties", "type"),
        "type_handler_version": S("properties", "typeHandlerVersion"),
    }
    auto_upgrade_minor_version: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the extension should use a newer minor version if one is available at deployment time. Once deployed, however, the extension will not upgrade minor versions unless redeployed, even with this property set to true.'})  # fmt: skip
    enable_automatic_upgrade: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the extension should be automatically upgraded by the platform if there is a newer version of the extension available.'})  # fmt: skip
    force_update_tag: Optional[str] = field(default=None, metadata={'description': 'How the extension handler should be forced to update even if the extension configuration has not changed.'})  # fmt: skip
    machine_extension_instance_view: Optional[AzureVirtualMachineExtensionInstanceView] = field(default=None, metadata={'description': 'The instance view of a virtual machine extension.'})  # fmt: skip
    protected_settings: Optional[Any] = field(default=None, metadata={'description': 'The extension can contain either protectedsettings or protectedsettingsfromkeyvault or no protected settings at all.'})  # fmt: skip
    protected_settings_from_key_vault: Optional[AzureKeyVaultSecretReference] = field(default=None, metadata={'description': 'Describes a reference to key vault secret.'})  # fmt: skip
    provision_after_extensions: Optional[List[str]] = field(default=None, metadata={'description': 'Collection of extension names after which this extension needs to be provisioned.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state, which only appears in the response.'})  # fmt: skip
    publisher: Optional[str] = field(default=None, metadata={'description': 'The name of the extension handler publisher.'})  # fmt: skip
    settings: Optional[Any] = field(default=None, metadata={'description': 'Json formatted public settings for the extension.'})  # fmt: skip
    suppress_failures: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether failures stemming from the extension will be suppressed (operational failures such as not connecting to the vm will not be suppressed regardless of this value). The default is false.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Specifies the type of the extension; an example is customscriptextension.'})  # fmt: skip
    type_handler_version: Optional[str] = field(default=None, metadata={'description': 'Specifies the version of the script handler.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineIdentity:
    kind: ClassVar[str] = "azure_virtual_machine_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal id of virtual machine identity. This property will only be provided for a system assigned identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id associated with the virtual machine. This property will only be provided for a system assigned identity.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of identity used for the virtual machine. The type systemassigned, userassigned includes both an implicitly created identity and a set of user assigned identities. The type none will remove any identities from the virtual machine.'})  # fmt: skip
    user_assigned_identities: Optional[Dict[str, AzurePrincipalidClientid]] = field(default=None, metadata={'description': 'The list of user identities associated with the virtual machine. The user identity dictionary key references will be arm resource ids in the form: /subscriptions/{subscriptionid}/resourcegroups/{resourcegroupname}/providers/microsoft. Managedidentity/userassignedidentities/{identityname}.'})  # fmt: skip


InstanceStatusMapping = {
    "starting": InstanceStatus.BUSY,
    "running": InstanceStatus.RUNNING,
    "stopping": InstanceStatus.BUSY,
    "stopped": InstanceStatus.STOPPED,
    "deallocating": InstanceStatus.BUSY,
    "deallocated": InstanceStatus.TERMINATED,
}


@define(eq=False, slots=False)
class AzureVirtualMachineBase(AzureResource, BaseInstance):
    kind: ClassVar[str] = "azure_virtual_machine_base"
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "azure_proximity_placement_group",
                "azure_network_security_group",
                "azure_subnet",
                "azure_load_balancer",
            ]
        },
        "successors": {
            "default": ["azure_image", "azure_disk", "azure_network_interface", "azure_virtual_machine_size"]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("properties", "timeCreated"),
        "virtual_machine_capabilities": S("properties", "additionalCapabilities")
        >> Bend(AzureAdditionalCapabilities.mapping),
        "application_profile": S("properties", "applicationProfile") >> Bend(AzureApplicationProfile.mapping),
        "availability_set": S("properties", "availabilitySet", "id"),
        "billing_profile": S("properties", "billingProfile", "maxPrice"),
        "capacity_reservation": S("properties", "capacityReservation") >> Bend(AzureCapacityReservationProfile.mapping),
        "virtual_machine_diagnostics_profile": S("properties", "diagnosticsProfile")
        >> Bend(AzureDiagnosticsProfile.mapping),
        "eviction_policy": S("properties", "evictionPolicy"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "extensions_time_budget": S("properties", "extensionsTimeBudget"),
        "hardware_profile": S("properties", "hardwareProfile") >> Bend(AzureHardwareProfile.mapping),
        "host": S("properties", "host", "id"),
        "host_group": S("properties", "hostGroup", "id"),
        "virtual_machine_identity": S("identity") >> Bend(AzureVirtualMachineIdentity.mapping),
        "virtual_machine_instance_view": S("properties", "instanceView")
        >> Bend(AzureVirtualMachineInstanceView.mapping),
        "license_type": S("properties", "licenseType"),
        "virtual_machine_network_profile": S("properties", "networkProfile")
        >> Bend(AzureVirtualMachineNetworkProfile.mapping),
        "virtual_machine_os_profile": S("properties", "osProfile") >> Bend(AzureOSProfile.mapping),
        "azure_plan": S("plan") >> Bend(AzurePlan.mapping),
        "platform_fault_domain": S("properties", "platformFaultDomain"),
        "virtual_machine_priority": S("properties", "priority"),
        "provisioning_state": S("properties", "provisioningState"),
        "proximity_placement_group": S("properties", "proximityPlacementGroup", "id"),
        "virtual_machine_resources": S("resources") >> ForallBend(AzureVirtualMachineExtension.mapping),
        "scheduled_events_profile": S("properties", "scheduledEventsProfile")
        >> Bend(AzureScheduledEventsProfile.mapping),
        "virtual_machine_security_profile": S("properties", "securityProfile") >> Bend(AzureSecurityProfile.mapping),
        "virtual_machine_storage_profile": S("properties", "storageProfile") >> Bend(AzureStorageProfile.mapping),
        "time_created": S("properties", "timeCreated"),
        "user_data": S("properties", "userData"),
        "virtual_machine_scale_set": S("properties", "virtualMachineScaleSet", "id"),
        "vm_id": S("properties", "vmId"),
        "location": S("location"),
        "instance_type": S("properties", "hardwareProfile", "vmSize"),
    }
    virtual_machine_capabilities: Optional[AzureAdditionalCapabilities] = field(default=None, metadata={'description': 'Enables or disables a capability on the virtual machine or virtual machine scale set.'})  # fmt: skip
    application_profile: Optional[AzureApplicationProfile] = field(default=None, metadata={'description': 'Contains the list of gallery applications that should be made available to the vm/vmss.'})  # fmt: skip
    availability_set: Optional[str] = field(default=None, metadata={"description": ""})
    billing_profile: Optional[float] = field(default=None, metadata={'description': 'Specifies the billing related details of a azure spot vm or vmss. Minimum api-version: 2019-03-01.'})  # fmt: skip
    capacity_reservation: Optional[AzureCapacityReservationProfile] = field(default=None, metadata={'description': 'The parameters of a capacity reservation profile.'})  # fmt: skip
    virtual_machine_diagnostics_profile: Optional[AzureDiagnosticsProfile] = field(default=None, metadata={'description': 'Specifies the boot diagnostic settings state. Minimum api-version: 2015-06-15.'})  # fmt: skip
    eviction_policy: Optional[str] = field(default=None, metadata={'description': 'Specifies the eviction policy for the azure spot vm/vmss.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The complex type of the extended location.'})  # fmt: skip
    extensions_time_budget: Optional[str] = field(default=None, metadata={'description': 'Specifies the time alloted for all extensions to start. The time duration should be between 15 minutes and 120 minutes (inclusive) and should be specified in iso 8601 format. The default value is 90 minutes (pt1h30m). Minimum api-version: 2020-06-01.'})  # fmt: skip
    hardware_profile: Optional[AzureHardwareProfile] = field(default=None, metadata={'description': 'Specifies the hardware settings for the virtual machine.'})  # fmt: skip
    host: Optional[str] = field(default=None, metadata={"description": ""})
    host_group: Optional[str] = field(default=None, metadata={"description": ""})
    virtual_machine_identity: Optional[AzureVirtualMachineIdentity] = field(default=None, metadata={'description': 'Identity for the virtual machine.'})  # fmt: skip
    virtual_machine_instance_view: Optional[AzureVirtualMachineInstanceView] = field(default=None, metadata={'description': 'The instance view of a virtual machine.'})  # fmt: skip
    license_type: Optional[str] = field(default=None, metadata={'description': 'Specifies that the image or disk that is being used was licensed on-premises. Possible values for windows server operating system are: windows_client windows_server possible values for linux server operating system are: rhel_byos (for rhel) sles_byos (for suse) for more information, see [azure hybrid use benefit for windows server](https://docs. Microsoft. Com/azure/virtual-machines/windows/hybrid-use-benefit-licensing) [azure hybrid use benefit for linux server](https://docs. Microsoft. Com/azure/virtual-machines/linux/azure-hybrid-benefit-linux) minimum api-version: 2015-06-15.'})  # fmt: skip
    virtual_machine_network_profile: Optional[AzureVirtualMachineNetworkProfile] = field(default=None, metadata={'description': 'Specifies the network interfaces or the networking configuration of the virtual machine.'})  # fmt: skip
    virtual_machine_os_profile: Optional[AzureOSProfile] = field(default=None, metadata={'description': 'Specifies the operating system settings for the virtual machine. Some of the settings cannot be changed once vm is provisioned.'})  # fmt: skip
    azure_plan: Optional[AzurePlan] = field(default=None, metadata={'description': 'Specifies information about the marketplace image used to create the virtual machine. This element is only used for marketplace images. Before you can use a marketplace image from an api, you must enable the image for programmatic use. In the azure portal, find the marketplace image that you want to use and then click **want to deploy programmatically, get started ->**. Enter any required information and then click **save**.'})  # fmt: skip
    platform_fault_domain: Optional[int] = field(default=None, metadata={'description': 'Specifies the scale set logical fault domain into which the virtual machine will be created. By default, the virtual machine will by automatically assigned to a fault domain that best maintains balance across available fault domains. This is applicable only if the virtualmachinescaleset property of this virtual machine is set. The virtual machine scale set that is referenced, must have platformfaultdomaincount greater than 1. This property cannot be updated once the virtual machine is created. Fault domain assignment can be viewed in the virtual machine instance view. Minimum api‐version: 2020‐12‐01.'})  # fmt: skip
    virtual_machine_priority: Optional[str] = field(default=None, metadata={'description': 'Specifies the priority for a standalone virtual machine or the virtual machines in the scale set. Low enum will be deprecated in the future, please use spot as the enum to deploy azure spot vm/vmss.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state, which only appears in the response.'})  # fmt: skip
    proximity_placement_group: Optional[str] = field(default=None, metadata={"description": ""})
    virtual_machine_resources: Optional[List[AzureVirtualMachineExtension]] = field(default=None, metadata={'description': 'The virtual machine child extension resources.'})  # fmt: skip
    scheduled_events_profile: Optional[AzureScheduledEventsProfile] = field(default=None, metadata={"description": ""})
    virtual_machine_security_profile: Optional[AzureSecurityProfile] = field(default=None, metadata={'description': 'Specifies the security profile settings for the virtual machine or virtual machine scale set.'})  # fmt: skip
    virtual_machine_storage_profile: Optional[AzureStorageProfile] = field(default=None, metadata={'description': 'Specifies the storage settings for the virtual machine disks.'})  # fmt: skip
    time_created: Optional[datetime] = field(default=None, metadata={'description': 'Specifies the time at which the virtual machine resource was created. Minimum api-version: 2021-11-01.'})  # fmt: skip
    user_data: Optional[str] = field(default=None, metadata={'description': 'Userdata for the vm, which must be base-64 encoded. Customer should not pass any secrets in here. Minimum api-version: 2021-03-01.'})  # fmt: skip
    virtual_machine_scale_set: Optional[str] = field(default=None, metadata={"description": ""})
    vm_id: Optional[str] = field(default=None, metadata={'description': 'Specifies the vm unique id which is a 128-bits identifier that is encoded and stored in all azure iaas vms smbios and can be read using platform bios commands.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_instance_status() -> None:
            api_spec = AzureApiSpec(
                service="compute",
                version="2022-03-01",
                path=self.id,
                path_parameters=[],
                query_parameters=["api-version", "$expand"],
                access_path=None,
                expect_array=False,
            )
            params = {"$expand": "instanceView"}
            items = graph_builder.client.list(api_spec, **params)
            if items:
                item: Json = next(iter(items), {})
                try:
                    instance_v_statuses = item["properties"]["instanceView"]["statuses"]
                except KeyError:
                    instance_v_statuses = []
                instance_status_set = False
                for instance_v_status in instance_v_statuses:
                    status_code = instance_v_status.get("code", "").split("/")
                    if status_code[0] == "PowerState":
                        self.instance_status = InstanceStatusMapping.get(status_code[1], InstanceStatus.UNKNOWN)
                        instance_status_set = True
                if not instance_status_set:
                    self.instance_status = InstanceStatus.UNKNOWN

        graph_builder.submit_work("azure_virtual_machine", collect_instance_status)

    @classmethod
    def collect_usage_metrics(
        cls: Type[AzureResource], builder: GraphBuilder, collected_resources: List[AzureResourceType]
    ) -> None:
        virtual_machines = {vm.id: vm for vm in collected_resources if vm}
        queries = []
        start = builder.metrics_start
        now = builder.created_at
        delta = builder.metrics_delta
        for vm_id in virtual_machines:
            queries.append(
                AzureMetricQuery.create(
                    metric_name="Percentage CPU",
                    metric_namespace="Microsoft.Compute/virtualMachines",
                    instance_id=vm_id,
                    aggregation=("average", "minimum", "maximum"),
                    ref_id=vm_id,
                    unit="Percent",
                )
            )
            queries.extend(
                [
                    AzureMetricQuery.create(
                        metric_name=metric_name,
                        metric_namespace="Microsoft.Compute/virtualMachines",
                        instance_id=vm_id,
                        aggregation=("average", "minimum", "maximum"),
                        ref_id=vm_id,
                        unit="Bytes",
                    )
                    for metric_name in ["Disk Write Bytes", "Disk Read Bytes"]
                ]
            )
            queries.extend(
                [
                    AzureMetricQuery.create(
                        metric_name=metric_name,
                        metric_namespace="Microsoft.Compute/virtualMachines",
                        instance_id=vm_id,
                        aggregation=("average", "minimum", "maximum"),
                        ref_id=vm_id,
                        unit="CountPerSecond",
                    )
                    for metric_name in ["Disk Write Operations/Sec", "Disk Read Operations/Sec"]
                ]
            )
            queries.extend(
                [
                    AzureMetricQuery.create(
                        metric_name=metric_name,
                        metric_namespace="Microsoft.Compute/virtualMachines",
                        instance_id=vm_id,
                        aggregation=("average", "minimum", "maximum"),
                        ref_id=vm_id,
                        unit="Bytes",
                    )
                    for metric_name in ["Network In", "Network Out"]
                ]
            )

        metric_normalizers = {
            "Percentage CPU": MetricNormalization(
                metric_name=MetricName.CpuUtilization,
                unit=MetricUnit.Percent,
                normalize_value=lambda x: round(x, ndigits=3),
            ),
            "Network In": MetricNormalization(metric_name=MetricName.NetworkIn, unit=MetricUnit.Bytes),
            "Network Out": MetricNormalization(metric_name=MetricName.NetworkOut, unit=MetricUnit.Bytes),
            "Disk Read Operations/Sec": MetricNormalization(metric_name=MetricName.DiskRead, unit=MetricUnit.IOPS),
            "Disk Write Operations/Sec": MetricNormalization(metric_name=MetricName.DiskWrite, unit=MetricUnit.IOPS),
            "Disk Read Bytes": MetricNormalization(metric_name=MetricName.DiskRead, unit=MetricUnit.Bytes),
            "Disk Write Bytes": MetricNormalization(metric_name=MetricName.DiskWrite, unit=MetricUnit.Bytes),
        }

        metric_result = AzureMetricData.query_for(builder, queries, start, now, delta)

        update_resource_metrics(virtual_machines, metric_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if placement_group_id := self.proximity_placement_group:
            builder.add_edge(
                self,
                edge_type=EdgeType.default,
                reverse=True,
                clazz=AzureProximityPlacementGroup,
                id=placement_group_id,
            )

        if (
            (sp := self.virtual_machine_storage_profile)
            and (image_ref := sp.image_reference)
            and (image_reference_id := image_ref.id)
        ):
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureImage, id=image_reference_id)

        if (
            (sp := self.virtual_machine_storage_profile)
            and (disk := sp.os_disk)
            and (managed := disk.managed_disk)
            and (managed_disk_id := managed.id)
        ):
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureDisk, id=managed_disk_id)

        if (vm_network_profile := self.virtual_machine_network_profile) and (
            ni_cofigurations := vm_network_profile.network_interface_configurations
        ):
            for ni_configuration in ni_cofigurations:
                if nsg_id := ni_configuration.network_security_group:
                    builder.add_edge(
                        self, edge_type=EdgeType.default, reverse=True, clazz=AzureNetworkSecurityGroup, id=nsg_id
                    )
                if ip_configurations := ni_configuration.ip_configurations:
                    for ip_configuration in ip_configurations:
                        if subnet_id := ip_configuration.subnet:
                            builder.add_edge(
                                self, edge_type=EdgeType.default, reverse=True, clazz=AzureSubnet, id=subnet_id
                            )
                        if lbbap_ids := ip_configuration.load_balancer_backend_address_pools:
                            for lbbap_id in lbbap_ids:
                                # take only id of load balancer
                                lbbap_id = "/".join(lbbap_id.split("/")[:-2])
                                builder.add_edge(
                                    self, edge_type=EdgeType.default, reverse=True, clazz=AzureLoadBalancer, id=lbbap_id
                                )

        if (vm_network_profile := self.virtual_machine_network_profile) and (
            network_interfaces := vm_network_profile.network_interfaces
        ):
            for network_interface in network_interfaces:
                if ni_id := network_interface.id:
                    builder.add_edge(self, edge_type=EdgeType.default, clazz=AzureNetworkInterface, id=ni_id)
        if (vms_type := self.instance_type) and (vm_location := self.location):
            builder.add_edge(
                self, edge_type=EdgeType.default, clazz=AzureVirtualMachineSize, name=vms_type, location=vm_location
            )


@define(eq=False, slots=False)
class AzureVirtualMachine(AzureVirtualMachineBase):
    kind: ClassVar[str] = "azure_virtual_machine"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )


@define(eq=False, slots=False)
class AzureRollingUpgradePolicy:
    kind: ClassVar[str] = "azure_rolling_upgrade_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_cross_zone_upgrade": S("enableCrossZoneUpgrade"),
        "max_batch_instance_percent": S("maxBatchInstancePercent"),
        "max_surge": S("maxSurge"),
        "max_unhealthy_instance_percent": S("maxUnhealthyInstancePercent"),
        "max_unhealthy_upgraded_instance_percent": S("maxUnhealthyUpgradedInstancePercent"),
        "pause_time_between_batches": S("pauseTimeBetweenBatches"),
        "prioritize_unhealthy_instances": S("prioritizeUnhealthyInstances"),
        "rollback_failed_instances_on_policy_breach": S("rollbackFailedInstancesOnPolicyBreach"),
    }
    enable_cross_zone_upgrade: Optional[bool] = field(default=None, metadata={'description': 'Allow vmss to ignore az boundaries when constructing upgrade batches. Take into consideration the update domain and maxbatchinstancepercent to determine the batch size.'})  # fmt: skip
    max_batch_instance_percent: Optional[int] = field(default=None, metadata={'description': 'The maximum percent of total virtual machine instances that will be upgraded simultaneously by the rolling upgrade in one batch. As this is a maximum, unhealthy instances in previous or future batches can cause the percentage of instances in a batch to decrease to ensure higher reliability. The default value for this parameter is 20%.'})  # fmt: skip
    max_surge: Optional[bool] = field(default=None, metadata={'description': 'Create new virtual machines to upgrade the scale set, rather than updating the existing virtual machines. Existing virtual machines will be deleted once the new virtual machines are created for each batch.'})  # fmt: skip
    max_unhealthy_instance_percent: Optional[int] = field(default=None, metadata={'description': 'The maximum percentage of the total virtual machine instances in the scale set that can be simultaneously unhealthy, either as a result of being upgraded, or by being found in an unhealthy state by the virtual machine health checks before the rolling upgrade aborts. This constraint will be checked prior to starting any batch. The default value for this parameter is 20%.'})  # fmt: skip
    max_unhealthy_upgraded_instance_percent: Optional[int] = field(default=None, metadata={'description': 'The maximum percentage of upgraded virtual machine instances that can be found to be in an unhealthy state. This check will happen after each batch is upgraded. If this percentage is ever exceeded, the rolling update aborts. The default value for this parameter is 20%.'})  # fmt: skip
    pause_time_between_batches: Optional[str] = field(default=None, metadata={'description': 'The wait time between completing the update for all virtual machines in one batch and starting the next batch. The time duration should be specified in iso 8601 format. The default value is 0 seconds (pt0s).'})  # fmt: skip
    prioritize_unhealthy_instances: Optional[bool] = field(default=None, metadata={'description': 'Upgrade all unhealthy instances in a scale set before any healthy instances.'})  # fmt: skip
    rollback_failed_instances_on_policy_breach: Optional[bool] = field(default=None, metadata={'description': 'Rollback failed instances to previous model if the rolling upgrade policy is violated.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAutomaticOSUpgradePolicy:
    kind: ClassVar[str] = "azure_automatic_os_upgrade_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disable_automatic_rollback": S("disableAutomaticRollback"),
        "enable_automatic_os_upgrade": S("enableAutomaticOSUpgrade"),
        "use_rolling_upgrade_policy": S("useRollingUpgradePolicy"),
    }
    disable_automatic_rollback: Optional[bool] = field(default=None, metadata={'description': 'Whether os image rollback feature should be disabled. Default value is false.'})  # fmt: skip
    enable_automatic_os_upgrade: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether os upgrades should automatically be applied to scale set instances in a rolling fashion when a newer version of the os image becomes available. Default value is false. If this is set to true for windows based scale sets, [enableautomaticupdates](https://docs. Microsoft. Com/dotnet/api/microsoft. Azure. Management. Compute. Models. Windowsconfiguration. Enableautomaticupdates?view=azure-dotnet) is automatically set to false and cannot be set to true.'})  # fmt: skip
    use_rolling_upgrade_policy: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether rolling upgrade policy should be used during auto os upgrade. Default value is false. Auto os upgrade will fallback to the default policy if no policy is defined on the vmss.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureUpgradePolicy:
    kind: ClassVar[str] = "azure_upgrade_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "automatic_os_upgrade_policy": S("automaticOSUpgradePolicy") >> Bend(AzureAutomaticOSUpgradePolicy.mapping),
        "mode": S("mode"),
        "rolling_upgrade_policy": S("rollingUpgradePolicy") >> Bend(AzureRollingUpgradePolicy.mapping),
    }
    automatic_os_upgrade_policy: Optional[AzureAutomaticOSUpgradePolicy] = field(default=None, metadata={'description': 'The configuration parameters used for performing automatic os upgrade.'})  # fmt: skip
    mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the mode of an upgrade to virtual machines in the scale set. Possible values are: **manual** - you control the application of updates to virtual machines in the scale set. You do this by using the manualupgrade action. **automatic** - all virtual machines in the scale set are automatically updated at the same time.'})  # fmt: skip
    rolling_upgrade_policy: Optional[AzureRollingUpgradePolicy] = field(default=None, metadata={'description': 'The configuration parameters used while performing a rolling upgrade.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAutomaticRepairsPolicy:
    kind: ClassVar[str] = "azure_automatic_repairs_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("enabled"),
        "grace_period": S("gracePeriod"),
        "repair_action": S("repairAction"),
    }
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether automatic repairs should be enabled on the virtual machine scale set. The default value is false.'})  # fmt: skip
    grace_period: Optional[str] = field(default=None, metadata={'description': 'The amount of time for which automatic repairs are suspended due to a state change on vm. The grace time starts after the state change has completed. This helps avoid premature or accidental repairs. The time duration should be specified in iso 8601 format. The minimum allowed grace period is 10 minutes (pt10m), which is also the default value. The maximum allowed grace period is 90 minutes (pt90m).'})  # fmt: skip
    repair_action: Optional[str] = field(default=None, metadata={'description': 'Type of repair action (replace, restart, reimage) that will be used for repairing unhealthy virtual machines in the scale set. Default value is replace.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetOSProfile:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_os_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "admin_password": S("adminPassword"),
        "admin_username": S("adminUsername"),
        "allow_extension_operations": S("allowExtensionOperations"),
        "computer_name_prefix": S("computerNamePrefix"),
        "custom_data": S("customData"),
        "linux_configuration": S("linuxConfiguration") >> Bend(AzureLinuxConfiguration.mapping),
        "require_guest_provision_signal": S("requireGuestProvisionSignal"),
        "secrets": S("secrets") >> ForallBend(AzureVaultSecretGroup.mapping),
        "windows_configuration": S("windowsConfiguration") >> Bend(AzureWindowsConfiguration.mapping),
    }
    admin_password: Optional[str] = field(default=None, metadata={'description': 'Specifies the password of the administrator account. **minimum-length (windows):** 8 characters **minimum-length (linux):** 6 characters **max-length (windows):** 123 characters **max-length (linux):** 72 characters **complexity requirements:** 3 out of 4 conditions below need to be fulfilled has lower characters has upper characters has a digit has a special character (regex match [\\w_]) **disallowed values:** abc@123 , p@$$w0rd , p@ssw0rd , p@ssword123 , pa$$word , pass@word1 , password! , password1 , password22 , iloveyou! for resetting the password, see [how to reset the remote desktop service or its login password in a windows vm](https://docs. Microsoft. Com/troubleshoot/azure/virtual-machines/reset-rdp) for resetting root password, see [manage users, ssh, and check or repair disks on azure linux vms using the vmaccess extension](https://docs. Microsoft. Com/troubleshoot/azure/virtual-machines/troubleshoot-ssh-connection).'})  # fmt: skip
    admin_username: Optional[str] = field(default=None, metadata={'description': 'Specifies the name of the administrator account. **windows-only restriction:** cannot end in. **disallowed values:** administrator , admin , user , user1 , test , user2 , test1 , user3 , admin1 , 1 , 123 , a , actuser , adm , admin2 , aspnet , backup , console , david , guest , john , owner , root , server , sql , support , support_388945a0 , sys , test2 , test3 , user4 , user5. **minimum-length (linux):** 1 character **max-length (linux):** 64 characters **max-length (windows):** 20 characters.'})  # fmt: skip
    allow_extension_operations: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether extension operations should be allowed on the virtual machine scale set. This may only be set to false when no extensions are present on the virtual machine scale set.'})  # fmt: skip
    computer_name_prefix: Optional[str] = field(default=None, metadata={'description': 'Specifies the computer name prefix for all of the virtual machines in the scale set. Computer name prefixes must be 1 to 15 characters long.'})  # fmt: skip
    custom_data: Optional[str] = field(default=None, metadata={'description': 'Specifies a base-64 encoded string of custom data. The base-64 encoded string is decoded to a binary array that is saved as a file on the virtual machine. The maximum length of the binary array is 65535 bytes. For using cloud-init for your vm, see [using cloud-init to customize a linux vm during creation](https://docs. Microsoft. Com/azure/virtual-machines/linux/using-cloud-init).'})  # fmt: skip
    linux_configuration: Optional[AzureLinuxConfiguration] = field(default=None, metadata={'description': 'Specifies the linux operating system settings on the virtual machine. For a list of supported linux distributions, see [linux on azure-endorsed distributions](https://docs. Microsoft. Com/azure/virtual-machines/linux/endorsed-distros).'})  # fmt: skip
    require_guest_provision_signal: Optional[bool] = field(default=None, metadata={'description': 'Optional property which must either be set to true or omitted.'})  # fmt: skip
    secrets: Optional[List[AzureVaultSecretGroup]] = field(default=None, metadata={'description': 'Specifies set of certificates that should be installed onto the virtual machines in the scale set. To install certificates on a virtual machine it is recommended to use the [azure key vault virtual machine extension for linux](https://docs. Microsoft. Com/azure/virtual-machines/extensions/key-vault-linux) or the [azure key vault virtual machine extension for windows](https://docs. Microsoft. Com/azure/virtual-machines/extensions/key-vault-windows).'})  # fmt: skip
    windows_configuration: Optional[AzureWindowsConfiguration] = field(default=None, metadata={'description': 'Specifies windows operating system settings on the virtual machine.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetManagedDiskParameters:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_managed_disk_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_encryption_set": S("diskEncryptionSet") >> Bend(AzureSubResource.mapping),
        "security_profile": S("securityProfile") >> Bend(AzureVMDiskSecurityProfile.mapping),
        "storage_account_type": S("storageAccountType"),
    }
    disk_encryption_set: Optional[AzureSubResource] = field(default=None, metadata={'description': 'Describes the parameter of customer managed disk encryption set resource id that can be specified for disk. **note:** the disk encryption set resource id can only be specified for managed disk. Please refer https://aka. Ms/mdssewithcmkoverview for more details.'})  # fmt: skip
    security_profile: Optional[AzureVMDiskSecurityProfile] = field(default=None, metadata={'description': 'Specifies the security profile settings for the managed disk. **note:** it can only be set for confidential vms.'})  # fmt: skip
    storage_account_type: Optional[str] = field(default=None, metadata={'description': 'Specifies the storage account type for the managed disk. Managed os disk storage account type can only be set when you create the scale set. Note: ultrassd_lrs can only be used with data disks. It cannot be used with os disk. Standard_lrs uses standard hdd. Standardssd_lrs uses standard ssd. Premium_lrs uses premium ssd. Ultrassd_lrs uses ultra disk. Premium_zrs uses premium ssd zone redundant storage. Standardssd_zrs uses standard ssd zone redundant storage. For more information regarding disks supported for windows virtual machines, refer to https://docs. Microsoft. Com/azure/virtual-machines/windows/disks-types and, for linux virtual machines, refer to https://docs. Microsoft. Com/azure/virtual-machines/linux/disks-types.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetOSDisk:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_os_disk"
    mapping: ClassVar[Dict[str, Bender]] = {
        "caching": S("caching"),
        "create_option": S("createOption"),
        "delete_option": S("deleteOption"),
        "diff_disk_settings": S("diffDiskSettings") >> Bend(AzureDiffDiskSettings.mapping),
        "disk_size_gb": S("diskSizeGB"),
        "image": S("image", "uri"),
        "managed_disk": S("managedDisk") >> Bend(AzureVirtualMachineScaleSetManagedDiskParameters.mapping),
        "name": S("name"),
        "os_type": S("osType"),
        "vhd_containers": S("vhdContainers"),
        "write_accelerator_enabled": S("writeAcceleratorEnabled"),
    }
    caching: Optional[str] = field(default=None, metadata={'description': 'Specifies the caching requirements. Possible values are: **none,** **readonly,** **readwrite. ** the default values are: **none for standard storage. Readonly for premium storage**.'})  # fmt: skip
    create_option: Optional[str] = field(default=None, metadata={'description': 'Specifies how the virtual machine should be created. Possible values are: **attach. ** this value is used when you are using a specialized disk to create the virtual machine. **fromimage. ** this value is used when you are using an image to create the virtual machine. If you are using a platform image, you also use the imagereference element described above. If you are using a marketplace image, you also use the plan element previously described.'})  # fmt: skip
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specifies the behavior of the managed disk when the vm gets deleted, for example whether the managed disk is deleted or detached. Supported values are: **delete. ** if this value is used, the managed disk is deleted when vm gets deleted. **detach. ** if this value is used, the managed disk is retained after vm gets deleted. Minimum api-version: 2021-03-01.'})  # fmt: skip
    diff_disk_settings: Optional[AzureDiffDiskSettings] = field(default=None, metadata={'description': 'Describes the parameters of ephemeral disk settings that can be specified for operating system disk. **note:** the ephemeral disk settings can only be specified for managed disk.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'Specifies the size of an empty data disk in gigabytes. This element can be used to overwrite the size of the disk in a virtual machine image. The property disksizegb is the number of bytes x 1024^3 for the disk and the value cannot be larger than 1023.'})  # fmt: skip
    image: Optional[str] = field(default=None, metadata={"description": "Describes the uri of a disk."})
    managed_disk: Optional[AzureVirtualMachineScaleSetManagedDiskParameters] = field(default=None, metadata={'description': 'Describes the parameters of a scaleset managed disk.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The disk name."})
    os_type: Optional[str] = field(default=None, metadata={'description': 'This property allows you to specify the type of the os that is included in the disk if creating a vm from user-image or a specialized vhd. Possible values are: **windows,** **linux. **.'})  # fmt: skip
    vhd_containers: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies the container urls that are used to store operating system disks for the scale set.'})  # fmt: skip
    write_accelerator_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether writeaccelerator should be enabled or disabled on the disk.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetDataDisk:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_data_disk"
    mapping: ClassVar[Dict[str, Bender]] = {
        "caching": S("caching"),
        "create_option": S("createOption"),
        "delete_option": S("deleteOption"),
        "disk_iops_read_write": S("diskIOPSReadWrite"),
        "disk_m_bps_read_write": S("diskMBpsReadWrite"),
        "disk_size_gb": S("diskSizeGB"),
        "lun": S("lun"),
        "managed_disk": S("managedDisk") >> Bend(AzureVirtualMachineScaleSetManagedDiskParameters.mapping),
        "name": S("name"),
        "write_accelerator_enabled": S("writeAcceleratorEnabled"),
    }
    caching: Optional[str] = field(default=None, metadata={'description': 'Specifies the caching requirements. Possible values are: **none,** **readonly,** **readwrite. ** the default values are: **none for standard storage. Readonly for premium storage**.'})  # fmt: skip
    create_option: Optional[str] = field(default=None, metadata={'description': 'Specifies how the virtual machine should be created. Possible values are: **attach. ** this value is used when you are using a specialized disk to create the virtual machine. **fromimage. ** this value is used when you are using an image to create the virtual machine. If you are using a platform image, you also use the imagereference element described above. If you are using a marketplace image, you also use the plan element previously described.'})  # fmt: skip
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specifies the behavior of the managed disk when the vm gets deleted, for example whether the managed disk is deleted or detached. Supported values are: **delete. ** if this value is used, the managed disk is deleted when vm gets deleted. **detach. ** if this value is used, the managed disk is retained after vm gets deleted. Minimum api-version: 2021-03-01.'})  # fmt: skip
    disk_iops_read_write: Optional[int] = field(default=None, metadata={'description': 'Specifies the read-write iops for the managed disk. Should be used only when storageaccounttype is ultrassd_lrs. If not specified, a default value would be assigned based on disksizegb.'})  # fmt: skip
    disk_m_bps_read_write: Optional[int] = field(default=None, metadata={'description': 'Specifies the bandwidth in mb per second for the managed disk. Should be used only when storageaccounttype is ultrassd_lrs. If not specified, a default value would be assigned based on disksizegb.'})  # fmt: skip
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'Specifies the size of an empty data disk in gigabytes. This element can be used to overwrite the size of the disk in a virtual machine image. The property disksizegb is the number of bytes x 1024^3 for the disk and the value cannot be larger than 1023.'})  # fmt: skip
    lun: Optional[int] = field(default=None, metadata={'description': 'Specifies the logical unit number of the data disk. This value is used to identify data disks within the vm and therefore must be unique for each data disk attached to a vm.'})  # fmt: skip
    managed_disk: Optional[AzureVirtualMachineScaleSetManagedDiskParameters] = field(default=None, metadata={'description': 'Describes the parameters of a scaleset managed disk.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The disk name."})
    write_accelerator_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether writeaccelerator should be enabled or disabled on the disk.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetStorageProfile:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_storage_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_disks": S("dataDisks") >> ForallBend(AzureVirtualMachineScaleSetDataDisk.mapping),
        "disk_controller_type": S("diskControllerType"),
        "image_reference": S("imageReference") >> Bend(AzureImageReference.mapping),
        "os_disk": S("osDisk") >> Bend(AzureVirtualMachineScaleSetOSDisk.mapping),
    }
    data_disks: Optional[List[AzureVirtualMachineScaleSetDataDisk]] = field(default=None, metadata={'description': 'Specifies the parameters that are used to add data disks to the virtual machines in the scale set. For more information about disks, see [about disks and vhds for azure virtual machines](https://docs. Microsoft. Com/azure/virtual-machines/managed-disks-overview).'})  # fmt: skip
    disk_controller_type: Optional[str] = field(default=None, metadata={"description": ""})
    image_reference: Optional[AzureImageReference] = field(default=None, metadata={'description': 'Specifies information about the image to use. You can specify information about platform images, marketplace images, or virtual machine images. This element is required when you want to use a platform image, marketplace image, or virtual machine image, but is not used in other creation operations. Note: image reference publisher and offer can only be set when you create the scale set.'})  # fmt: skip
    os_disk: Optional[AzureVirtualMachineScaleSetOSDisk] = field(default=None, metadata={'description': 'Describes a virtual machine scale set operating system disk.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetNetworkConfigurationDnsSettings:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_network_configuration_dns_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"dns_servers": S("dnsServers")}
    dns_servers: Optional[List[str]] = field(
        default=None, metadata={"description": "List of dns servers ip addresses."}
    )


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetIpTag:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_ip_tag"
    mapping: ClassVar[Dict[str, Bender]] = {"ip_tag_type": S("ipTagType"), "tag": S("tag")}
    ip_tag_type: Optional[str] = field(default=None, metadata={'description': 'Ip tag type. Example: firstpartyusage.'})  # fmt: skip
    tag: Optional[str] = field(default=None, metadata={'description': 'Ip tag associated with the public ip. Example: sql, storage etc.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetPublicIPAddressConfiguration:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_public_ip_address_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "delete_option": S("properties", "deleteOption"),
        "dns_settings": S("properties", "dnsSettings", "domainNameLabel"),
        "idle_timeout_in_minutes": S("properties", "idleTimeoutInMinutes"),
        "ip_tags": S("properties", "ipTags") >> ForallBend(AzureVirtualMachineScaleSetIpTag.mapping),
        "name": S("name"),
        "public_ip_address_version": S("properties", "publicIPAddressVersion"),
        "public_ip_prefix": S("properties", "publicIPPrefix", "id"),
        "sku": S("sku") >> Bend(AzurePublicIPAddressSku.mapping),
    }
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specify what happens to the public ip when the vm is deleted.'})  # fmt: skip
    dns_settings: Optional[str] = field(default=None, metadata={'description': 'Describes a virtual machines scale sets network configuration s dns settings.'})  # fmt: skip
    idle_timeout_in_minutes: Optional[int] = field(default=None, metadata={'description': 'The idle timeout of the public ip address.'})  # fmt: skip
    ip_tags: Optional[List[AzureVirtualMachineScaleSetIpTag]] = field(default=None, metadata={'description': 'The list of ip tags associated with the public ip address.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The publicip address configuration name."})
    public_ip_address_version: Optional[str] = field(default=None, metadata={'description': 'Available from api-version 2019-07-01 onwards, it represents whether the specific ipconfiguration is ipv4 or ipv6. Default is taken as ipv4. Possible values are: ipv4 and ipv6.'})  # fmt: skip
    public_ip_prefix: Optional[str] = field(default=None, metadata={"description": ""})
    sku: Optional[AzurePublicIPAddressSku] = field(default=None, metadata={'description': 'Describes the public ip sku. It can only be set with orchestrationmode as flexible.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetIPConfiguration:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_ip_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "application_gateway_backend_address_pools": S("properties")
        >> S("applicationGatewayBackendAddressPools", default=[])
        >> ForallBend(S("id")),
        "application_security_groups": S("properties")
        >> S("applicationSecurityGroups", default=[])
        >> ForallBend(S("id")),
        "load_balancer_backend_address_pools": S("properties")
        >> S("loadBalancerBackendAddressPools", default=[])
        >> ForallBend(S("id")),
        "load_balancer_inbound_nat_pools": S("properties")
        >> S("loadBalancerInboundNatPools", default=[])
        >> ForallBend(S("id")),
        "name": S("name"),
        "primary": S("properties", "primary"),
        "private_ip_address_version": S("properties", "privateIPAddressVersion"),
        "public_ip_address_configuration": S("properties", "publicIPAddressConfiguration")
        >> Bend(AzureVirtualMachineScaleSetPublicIPAddressConfiguration.mapping),
        "subnet": S("properties", "subnet", "id"),
    }
    application_gateway_backend_address_pools: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies an array of references to backend address pools of application gateways. A scale set can reference backend address pools of multiple application gateways. Multiple scale sets cannot use the same application gateway.'})  # fmt: skip
    application_security_groups: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies an array of references to application security group.'})  # fmt: skip
    load_balancer_backend_address_pools: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies an array of references to backend address pools of load balancers. A scale set can reference backend address pools of one public and one internal load balancer. Multiple scale sets cannot use the same basic sku load balancer.'})  # fmt: skip
    load_balancer_inbound_nat_pools: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies an array of references to inbound nat pools of the load balancers. A scale set can reference inbound nat pools of one public and one internal load balancer. Multiple scale sets cannot use the same basic sku load balancer.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The ip configuration name."})
    primary: Optional[bool] = field(default=None, metadata={'description': 'Specifies the primary network interface in case the virtual machine has more than 1 network interface.'})  # fmt: skip
    private_ip_address_version: Optional[str] = field(default=None, metadata={'description': 'Available from api-version 2017-03-30 onwards, it represents whether the specific ipconfiguration is ipv4 or ipv6. Default is taken as ipv4. Possible values are: ipv4 and ipv6.'})  # fmt: skip
    public_ip_address_configuration: Optional[AzureVirtualMachineScaleSetPublicIPAddressConfiguration] = field(default=None, metadata={'description': 'Describes a virtual machines scale set ip configuration s publicipaddress configuration.'})  # fmt: skip
    subnet: Optional[str] = field(default=None, metadata={"description": "The api entity reference."})


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetNetworkConfiguration:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_network_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "delete_option": S("properties", "deleteOption"),
        "disable_tcp_state_tracking": S("properties", "disableTcpStateTracking"),
        "dns_settings": S("properties", "dnsSettings")
        >> Bend(AzureVirtualMachineScaleSetNetworkConfigurationDnsSettings.mapping),
        "enable_accelerated_networking": S("properties", "enableAcceleratedNetworking"),
        "enable_fpga": S("properties", "enableFpga"),
        "enable_ip_forwarding": S("properties", "enableIPForwarding"),
        "ip_configurations": S("properties", "ipConfigurations")
        >> ForallBend(AzureVirtualMachineScaleSetIPConfiguration.mapping),
        "name": S("name"),
        "network_security_group": S("properties", "networkSecurityGroup", "id"),
        "primary": S("properties", "primary"),
    }
    delete_option: Optional[str] = field(default=None, metadata={'description': 'Specify what happens to the network interface when the vm is deleted.'})  # fmt: skip
    disable_tcp_state_tracking: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the network interface is disabled for tcp state tracking.'})  # fmt: skip
    dns_settings: Optional[AzureVirtualMachineScaleSetNetworkConfigurationDnsSettings] = field(default=None, metadata={'description': 'Describes a virtual machines scale sets network configuration s dns settings.'})  # fmt: skip
    enable_accelerated_networking: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the network interface is accelerated networking-enabled.'})  # fmt: skip
    enable_fpga: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the network interface is fpga networking-enabled.'})  # fmt: skip
    enable_ip_forwarding: Optional[bool] = field(default=None, metadata={'description': 'Whether ip forwarding enabled on this nic.'})  # fmt: skip
    ip_configurations: Optional[List[AzureVirtualMachineScaleSetIPConfiguration]] = field(default=None, metadata={'description': 'Specifies the ip configurations of the network interface.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The network configuration name."})
    network_security_group: Optional[str] = field(default=None, metadata={"description": ""})
    primary: Optional[bool] = field(default=None, metadata={'description': 'Specifies the primary network interface in case the virtual machine has more than 1 network interface.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetNetworkProfile:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_network_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "health_probe": S("healthProbe", "id"),
        "network_api_version": S("networkApiVersion"),
        "network_interface_configurations": S("networkInterfaceConfigurations")
        >> ForallBend(AzureVirtualMachineScaleSetNetworkConfiguration.mapping),
    }
    health_probe: Optional[str] = field(default=None, metadata={"description": "The api entity reference."})
    network_api_version: Optional[str] = field(default=None, metadata={'description': 'Specifies the microsoft. Network api version used when creating networking resources in the network interface configurations for virtual machine scale set with orchestration mode flexible.'})  # fmt: skip
    network_interface_configurations: Optional[List[AzureVirtualMachineScaleSetNetworkConfiguration]] = field(default=None, metadata={'description': 'The list of network configurations.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetExtension(AzureSubResourceReadOnly):
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_extension"
    mapping: ClassVar[Dict[str, Bender]] = AzureSubResourceReadOnly.mapping | {
        "auto_upgrade_minor_version": S("properties", "autoUpgradeMinorVersion"),
        "enable_automatic_upgrade": S("properties", "enableAutomaticUpgrade"),
        "force_update_tag": S("properties", "forceUpdateTag"),
        "name": S("name"),
        "protected_settings": S("properties", "protectedSettings"),
        "protected_settings_from_key_vault": S("properties", "protectedSettingsFromKeyVault")
        >> Bend(AzureKeyVaultSecretReference.mapping),
        "provision_after_extensions": S("properties", "provisionAfterExtensions"),
        "provisioning_state": S("properties", "provisioningState"),
        "publisher": S("properties", "publisher"),
        "settings": S("properties", "settings"),
        "suppress_failures": S("properties", "suppressFailures"),
        "type": S("properties", "type"),
        "type_handler_version": S("properties", "typeHandlerVersion"),
    }
    auto_upgrade_minor_version: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the extension should use a newer minor version if one is available at deployment time. Once deployed, however, the extension will not upgrade minor versions unless redeployed, even with this property set to true.'})  # fmt: skip
    enable_automatic_upgrade: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether the extension should be automatically upgraded by the platform if there is a newer version of the extension available.'})  # fmt: skip
    force_update_tag: Optional[str] = field(default=None, metadata={'description': 'If a value is provided and is different from the previous value, the extension handler will be forced to update even if the extension configuration has not changed.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the extension."})
    protected_settings: Optional[Any] = field(default=None, metadata={'description': 'The extension can contain either protectedsettings or protectedsettingsfromkeyvault or no protected settings at all.'})  # fmt: skip
    protected_settings_from_key_vault: Optional[AzureKeyVaultSecretReference] = field(default=None, metadata={'description': 'Describes a reference to key vault secret.'})  # fmt: skip
    provision_after_extensions: Optional[List[str]] = field(default=None, metadata={'description': 'Collection of extension names after which this extension needs to be provisioned.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state, which only appears in the response.'})  # fmt: skip
    publisher: Optional[str] = field(default=None, metadata={'description': 'The name of the extension handler publisher.'})  # fmt: skip
    settings: Optional[Any] = field(default=None, metadata={'description': 'Json formatted public settings for the extension.'})  # fmt: skip
    suppress_failures: Optional[bool] = field(default=None, metadata={'description': 'Indicates whether failures stemming from the extension will be suppressed (operational failures such as not connecting to the vm will not be suppressed regardless of this value). The default is false.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Specifies the type of the extension; an example is customscriptextension.'})  # fmt: skip
    type_handler_version: Optional[str] = field(default=None, metadata={'description': 'Specifies the version of the script handler.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetExtensionProfile:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_extension_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "extensions": S("extensions") >> ForallBend(AzureVirtualMachineScaleSetExtension.mapping),
        "extensions_time_budget": S("extensionsTimeBudget"),
    }
    extensions: Optional[List[AzureVirtualMachineScaleSetExtension]] = field(default=None, metadata={'description': 'The virtual machine scale set child extension resources.'})  # fmt: skip
    extensions_time_budget: Optional[str] = field(default=None, metadata={'description': 'Specifies the time alloted for all extensions to start. The time duration should be between 15 minutes and 120 minutes (inclusive) and should be specified in iso 8601 format. The default value is 90 minutes (pt1h30m). Minimum api-version: 2020-06-01.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetHardwareProfile:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_hardware_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "vm_size_properties": S("vmSizeProperties") >> Bend(AzureVMSizeProperties.mapping)
    }
    vm_size_properties: Optional[AzureVMSizeProperties] = field(default=None, metadata={'description': 'Specifies vm size property settings on the virtual machine.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSecurityPostureReference:
    kind: ClassVar[str] = "azure_security_posture_reference"
    mapping: ClassVar[Dict[str, Bender]] = {
        "exclude_extensions": S("excludeExtensions") >> ForallBend(AzureVirtualMachineExtension.mapping),
        "id": S("id"),
    }
    exclude_extensions: Optional[List[AzureVirtualMachineExtension]] = field(default=None, metadata={'description': 'List of virtual machine extensions to exclude when applying the security posture.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'The security posture reference id in the form of /communitygalleries/{communitygalleryname}/securitypostures/{securityposturename}/versions/{major. Minor. Patch}|{major. *}|latest.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetVMProfile:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_vm_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "application_profile": S("applicationProfile") >> Bend(AzureApplicationProfile.mapping),
        "billing_profile": S("billingProfile", "maxPrice"),
        "capacity_reservation": S("capacityReservation") >> Bend(AzureCapacityReservationProfile.mapping),
        "diagnostics_profile": S("diagnosticsProfile") >> Bend(AzureDiagnosticsProfile.mapping),
        "eviction_policy": S("evictionPolicy"),
        "extension_profile": S("extensionProfile") >> Bend(AzureVirtualMachineScaleSetExtensionProfile.mapping),
        "hardware_profile": S("hardwareProfile") >> Bend(AzureVirtualMachineScaleSetHardwareProfile.mapping),
        "license_type": S("licenseType"),
        "network_profile": S("networkProfile") >> Bend(AzureVirtualMachineScaleSetNetworkProfile.mapping),
        "os_profile": S("osProfile") >> Bend(AzureVirtualMachineScaleSetOSProfile.mapping),
        "priority": S("priority"),
        "scheduled_events_profile": S("scheduledEventsProfile") >> Bend(AzureScheduledEventsProfile.mapping),
        "security_posture_reference": S("securityPostureReference") >> Bend(AzureSecurityPostureReference.mapping),
        "security_profile": S("securityProfile") >> Bend(AzureSecurityProfile.mapping),
        "service_artifact_reference": S("serviceArtifactReference", "id"),
        "storage_profile": S("storageProfile") >> Bend(AzureVirtualMachineScaleSetStorageProfile.mapping),
        "user_data": S("userData"),
    }
    application_profile: Optional[AzureApplicationProfile] = field(default=None, metadata={'description': 'Contains the list of gallery applications that should be made available to the vm/vmss.'})  # fmt: skip
    billing_profile: Optional[float] = field(default=None, metadata={'description': 'Specifies the billing related details of a azure spot vm or vmss. Minimum api-version: 2019-03-01.'})  # fmt: skip
    capacity_reservation: Optional[AzureCapacityReservationProfile] = field(default=None, metadata={'description': 'The parameters of a capacity reservation profile.'})  # fmt: skip
    diagnostics_profile: Optional[AzureDiagnosticsProfile] = field(default=None, metadata={'description': 'Specifies the boot diagnostic settings state. Minimum api-version: 2015-06-15.'})  # fmt: skip
    eviction_policy: Optional[str] = field(default=None, metadata={'description': 'Specifies the eviction policy for the azure spot vm/vmss.'})  # fmt: skip
    extension_profile: Optional[AzureVirtualMachineScaleSetExtensionProfile] = field(default=None, metadata={'description': 'Describes a virtual machine scale set extension profile.'})  # fmt: skip
    hardware_profile: Optional[AzureVirtualMachineScaleSetHardwareProfile] = field(default=None, metadata={'description': 'Specifies the hardware settings for the virtual machine scale set.'})  # fmt: skip
    license_type: Optional[str] = field(default=None, metadata={'description': 'Specifies that the image or disk that is being used was licensed on-premises. Possible values for windows server operating system are: windows_client windows_server possible values for linux server operating system are: rhel_byos (for rhel) sles_byos (for suse) for more information, see [azure hybrid use benefit for windows server](https://docs. Microsoft. Com/azure/virtual-machines/windows/hybrid-use-benefit-licensing) [azure hybrid use benefit for linux server](https://docs. Microsoft. Com/azure/virtual-machines/linux/azure-hybrid-benefit-linux) minimum api-version: 2015-06-15.'})  # fmt: skip
    network_profile: Optional[AzureVirtualMachineScaleSetNetworkProfile] = field(default=None, metadata={'description': 'Describes a virtual machine scale set network profile.'})  # fmt: skip
    os_profile: Optional[AzureVirtualMachineScaleSetOSProfile] = field(default=None, metadata={'description': 'Describes a virtual machine scale set os profile.'})  # fmt: skip
    priority: Optional[str] = field(default=None, metadata={'description': 'Specifies the priority for a standalone virtual machine or the virtual machines in the scale set. Low enum will be deprecated in the future, please use spot as the enum to deploy azure spot vm/vmss.'})  # fmt: skip
    scheduled_events_profile: Optional[AzureScheduledEventsProfile] = field(default=None, metadata={"description": ""})
    security_posture_reference: Optional[AzureSecurityPostureReference] = field(default=None, metadata={'description': 'Specifies the security posture to be used for all virtual machines in the scale set. Minimum api-version: 2023-03-01.'})  # fmt: skip
    security_profile: Optional[AzureSecurityProfile] = field(default=None, metadata={'description': 'Specifies the security profile settings for the virtual machine or virtual machine scale set.'})  # fmt: skip
    service_artifact_reference: Optional[str] = field(default=None, metadata={'description': 'Specifies the service artifact reference id used to set same image version for all virtual machines in the scale set when using latest image version. Minimum api-version: 2022-11-01.'})  # fmt: skip
    storage_profile: Optional[AzureVirtualMachineScaleSetStorageProfile] = field(default=None, metadata={'description': 'Describes a virtual machine scale set storage profile.'})  # fmt: skip
    user_data: Optional[str] = field(default=None, metadata={'description': 'Userdata for the virtual machines in the scale set, which must be base-64 encoded. Customer should not pass any secrets in here. Minimum api-version: 2021-03-01.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureScaleInPolicy:
    kind: ClassVar[str] = "azure_scale_in_policy"
    mapping: ClassVar[Dict[str, Bender]] = {"force_deletion": S("forceDeletion"), "rules": S("rules")}
    force_deletion: Optional[bool] = field(default=None, metadata={'description': 'This property allows you to specify if virtual machines chosen for removal have to be force deleted when a virtual machine scale set is being scaled-in. (feature in preview).'})  # fmt: skip
    rules: Optional[List[str]] = field(default=None, metadata={'description': 'The rules to be followed when scaling-in a virtual machine scale set. Possible values are: **default** when a virtual machine scale set is scaled in, the scale set will first be balanced across zones if it is a zonal scale set. Then, it will be balanced across fault domains as far as possible. Within each fault domain, the virtual machines chosen for removal will be the newest ones that are not protected from scale-in. **oldestvm** when a virtual machine scale set is being scaled-in, the oldest virtual machines that are not protected from scale-in will be chosen for removal. For zonal virtual machine scale sets, the scale set will first be balanced across zones. Within each zone, the oldest virtual machines that are not protected will be chosen for removal. **newestvm** when a virtual machine scale set is being scaled-in, the newest virtual machines that are not protected from scale-in will be chosen for removal. For zonal virtual machine scale sets, the scale set will first be balanced across zones. Within each zone, the newest virtual machines that are not protected will be chosen for removal.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSpotRestorePolicy:
    kind: ClassVar[str] = "azure_spot_restore_policy"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("enabled"), "restore_timeout": S("restoreTimeout")}
    enabled: Optional[bool] = field(default=None, metadata={'description': 'Enables the spot-try-restore feature where evicted vmss spot instances will be tried to be restored opportunistically based on capacity availability and pricing constraints.'})  # fmt: skip
    restore_timeout: Optional[str] = field(default=None, metadata={'description': 'Timeout value expressed as an iso 8601 time duration after which the platform will not try to restore the vmss spot instances.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePriorityMixPolicy:
    kind: ClassVar[str] = "azure_priority_mix_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "base_regular_priority_count": S("baseRegularPriorityCount"),
        "regular_priority_percentage_above_base": S("regularPriorityPercentageAboveBase"),
    }
    base_regular_priority_count: Optional[int] = field(default=None, metadata={'description': 'The base number of regular priority vms that will be created in this scale set as it scales out.'})  # fmt: skip
    regular_priority_percentage_above_base: Optional[int] = field(default=None, metadata={'description': 'The percentage of vm instances, after the base regular priority count has been reached, that are expected to use regular priority.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetIdentity:
    kind: ClassVar[str] = "azure_virtual_machine_scale_set_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The principal id of virtual machine scale set identity. This property will only be provided for a system assigned identity.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenant id associated with the virtual machine scale set. This property will only be provided for a system assigned identity.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of identity used for the virtual machine scale set. The type systemassigned, userassigned includes both an implicitly created identity and a set of user assigned identities. The type none will remove any identities from the virtual machine scale set.'})  # fmt: skip
    user_assigned_identities: Optional[Dict[str, AzurePrincipalidClientid]] = field(default=None, metadata={'description': 'The list of user identities associated with the virtual machine. The user identity dictionary key references will be arm resource ids in the form: /subscriptions/{subscriptionid}/resourcegroups/{resourcegroupname}/providers/microsoft. Managedidentity/userassignedidentities/{identityname}.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSet(AzureResource, BaseAutoScalingGroup):
    kind: ClassVar[str] = "azure_virtual_machine_scale_set"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_load_balancer", "azure_subnet"]},
        "successors": {"default": ["azure_virtual_machine_scale_set_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("properties", "timeCreated"),
        "scale_set_capabilities": S("properties", "additionalCapabilities")
        >> Bend(AzureAdditionalCapabilities.mapping),
        "automatic_repairs_policy": S("properties", "automaticRepairsPolicy")
        >> Bend(AzureAutomaticRepairsPolicy.mapping),
        "constrained_maximum_capacity": S("properties", "constrainedMaximumCapacity"),
        "do_not_run_extensions_on_overprovisioned_vm_s": S("properties", "doNotRunExtensionsOnOverprovisionedVMs"),
        "extended_location": S("extendedLocation") >> Bend(AzureExtendedLocation.mapping),
        "host_group": S("properties", "hostGroup", "id"),
        "scale_set_identity": S("identity") >> Bend(AzureVirtualMachineScaleSetIdentity.mapping),
        "orchestration_mode": S("properties", "orchestrationMode"),
        "overprovision": S("properties", "overprovision"),
        "azure_plan": S("plan") >> Bend(AzurePlan.mapping),
        "platform_fault_domain_count": S("properties", "platformFaultDomainCount"),
        "priority_mix_policy": S("properties", "priorityMixPolicy") >> Bend(AzurePriorityMixPolicy.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "proximity_placement_group": S("properties", "proximityPlacementGroup", "id"),
        "scale_in_policy": S("properties", "scaleInPolicy") >> Bend(AzureScaleInPolicy.mapping),
        "single_placement_group": S("properties", "singlePlacementGroup"),
        "azure_sku": S("sku") >> Bend(AzureSku.mapping),
        "spot_restore_policy": S("properties", "spotRestorePolicy") >> Bend(AzureSpotRestorePolicy.mapping),
        "time_created": S("properties", "timeCreated"),
        "unique_id": S("properties", "uniqueId"),
        "upgrade_policy": S("properties", "upgradePolicy") >> Bend(AzureUpgradePolicy.mapping),
        "virtual_machine_profile": S("properties", "virtualMachineProfile")
        >> Bend(AzureVirtualMachineScaleSetVMProfile.mapping),
        "zone_balance": S("properties", "zoneBalance"),
    }
    scale_set_capabilities: Optional[AzureAdditionalCapabilities] = field(default=None, metadata={'description': 'Enables or disables a capability on the virtual machine or virtual machine scale set.'})  # fmt: skip
    automatic_repairs_policy: Optional[AzureAutomaticRepairsPolicy] = field(default=None, metadata={'description': 'Specifies the configuration parameters for automatic repairs on the virtual machine scale set.'})  # fmt: skip
    constrained_maximum_capacity: Optional[bool] = field(default=None, metadata={'description': 'Optional property which must either be set to true or omitted.'})  # fmt: skip
    do_not_run_extensions_on_overprovisioned_vm_s: Optional[bool] = field(default=None, metadata={'description': 'When overprovision is enabled, extensions are launched only on the requested number of vms which are finally kept. This property will hence ensure that the extensions do not run on the extra overprovisioned vms.'})  # fmt: skip
    extended_location: Optional[AzureExtendedLocation] = field(default=None, metadata={'description': 'The complex type of the extended location.'})  # fmt: skip
    host_group: Optional[str] = field(default=None, metadata={"description": ""})
    scale_set_identity: Optional[AzureVirtualMachineScaleSetIdentity] = field(default=None, metadata={'description': 'Identity for the virtual machine scale set.'})  # fmt: skip
    orchestration_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the orchestration mode for the virtual machine scale set.'})  # fmt: skip
    overprovision: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether the virtual machine scale set should be overprovisioned.'})  # fmt: skip
    azure_plan: Optional[AzurePlan] = field(default=None, metadata={'description': 'Specifies information about the marketplace image used to create the virtual machine. This element is only used for marketplace images. Before you can use a marketplace image from an api, you must enable the image for programmatic use. In the azure portal, find the marketplace image that you want to use and then click **want to deploy programmatically, get started ->**. Enter any required information and then click **save**.'})  # fmt: skip
    platform_fault_domain_count: Optional[int] = field(default=None, metadata={'description': 'Fault domain count for each placement group.'})  # fmt: skip
    priority_mix_policy: Optional[AzurePriorityMixPolicy] = field(default=None, metadata={'description': 'Specifies the target splits for spot and regular priority vms within a scale set with flexible orchestration mode. With this property the customer is able to specify the base number of regular priority vms created as the vmss flex instance scales out and the split between spot and regular priority vms after this base target has been reached.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The provisioning state, which only appears in the response.'})  # fmt: skip
    proximity_placement_group: Optional[str] = field(default=None, metadata={"description": ""})
    scale_in_policy: Optional[AzureScaleInPolicy] = field(default=None, metadata={'description': 'Describes a scale-in policy for a virtual machine scale set.'})  # fmt: skip
    single_placement_group: Optional[bool] = field(default=None, metadata={'description': 'When true this limits the scale set to a single placement group, of max size 100 virtual machines. Note: if singleplacementgroup is true, it may be modified to false. However, if singleplacementgroup is false, it may not be modified to true.'})  # fmt: skip
    azure_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Describes a virtual machine scale set sku. Note: if the new vm sku is not supported on the hardware the scale set is currently on, you need to deallocate the vms in the scale set before you modify the sku name.'})  # fmt: skip
    spot_restore_policy: Optional[AzureSpotRestorePolicy] = field(default=None, metadata={'description': 'Specifies the spot-try-restore properties for the virtual machine scale set. With this property customer can enable or disable automatic restore of the evicted spot vmss vm instances opportunistically based on capacity availability and pricing constraint.'})  # fmt: skip
    time_created: Optional[datetime] = field(default=None, metadata={'description': 'Specifies the time at which the virtual machine scale set resource was created. Minimum api-version: 2021-11-01.'})  # fmt: skip
    unique_id: Optional[str] = field(default=None, metadata={'description': 'Specifies the id which uniquely identifies a virtual machine scale set.'})  # fmt: skip
    upgrade_policy: Optional[AzureUpgradePolicy] = field(default=None, metadata={'description': 'Describes an upgrade policy - automatic, manual, or rolling.'})  # fmt: skip
    virtual_machine_profile: Optional[AzureVirtualMachineScaleSetVMProfile] = field(default=None, metadata={'description': 'Describes a virtual machine scale set virtual machine profile.'})  # fmt: skip
    zone_balance: Optional[bool] = field(default=None, metadata={'description': 'Whether to force strictly even virtual machine distribution cross x-zones in case there is zone outage. Zonebalance property can only be set if the zones property of the scale set contains more than one zone. If there are no zones or only one zone specified, then zonebalance property should not be set.'})  # fmt: skip

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def collect_vmss_instances() -> None:
            api_spec = AzureApiSpec(
                service="compute",
                version="2023-09-01",
                path=f"{self.id}/virtualMachines",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )

            items = graph_builder.client.list(api_spec)
            vmss_instance_ids = [str(item.get("id")) for item in items if item.get("id") is not None]

            AzureVirtualMachineScaleSetInstance.collect(items, graph_builder)

            for vmss_instance_id in vmss_instance_ids:
                graph_builder.add_edge(
                    self, edge_type=EdgeType.default, clazz=AzureVirtualMachineScaleSetInstance, id=vmss_instance_id
                )

        graph_builder.submit_work("azure_vm_scale_set", collect_vmss_instances)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (
            (vm_profile := self.virtual_machine_profile)
            and (net_profile := vm_profile.network_profile)
            and (net_i_configs := net_profile.network_interface_configurations)
        ):
            for net_i_config in net_i_configs:
                if ip_configs := net_i_config.ip_configurations:
                    for ip_config in ip_configs:
                        if baps := ip_config.load_balancer_backend_address_pools:
                            for bap in baps:
                                bap_id = "/".join(bap.split("/")[:-2])
                                builder.add_edge(
                                    self,
                                    edge_type=EdgeType.default,
                                    reverse=True,
                                    clazz=AzureLoadBalancer,
                                    id=bap_id,
                                )
                        if subnet_id := ip_config.subnet:
                            builder.add_edge(
                                self,
                                edge_type=EdgeType.default,
                                reverse=True,
                                clazz=AzureSubnet,
                                id=subnet_id,
                            )


@define(eq=False, slots=False)
class AzureVirtualMachineSize(AzureResource, BaseInstanceType):
    kind: ClassVar[str] = "azure_virtual_machine_size"
    api_spec: ClassVar[AzureApiSpec] = AzureApiSpec(
        service="compute",
        version="2023-03-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/vmSizes",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "max_data_disk_count": S("maxDataDiskCount"),
        "memory_in_mb": S("memoryInMB"),
        "number_of_cores": S("numberOfCores"),
        "os_disk_size_in_mb": S("osDiskSizeInMB"),
        "resource_disk_size_in_mb": S("resourceDiskSizeInMB"),
        "instance_type": S("name"),
        "instance_cores": S("numberOfCores"),
        "instance_memory": S("memoryInMB") >> F(lambda x: int(x) / 1024),
    }
    max_data_disk_count: Optional[int] = field(default=None, metadata={'description': 'The maximum number of data disks that can be attached to the virtual machine size.'})  # fmt: skip
    memory_in_mb: Optional[int] = field(default=None, metadata={'description': 'The amount of memory, in mb, supported by the virtual machine size.'})  # fmt: skip
    number_of_cores: Optional[int] = field(default=None, metadata={'description': 'The number of cores supported by the virtual machine size. For constrained vcpu capable vm sizes, this number represents the total vcpus of quota that the vm uses. For accurate vcpu count, please refer to https://docs. Microsoft. Com/azure/virtual-machines/constrained-vcpu or https://docs. Microsoft. Com/rest/api/compute/resourceskus/list.'})  # fmt: skip
    os_disk_size_in_mb: Optional[int] = field(default=None, metadata={'description': 'The os disk size, in mb, allowed by the virtual machine size.'})  # fmt: skip
    resource_disk_size_in_mb: Optional[int] = field(default=None, metadata={'description': 'The resource disk size, in mb, allowed by the virtual machine size.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    _is_provider_link: bool = False

    def pre_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        self.location = graph_builder.location.name if graph_builder.location else ""

    def after_collect(self, builder: GraphBuilder, source: Json) -> None:
        if (location := self.location) and (sku_name := self.name):
            api_spec = AzureApiSpec(
                service="compute",
                version="2023-01-01-preview",
                path=f"https://prices.azure.com/api/retail/prices?$filter=serviceName eq 'Virtual Machines' and armSkuName eq '{sku_name}' and armRegionName eq '{location}' and type eq 'Consumption' and isPrimaryMeterRegion eq true",
                path_parameters=[],
                query_parameters=["api-version"],
                access_path="Items",
                expect_array=True,
            )
            items = builder.client.list(api_spec)
            for item in items:
                if (product_name := item.get("productName")) and ("Windows" not in product_name):
                    self.ondemand_cost = item.get("unitPrice")


@define(eq=False, slots=False)
class AzureVirtualMachineScaleSetInstance(AzureVirtualMachineBase):
    # note: instances are collected as part of collecting AzureVirtualMachineScaleSets

    kind: ClassVar[str] = "azure_virtual_machine_scale_set_instance"


resources: List[Type[AzureResource]] = [
    AzureAvailabilitySet,
    AzureCapacityReservationGroup,
    AzureCloudService,
    AzureDedicatedHostGroup,
    AzureDiskTypePricing,
    AzureDisk,
    AzureDiskType,
    AzureDiskAccess,
    AzureDiskEncryptionSet,
    AzureGallery,
    AzureImage,
    AzureProximityPlacementGroup,
    # AzureResourceSku, TODO: handle resource skus correctly
    AzureRestorePointCollection,
    AzureSnapshot,
    AzureSshPublicKeyResource,
    AzureVirtualMachine,
    AzureVirtualMachineScaleSet,
    AzureVirtualMachineSize,
]
