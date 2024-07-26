from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    AzureProxyResource,
    AzureResourceIdentity,
    AzureSku,
    AzureTrackedResource,
    GraphBuilder,
    MicrosoftResource,
    AzureSystemData,
)
from fixlib.baseresources import EdgeType, ModelReference
from fixlib.json_bender import Bender, S, ForallBend, Bend
from fixlib.types import Json

service_name = "azure_mysql"


@define(eq=False, slots=False)
class AzurePostgresqlServerADAdministrator(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_postgresql_ad_administrator"
    # Collect via AzurePostgresqlServer()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "object_id": S("properties", "objectId"),
        "principal_name": S("properties", "principalName"),
        "principal_type": S("properties", "principalType"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "tenant_id": S("properties", "tenantId"),
    }
    object_id: Optional[str] = field(default=None, metadata={'description': 'The objectId of the Active Directory administrator.'})  # fmt: skip
    principal_name: Optional[str] = field(default=None, metadata={'description': 'Active Directory administrator principal name.'})  # fmt: skip
    principal_type: Optional[str] = field(default=None, metadata={'description': 'The principal type used to represent the type of Active Directory Administrator.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'The tenantId of the Active Directory administrator.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStorageTierCapability:
    kind: ClassVar[str] = "azure_storage_tier_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "iops": S("iops"),
        "is_baseline": S("isBaseline"),
        "name": S("name"),
        "status": S("status"),
        "tier_name": S("tierName"),
    }
    iops: Optional[int] = field(default=None, metadata={"description": "Supported IOPS for this storage tier"})
    is_baseline: Optional[bool] = field(default=None, metadata={'description': 'Indicates if this is a baseline storage tier or not'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Name to represent Storage tier capability"})
    status: Optional[str] = field(default=None, metadata={"description": "Status os this storage tier"})
    tier_name: Optional[str] = field(default=None, metadata={"description": "Storage tier name"})


@define(eq=False, slots=False)
class AzureStorageMBCapability:
    kind: ClassVar[str] = "azure_storage_mb_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "status": S("status"),
        "storage_size_mb": S("storageSizeMB"),
        "supported_iops": S("supportedIops"),
        "supported_upgradable_tier_list": S("supportedUpgradableTierList")
        >> ForallBend(AzureStorageTierCapability.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "storage MB name"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    storage_size_mb: Optional[int] = field(default=None, metadata={"description": "storage size in MB"})
    supported_iops: Optional[int] = field(default=None, metadata={"description": "supported IOPS"})
    supported_upgradable_tier_list: Optional[List[AzureStorageTierCapability]] = field(default=None, metadata={'description': ''})  # fmt: skip


@define(eq=False, slots=False)
class AzureStorageEditionCapability:
    kind: ClassVar[str] = "azure_storage_edition_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "status": S("status"),
        "supported_storage_mb": S("supportedStorageMB") >> ForallBend(AzureStorageMBCapability.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "storage edition name"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_storage_mb: Optional[List[AzureStorageMBCapability]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureVcoreCapability:
    kind: ClassVar[str] = "azure_vcore_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "status": S("status"),
        "supported_iops": S("supportedIops"),
        "supported_memory_per_vcore_mb": S("supportedMemoryPerVcoreMB"),
        "v_cores": S("vCores"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "vCore name"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_iops: Optional[int] = field(default=None, metadata={"description": "supported IOPS"})
    supported_memory_per_vcore_mb: Optional[int] = field(default=None, metadata={'description': 'supported memory per vCore in MB'})  # fmt: skip
    v_cores: Optional[int] = field(default=None, metadata={"description": "supported vCores"})


@define(eq=False, slots=False)
class AzureServerVersionCapability:
    kind: ClassVar[str] = "azure_server_version_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "status": S("status"),
        "supported_vcores": S("supportedVcores") >> ForallBend(AzureVcoreCapability.mapping),
        "supported_versions_to_upgrade": S("supportedVersionsToUpgrade"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "server version"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_vcores: Optional[List[AzureVcoreCapability]] = field(default=None, metadata={"description": ""})
    supported_versions_to_upgrade: Optional[List[str]] = field(default=None, metadata={'description': 'Supported servers versions to upgrade'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFlexibleServerEditionCapability:
    kind: ClassVar[str] = "azure_flexible_server_edition_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "status": S("status"),
        "supported_server_versions": S("supportedServerVersions") >> ForallBend(AzureServerVersionCapability.mapping),
        "supported_storage_editions": S("supportedStorageEditions")
        >> ForallBend(AzureStorageEditionCapability.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Server edition name"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_server_versions: Optional[List[AzureServerVersionCapability]] = field(default=None, metadata={'description': 'The list of server versions supported by this server edition.'})  # fmt: skip
    supported_storage_editions: Optional[List[AzureStorageEditionCapability]] = field(default=None, metadata={'description': 'The list of editions supported by this server edition.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNodeTypeCapability:
    kind: ClassVar[str] = "azure_node_type_capability"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "node_type": S("nodeType"), "status": S("status")}
    name: Optional[str] = field(default=None, metadata={"description": "note type name"})
    node_type: Optional[str] = field(default=None, metadata={"description": "note type"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})


@define(eq=False, slots=False)
class AzureHyperscaleNodeEditionCapability:
    kind: ClassVar[str] = "azure_hyperscale_node_edition_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "status": S("status"),
        "supported_node_types": S("supportedNodeTypes") >> ForallBend(AzureNodeTypeCapability.mapping),
        "supported_server_versions": S("supportedServerVersions") >> ForallBend(AzureServerVersionCapability.mapping),
        "supported_storage_editions": S("supportedStorageEditions")
        >> ForallBend(AzureStorageEditionCapability.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Server edition name"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_node_types: Optional[List[AzureNodeTypeCapability]] = field(default=None, metadata={'description': 'The list of Node Types supported by this server edition.'})  # fmt: skip
    supported_server_versions: Optional[List[AzureServerVersionCapability]] = field(default=None, metadata={'description': 'The list of server versions supported by this server edition.'})  # fmt: skip
    supported_storage_editions: Optional[List[AzureStorageEditionCapability]] = field(default=None, metadata={'description': 'The list of editions supported by this server edition.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFastProvisioningEditionCapability:
    kind: ClassVar[str] = "azure_fast_provisioning_edition_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "supported_server_versions": S("supportedServerVersions"),
        "supported_sku": S("supportedSku"),
        "supported_storage_gb": S("supportedStorageGb"),
    }
    supported_server_versions: Optional[str] = field(default=None, metadata={'description': 'Fast provisioning supported version'})  # fmt: skip
    supported_sku: Optional[str] = field(default=None, metadata={'description': 'Fast provisioning supported sku name'})  # fmt: skip
    supported_storage_gb: Optional[int] = field(default=None, metadata={'description': 'Fast provisioning supported storage in Gb'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePostgresqlCapability(MicrosoftResource):
    kind: ClassVar[str] = "azure_postgresql_capability"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="postgresql",
        version="2022-12-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/locations/{location}/capabilities",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "fast_provisioning_supported": S("fastProvisioningSupported"),
        "geo_backup_supported": S("geoBackupSupported"),
        "status": S("status"),
        "supported_fast_provisioning_editions": S("supportedFastProvisioningEditions")
        >> ForallBend(AzureFastProvisioningEditionCapability.mapping),
        "supported_flexible_server_editions": S("supportedFlexibleServerEditions")
        >> ForallBend(AzureFlexibleServerEditionCapability.mapping),
        "supported_ha_mode": S("supportedHAMode"),
        "supported_hyperscale_node_editions": S("supportedHyperscaleNodeEditions")
        >> ForallBend(AzureHyperscaleNodeEditionCapability.mapping),
        "capability_zone": S("zone"),
        "zone_redundant_ha_and_geo_backup_supported": S("zoneRedundantHaAndGeoBackupSupported"),
        "zone_redundant_ha_supported": S("zoneRedundantHaSupported"),
    }
    fast_provisioning_supported: Optional[bool] = field(default=None, metadata={'description': 'A value indicating whether fast provisioning is supported in this region.'})  # fmt: skip
    geo_backup_supported: Optional[bool] = field(default=None, metadata={'description': 'A value indicating whether a new server in this region can have geo-backups to paired region.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_fast_provisioning_editions: Optional[List[AzureFastProvisioningEditionCapability]] = field(default=None, metadata={'description': ''})  # fmt: skip
    supported_flexible_server_editions: Optional[List[AzureFlexibleServerEditionCapability]] = field(default=None, metadata={'description': ''})  # fmt: skip
    supported_ha_mode: Optional[List[str]] = field(default=None, metadata={'description': 'Supported high availability mode'})  # fmt: skip
    supported_hyperscale_node_editions: Optional[List[AzureHyperscaleNodeEditionCapability]] = field(default=None, metadata={'description': ''})  # fmt: skip
    capability_zone: Optional[str] = field(default=None, metadata={"description": "zone name"})
    zone_redundant_ha_and_geo_backup_supported: Optional[bool] = field(default=None, metadata={'description': 'A value indicating whether a new server in this region can have geo-backups to paired region.'})  # fmt: skip
    zone_redundant_ha_supported: Optional[bool] = field(default=None, metadata={'description': 'A value indicating whether a new server in this region can support multi zone HA.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip

    def pre_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if builder_location := graph_builder.location:
            self.location = builder_location.long_name


@define(eq=False, slots=False)
class AzurePostgresqlServerConfiguration(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_postgresql_server_configuration"
    # Collect via AzurePostgresqlServer()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "allowed_values": S("properties", "allowedValues"),
        "data_type": S("properties", "dataType"),
        "default_value": S("properties", "defaultValue"),
        "description": S("properties", "description"),
        "documentation_link": S("properties", "documentationLink"),
        "is_config_pending_restart": S("properties", "isConfigPendingRestart"),
        "is_dynamic_config": S("properties", "isDynamicConfig"),
        "is_read_only": S("properties", "isReadOnly"),
        "configuration_source": S("properties", "source"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "unit": S("properties", "unit"),
        "value": S("properties", "value"),
    }
    allowed_values: Optional[str] = field(default=None, metadata={'description': 'Allowed values of the configuration.'})  # fmt: skip
    data_type: Optional[str] = field(default=None, metadata={"description": "Data type of the configuration."})
    default_value: Optional[str] = field(default=None, metadata={"description": "Default value of the configuration."})
    description: Optional[str] = field(default=None, metadata={"description": "Description of the configuration."})
    documentation_link: Optional[str] = field(default=None, metadata={'description': 'Configuration documentation link.'})  # fmt: skip
    is_config_pending_restart: Optional[bool] = field(default=None, metadata={'description': 'Configuration is pending restart or not.'})  # fmt: skip
    is_dynamic_config: Optional[bool] = field(default=None, metadata={'description': 'Configuration dynamic or static.'})  # fmt: skip
    is_read_only: Optional[bool] = field(default=None, metadata={"description": "Configuration read-only or not."})
    configuration_source: Optional[str] = field(default=None, metadata={"description": "Source of the configuration."})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    unit: Optional[str] = field(default=None, metadata={"description": "Configuration unit."})
    value: Optional[str] = field(default=None, metadata={"description": "Value of the configuration."})


@define(eq=False, slots=False)
class AzurePostgresqlServerDatabase(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_postgresql_server_database"
    # Collect via AzurePostgresqlServer()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "charset": S("properties", "charset"),
        "collation": S("properties", "collation"),
    }
    charset: Optional[str] = field(default=None, metadata={"description": "The charset of the database."})
    collation: Optional[str] = field(default=None, metadata={"description": "The collation of the database."})


@define(eq=False, slots=False)
class AzurePostgresqlServerFirewallRule(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_postgresql_server_firewall_rule"
    # Collect via AzurePostgresqlServer()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "end_ip_address": S("properties", "endIpAddress"),
        "start_ip_address": S("properties", "startIpAddress"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    end_ip_address: Optional[str] = field(default=None, metadata={'description': 'The end IP address of the server firewall rule. Must be IPv4 format.'})  # fmt: skip
    start_ip_address: Optional[str] = field(default=None, metadata={'description': 'The start IP address of the server firewall rule. Must be IPv4 format.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureOperationDisplay:
    kind: ClassVar[str] = "azure_operation_display"
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("description"),
        "operation": S("operation"),
        "provider": S("provider"),
        "resource": S("resource"),
    }
    description: Optional[str] = field(default=None, metadata={"description": "Operation description."})
    operation: Optional[str] = field(default=None, metadata={'description': 'Localized friendly name for the operation.'})  # fmt: skip
    provider: Optional[str] = field(default=None, metadata={"description": "Operation resource provider name."})
    resource: Optional[str] = field(default=None, metadata={'description': 'Resource on which the operation is performed.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAuthConfig:
    kind: ClassVar[str] = "azure_auth_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "active_directory_auth": S("activeDirectoryAuth"),
        "password_auth": S("passwordAuth"),
        "tenant_id": S("tenantId"),
    }
    active_directory_auth: Optional[str] = field(default=None, metadata={'description': 'If Enabled, Azure Active Directory authentication is enabled.'})  # fmt: skip
    password_auth: Optional[str] = field(default=None, metadata={'description': 'If Enabled, Password authentication is enabled.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={"description": "Tenant id of the server."})


@define(eq=False, slots=False)
class AzureDataEncryption:
    kind: ClassVar[str] = "azure_data_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {
        "primary_key_uri": S("primaryKeyURI"),
        "primary_user_assigned_identity_id": S("primaryUserAssignedIdentityId"),
        "type": S("type"),
    }
    primary_key_uri: Optional[str] = field(default=None, metadata={'description': 'URI for the key for data encryption for primary server.'})  # fmt: skip
    primary_user_assigned_identity_id: Optional[str] = field(default=None, metadata={'description': 'Resource Id for the User assigned identity to be used for data encryption for primary server.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'Data encryption type to depict if it is System Managed vs Azure Key vault.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBackup:
    kind: ClassVar[str] = "azure_backup"
    mapping: ClassVar[Dict[str, Bender]] = {
        "backup_retention_days": S("backupRetentionDays"),
        "earliest_restore_date": S("earliestRestoreDate"),
        "geo_redundant_backup": S("geoRedundantBackup"),
    }
    backup_retention_days: Optional[int] = field(default=None, metadata={'description': 'Backup retention days for the server.'})  # fmt: skip
    earliest_restore_date: Optional[datetime] = field(default=None, metadata={'description': 'The earliest restore point time (ISO8601 format) for server.'})  # fmt: skip
    geo_redundant_backup: Optional[str] = field(default=None, metadata={'description': 'A value indicating whether Geo-Redundant backup is enabled on the server.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNetwork:
    kind: ClassVar[str] = "azure_network"
    mapping: ClassVar[Dict[str, Bender]] = {
        "delegated_subnet_resource_id": S("delegatedSubnetResourceId"),
        "private_dns_zone_arm_resource_id": S("privateDnsZoneArmResourceId"),
        "public_network_access": S("publicNetworkAccess"),
    }
    delegated_subnet_resource_id: Optional[str] = field(default=None, metadata={'description': 'Delegated subnet arm resource id. This is required to be passed during create, in case we want the server to be VNET injected, i.e. Private access server. During update, pass this only if we want to update the value for Private DNS zone.'})  # fmt: skip
    private_dns_zone_arm_resource_id: Optional[str] = field(default=None, metadata={'description': 'Private dns zone arm resource id. This is required to be passed during create, in case we want the server to be VNET injected, i.e. Private access server. During update, pass this only if we want to update the value for Private DNS zone.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'public network access is enabled or not'})  # fmt: skip


@define(eq=False, slots=False)
class AzureHighAvailability:
    kind: ClassVar[str] = "azure_high_availability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "mode": S("mode"),
        "standby_availability_zone": S("standbyAvailabilityZone"),
        "state": S("state"),
    }
    mode: Optional[str] = field(default=None, metadata={"description": "The HA mode for the server."})
    standby_availability_zone: Optional[str] = field(default=None, metadata={'description': 'availability zone information of the standby.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'A state of a HA server that is visible to user.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMaintenanceWindow:
    kind: ClassVar[str] = "azure_maintenance_window"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_window": S("customWindow"),
        "day_of_week": S("dayOfWeek"),
        "start_hour": S("startHour"),
        "start_minute": S("startMinute"),
    }
    custom_window: Optional[str] = field(default=None, metadata={'description': 'indicates whether custom window is enabled or disabled'})  # fmt: skip
    day_of_week: Optional[int] = field(default=None, metadata={"description": "day of week for maintenance window"})
    start_hour: Optional[int] = field(default=None, metadata={"description": "start hour for maintenance window"})
    start_minute: Optional[int] = field(default=None, metadata={"description": "start minute for maintenance window"})


@define(eq=False, slots=False)
class AzurePostgresqlServer(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_postgresql_server"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="postgresql",
        version="2022-12-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/flexibleServers",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_postgresql_ad_administrator",
                "azure_postgresql_server_configuration",
                "azure_postgresql_server_database",
                "azure_postgresql_server_firewall_rule",
                "azure_postgresql_server_backup",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "administrator_login": S("properties", "administratorLogin"),
        "administrator_login_password": S("properties", "administratorLoginPassword"),
        "auth_config": S("properties", "authConfig") >> Bend(AzureAuthConfig.mapping),
        "availability_zone": S("properties", "availabilityZone"),
        "server_backup": S("properties", "backup") >> Bend(AzureBackup.mapping),
        "create_mode": S("properties", "createMode"),
        "data_encryption": S("properties", "dataEncryption") >> Bend(AzureDataEncryption.mapping),
        "fully_qualified_domain_name": S("properties", "fullyQualifiedDomainName"),
        "high_availability": S("properties", "highAvailability") >> Bend(AzureHighAvailability.mapping),
        "user_identity": S("identity") >> Bend(AzureResourceIdentity.mapping),
        "server_maintenance_window": S("properties", "maintenanceWindow") >> Bend(AzureMaintenanceWindow.mapping),
        "minor_version": S("properties", "minorVersion"),
        "server_network": S("properties", "network") >> Bend(AzureNetwork.mapping),
        "point_in_time_utc": S("properties", "pointInTimeUTC"),
        "replica_capacity": S("properties", "replicaCapacity"),
        "replication_role": S("properties", "replicationRole"),
        "server_sku": S("sku") >> Bend(AzureSku.mapping),
        "source_server_resource_id": S("properties", "sourceServerResourceId"),
        "state": S("properties", "state"),
        "storage_size_gb": S("properties", "storage", "storageSizeGB"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "version": S("properties", "version"),
    }
    administrator_login: Optional[str] = field(default=None, metadata={'description': 'The administrator s login name of a server. Can only be specified when the server is being created (and is required for creation).'})  # fmt: skip
    administrator_login_password: Optional[str] = field(default=None, metadata={'description': 'The administrator login password (required for server creation).'})  # fmt: skip
    auth_config: Optional[AzureAuthConfig] = field(default=None, metadata={'description': 'Authentication configuration properties of a server'})  # fmt: skip
    availability_zone: Optional[str] = field(default=None, metadata={'description': 'availability zone information of the server.'})  # fmt: skip
    server_backup: Optional[AzureBackup] = field(
        default=None, metadata={"description": "Backup properties of a server"}
    )
    create_mode: Optional[str] = field(default=None, metadata={'description': 'The mode to create a new PostgreSQL server.'})  # fmt: skip
    data_encryption: Optional[AzureDataEncryption] = field(default=None, metadata={'description': 'Data encryption properties of a server'})  # fmt: skip
    fully_qualified_domain_name: Optional[str] = field(default=None, metadata={'description': 'The fully qualified domain name of a server.'})  # fmt: skip
    high_availability: Optional[AzureHighAvailability] = field(default=None, metadata={'description': 'High availability properties of a server'})  # fmt: skip
    user_identity: Optional[AzureResourceIdentity] = field(default=None, metadata={'description': 'Information describing the identities associated with this application.'})  # fmt: skip
    server_maintenance_window: Optional[AzureMaintenanceWindow] = field(default=None, metadata={'description': 'Maintenance window properties of a server.'})  # fmt: skip
    minor_version: Optional[str] = field(default=None, metadata={"description": "The minor version of the server."})
    server_network: Optional[AzureNetwork] = field(
        default=None, metadata={"description": "Network properties of a server."}
    )
    point_in_time_utc: Optional[datetime] = field(default=None, metadata={'description': 'Restore point creation time (ISO8601 format), specifying the time to restore from. It s required when createMode is PointInTimeRestore or GeoRestore .'})  # fmt: skip
    replica_capacity: Optional[int] = field(default=None, metadata={"description": "Replicas allowed for a server."})
    replication_role: Optional[str] = field(default=None, metadata={'description': 'Used to indicate role of the server in replication set.'})  # fmt: skip
    server_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Sku information related properties of a server.'})  # fmt: skip
    source_server_resource_id: Optional[str] = field(default=None, metadata={'description': 'The source server resource ID to restore from. It s required when createMode is PointInTimeRestore or GeoRestore or Replica . This property is returned only for Replica server'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'A state of a server that is visible to user.'})  # fmt: skip
    storage_size_gb: Optional[int] = field(default=None, metadata={"description": "Storage properties of a server"})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The version of a server."})

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        server_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
    ) -> None:
        path = f"{server_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="sql",
            version="2022-12-01",
            path=path,
            path_parameters=[],
            query_parameters=["api-version"],
            access_path="value",
            expect_array=True,
        )
        items = graph_builder.client.list(api_spec)
        if not items:
            return
        collected = class_instance.collect(items, graph_builder)
        for clazz in collected:
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if server_id := self.id:
            resources_to_collect = [
                ("administrators", AzurePostgresqlServerADAdministrator),
                ("configurations", AzurePostgresqlServerConfiguration),
                ("databases", AzurePostgresqlServerDatabase),
                ("firewallRules", AzurePostgresqlServerFirewallRule),
                ("backups", AzurePostgresqlServerBackup),
            ]

            for resource_type, resource_class in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    server_id,
                    resource_type,
                    resource_class,
                )

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if location := self.location:
            builder.add_edge(
                self,
                edge_type=EdgeType.default,
                clazz=AzurePostgresqlCapability,
                location=location,
            )


@define(eq=False, slots=False)
class AzurePostgresqlServerBackup(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_postgresql_server_backup"
    # Collect via AzurePostgresqlServer()
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "backup_type": S("properties", "backupType"),
        "completed_time": S("properties", "completedTime"),
        "backup_source": S("properties", "source"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    backup_type: Optional[str] = field(default=None, metadata={"description": "Backup type."})
    completed_time: Optional[datetime] = field(default=None, metadata={'description': 'Backup completed time (ISO8601 format).'})  # fmt: skip
    backup_source: Optional[str] = field(default=None, metadata={"description": "Backup source"})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip


resources: List[Type[MicrosoftResource]] = [
    AzurePostgresqlServerADAdministrator,
    AzurePostgresqlCapability,
    AzurePostgresqlServerConfiguration,
    AzurePostgresqlServerDatabase,
    AzurePostgresqlServerFirewallRule,
    AzurePostgresqlServer,
    AzurePostgresqlServerBackup,
]
