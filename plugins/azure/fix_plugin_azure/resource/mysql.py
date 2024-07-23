from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Any, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    AzurePrivateLinkServiceConnectionState,
    GraphBuilder,
    MicrosoftResource,
    AzureSystemData,
)
from fix_plugin_azure.resource.microsoft_graph import MicrosoftGraphUser
from fixlib.baseresources import BaseDatabase, BaseType, DatabaseInstanceStatus, EdgeType, ModelReference
from fixlib.graph import BySearchCriteria
from fixlib.json_bender import K, AsBool, Bender, S, ForallBend, Bend, MapEnum, MapValue
from fixlib.types import Json

service_name = "azure_mysql"


@define(eq=False, slots=False)
class AzureMysqlServerADAdministrator(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_ad_administrator"
    # Collect via AzureMysqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "type": S("type"),
        "administrator_type": S("properties", "administratorType"),
        "identity_resource_id": S("properties", "identityResourceId"),
        "login": S("properties", "login"),
        "sid": S("properties", "sid"),
        "tenant_id": S("properties", "tenantId"),
    }
    administrator_type: Optional[str] = field(default=None, metadata={'description': 'Type of the sever administrator.'})  # fmt: skip
    identity_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource id of the identity used for AAD Authentication.'})  # fmt: skip
    login: Optional[str] = field(default=None, metadata={"description": "Login name of the server administrator."})
    sid: Optional[str] = field(default=None, metadata={"description": "SID (object ID) of the server administrator."})
    tenant_id: Optional[str] = field(default=None, metadata={"description": "Tenant ID of the administrator."})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if user_id := self.sid:
            builder.add_deferred_edge(
                from_node=self,
                to_node=BySearchCriteria(f'is({MicrosoftGraphUser.kind}) and reported.id=="{user_id}"'),
            )


@define(eq=False, slots=False)
class AzureStorageEditionCapability:
    kind: ClassVar[str] = "azure_storage_edition_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_backup_interval_hours": S("maxBackupIntervalHours"),
        "max_backup_retention_days": S("maxBackupRetentionDays"),
        "max_storage_size": S("maxStorageSize"),
        "min_backup_interval_hours": S("minBackupIntervalHours"),
        "min_backup_retention_days": S("minBackupRetentionDays"),
        "min_storage_size": S("minStorageSize"),
        "name": S("name"),
    }
    max_backup_interval_hours: Optional[int] = field(default=None, metadata={'description': 'Maximum backup interval hours'})  # fmt: skip
    max_backup_retention_days: Optional[int] = field(default=None, metadata={'description': 'Maximum backup retention days'})  # fmt: skip
    max_storage_size: Optional[int] = field(default=None, metadata={'description': 'The maximum supported storage size.'})  # fmt: skip
    min_backup_interval_hours: Optional[int] = field(default=None, metadata={'description': 'Minimal backup interval hours'})  # fmt: skip
    min_backup_retention_days: Optional[int] = field(default=None, metadata={'description': 'Minimal backup retention days'})  # fmt: skip
    min_storage_size: Optional[int] = field(default=None, metadata={'description': 'The minimal supported storage size.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "storage edition name"})


@define(eq=False, slots=False)
class AzureSkuCapabilityV2:
    kind: ClassVar[str] = "azure_sku_capability_v2"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "supported_ha_mode": S("supportedHAMode"),
        "supported_iops": S("supportedIops"),
        "supported_memory_per_v_core_mb": S("supportedMemoryPerVCoreMB"),
        "supported_zones": S("supportedZones"),
        "v_cores": S("vCores"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "vCore name"})
    supported_ha_mode: Optional[List[str]] = field(default=None, metadata={'description': 'Supported high availability mode'})  # fmt: skip
    supported_iops: Optional[int] = field(default=None, metadata={"description": "supported IOPS"})
    supported_memory_per_v_core_mb: Optional[int] = field(default=None, metadata={'description': 'supported memory per vCore in MB'})  # fmt: skip
    supported_zones: Optional[List[str]] = field(default=None, metadata={"description": "Supported zones"})
    v_cores: Optional[int] = field(default=None, metadata={"description": "supported vCores"})


@define(eq=False, slots=False)
class AzureServerEditionCapabilityV2:
    kind: ClassVar[str] = "azure_server_edition_capability_v2"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_sku": S("defaultSku"),
        "default_storage_size": S("defaultStorageSize"),
        "name": S("name"),
        "supported_skus": S("supportedSkus") >> ForallBend(AzureSkuCapabilityV2.mapping),
        "supported_storage_editions": S("supportedStorageEditions")
        >> ForallBend(AzureStorageEditionCapability.mapping),
    }
    default_sku: Optional[str] = field(default=None, metadata={"description": "Default Sku name"})
    default_storage_size: Optional[int] = field(default=None, metadata={"description": "Default storage size"})
    name: Optional[str] = field(default=None, metadata={"description": "Server edition name"})
    supported_skus: Optional[List[AzureSkuCapabilityV2]] = field(default=None, metadata={'description': 'A list of supported Skus'})  # fmt: skip
    supported_storage_editions: Optional[List[AzureStorageEditionCapability]] = field(default=None, metadata={'description': 'A list of supported storage editions'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMysqlCapabilitySet(MicrosoftResource, BaseType):
    kind: ClassVar[str] = "azure_mysql_capability_set"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="mysql",
        version="2023-12-30",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/locations/{location}/capabilitySets",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "supported_flexible_server_editions_v2": S("properties", "supportedFlexibleServerEditions")
        >> ForallBend(AzureServerEditionCapabilityV2.mapping),
        "supported_geo_backup_regions": S("properties", "supportedGeoBackupRegions"),
        "supported_server_versions": S("properties")
        >> S("supportedServerVersions", default=[])
        >> ForallBend(S("name")),
    }
    supported_flexible_server_editions_v2: Optional[List[AzureServerEditionCapabilityV2]] = field(default=None, metadata={'description': 'A list of supported flexible server editions.'})  # fmt: skip
    supported_geo_backup_regions: Optional[List[str]] = field(default=None, metadata={'description': 'supported geo backup regions'})  # fmt: skip
    supported_server_versions: Optional[List[str]] = field(default=None, metadata={'description': 'A list of supported server versions.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip
    display_location_name: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def pre_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if builder_location := graph_builder.location:
            self.display_location_name = builder_location.long_name


@define(eq=False, slots=False)
class AzureSkuCapability:
    kind: ClassVar[str] = "azure_sku_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "supported_iops": S("supportedIops"),
        "supported_memory_per_v_core_mb": S("supportedMemoryPerVCoreMB"),
        "v_cores": S("vCores"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "vCore name"})
    supported_iops: Optional[int] = field(default=None, metadata={"description": "supported IOPS"})
    supported_memory_per_v_core_mb: Optional[int] = field(default=None, metadata={'description': 'supported memory per vCore in MB'})  # fmt: skip
    v_cores: Optional[int] = field(default=None, metadata={"description": "supported vCores"})


@define(eq=False, slots=False)
class AzureServerVersionCapability:
    kind: ClassVar[str] = "azure_server_version_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "supported_skus": S("supportedSkus") >> ForallBend(AzureSkuCapability.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "server version"})
    supported_skus: Optional[List[AzureSkuCapability]] = field(default=None, metadata={'description': 'A list of supported Skus'})  # fmt: skip


@define(eq=False, slots=False)
class AzureServerEditionCapability:
    kind: ClassVar[str] = "azure_server_edition_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "supported_server_versions": S("supportedServerVersions") >> ForallBend(AzureServerVersionCapability.mapping),
        "supported_storage_editions": S("supportedStorageEditions")
        >> ForallBend(AzureStorageEditionCapability.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Server edition name"})
    supported_server_versions: Optional[List[AzureServerVersionCapability]] = field(default=None, metadata={'description': 'A list of supported server versions.'})  # fmt: skip
    supported_storage_editions: Optional[List[AzureStorageEditionCapability]] = field(default=None, metadata={'description': 'A list of supported storage editions'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMysqlCapability(MicrosoftResource, BaseType):
    kind: ClassVar[str] = "azure_mysql_capability"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="mysql",
        version="2023-12-30",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/locations/{location}/capabilities",
        path_parameters=["subscriptionId", "location"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("zone"),
        "name": S("zone"),
        "tags": S("tags", default={}),
        "supported_flexible_server_editions": S("supportedFlexibleServerEditions")
        >> ForallBend(AzureServerEditionCapability.mapping),
        "supported_geo_backup_regions": S("supportedGeoBackupRegions"),
        "supported_ha_mode": S("supportedHAMode"),
        "capability_zone": S("zone"),
    }
    supported_flexible_server_editions: Optional[List[AzureServerEditionCapability]] = field(default=None, metadata={'description': 'A list of supported flexible server editions.'})  # fmt: skip
    supported_geo_backup_regions: Optional[List[str]] = field(default=None, metadata={'description': 'supported geo backup regions'})  # fmt: skip
    supported_ha_mode: Optional[List[str]] = field(default=None, metadata={'description': 'Supported high availability mode'})  # fmt: skip
    capability_zone: Optional[str] = field(default=None, metadata={"description": "zone name"})
    display_location_name: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def pre_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if builder_location := graph_builder.location:
            self.display_location_name = builder_location.long_name


@define(eq=False, slots=False)
class AzureMysqlServerConfiguration(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_configuration"
    # Collect via AzureMysqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "allowed_values": S("properties", "allowedValues"),
        "current_value": S("properties", "currentValue"),
        "data_type": S("properties", "dataType"),
        "default_value": S("properties", "defaultValue"),
        "description": S("properties", "description"),
        "documentation_link": S("properties", "documentationLink"),
        "is_config_pending_restart": S("properties", "isConfigPendingRestart") >> AsBool(),
        "is_dynamic_config": S("properties", "isDynamicConfig") >> AsBool(),
        "is_read_only": S("properties", "isReadOnly") >> AsBool(),
        "source": S("properties", "source"),
        "value": S("properties", "value"),
    }
    allowed_values: Optional[str] = field(default=None, metadata={'description': 'Allowed values of the configuration.'})  # fmt: skip
    current_value: Optional[str] = field(default=None, metadata={"description": "Current value of the configuration."})
    data_type: Optional[str] = field(default=None, metadata={"description": "Data type of the configuration."})
    default_value: Optional[str] = field(default=None, metadata={"description": "Default value of the configuration."})
    description: Optional[str] = field(default=None, metadata={"description": "Description of the configuration."})
    documentation_link: Optional[str] = field(default=None, metadata={'description': 'The link used to get the document from community or Azure site.'})  # fmt: skip
    is_config_pending_restart: Optional[bool] = field(default=None, metadata={'description': 'If is the configuration pending restart or not.'})  # fmt: skip
    is_dynamic_config: Optional[bool] = field(default=None, metadata={'description': 'If is the configuration dynamic.'})  # fmt: skip
    is_read_only: Optional[bool] = field(default=None, metadata={"description": "If is the configuration read only."})
    source: Optional[str] = field(default=None, metadata={"description": "Source of the configuration."})
    value: Optional[str] = field(default=None, metadata={"description": "Value of the configuration."})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureMysqlServerDatabase(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_database"
    # Collect via AzureMysqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "charset": S("properties", "charset"),
        "collation": S("properties", "collation"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    charset: Optional[str] = field(default=None, metadata={"description": "The charset of the database."})
    collation: Optional[str] = field(default=None, metadata={"description": "The collation of the database."})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureMysqlServerFirewallRule(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_firewall_rule"
    # Collect via AzureMysqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "end_ip_address": S("properties", "endIpAddress"),
        "start_ip_address": S("properties", "startIpAddress"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
    }
    end_ip_address: Optional[str] = field(default=None, metadata={'description': 'The end IP address of the server firewall rule. Must be IPv4 format.'})  # fmt: skip
    start_ip_address: Optional[str] = field(default=None, metadata={'description': 'The start IP address of the server firewall rule. Must be IPv4 format.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureMysqlServerLogFile(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_log_file"
    # Collect via AzureMysqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "ctime": S("properties", "createdTime"),
        "mtime": S("properties", "lastModifiedTime"),
        "created_time": S("properties", "createdTime"),
        "last_modified_time": S("properties", "lastModifiedTime"),
        "size_in_kb": S("properties", "sizeInKB"),
        "url": S("properties", "url"),
    }
    created_time: Optional[datetime] = field(default=None, metadata={'description': 'Creation timestamp of the log file.'})  # fmt: skip
    last_modified_time: Optional[datetime] = field(default=None, metadata={'description': 'Last modified timestamp of the log file.'})  # fmt: skip
    size_in_kb: Optional[int] = field(default=None, metadata={"description": "The size in kb of the logFile."})
    url: Optional[str] = field(default=None, metadata={"description": "The url to download the log file from."})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureMysqlServerMaintenance(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_maintenance"
    # Collect via AzureMysqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "maintenance_available_schedule_max_time": S("properties", "maintenanceAvailableScheduleMaxTime"),
        "maintenance_available_schedule_min_time": S("properties", "maintenanceAvailableScheduleMinTime"),
        "maintenance_description": S("properties", "maintenanceDescription"),
        "maintenance_end_time": S("properties", "maintenanceEndTime"),
        "maintenance_execution_end_time": S("properties", "maintenanceExecutionEndTime"),
        "maintenance_execution_start_time": S("properties", "maintenanceExecutionStartTime"),
        "maintenance_start_time": S("properties", "maintenanceStartTime"),
        "maintenance_state": S("properties", "maintenanceState"),
        "maintenance_title": S("properties", "maintenanceTitle"),
        "maintenance_type": S("properties", "maintenanceType"),
        "provisioning_state": S("properties", "provisioningState"),
    }
    maintenance_available_schedule_max_time: Optional[datetime] = field(default=None, metadata={'description': 'The max time the maintenance can be rescheduled.'})  # fmt: skip
    maintenance_available_schedule_min_time: Optional[datetime] = field(default=None, metadata={'description': 'The min time the maintenance can be rescheduled.'})  # fmt: skip
    maintenance_description: Optional[str] = field(default=None, metadata={'description': 'The maintenance description.'})  # fmt: skip
    maintenance_end_time: Optional[datetime] = field(default=None, metadata={'description': 'The end time for a maintenance.'})  # fmt: skip
    maintenance_execution_end_time: Optional[datetime] = field(default=None, metadata={'description': 'The end time for a maintenance execution.'})  # fmt: skip
    maintenance_execution_start_time: Optional[datetime] = field(default=None, metadata={'description': 'The start time for a maintenance execution.'})  # fmt: skip
    maintenance_start_time: Optional[datetime] = field(default=None, metadata={'description': 'The start time for a maintenance.'})  # fmt: skip
    maintenance_state: Optional[str] = field(default=None, metadata={'description': 'The current status of this maintenance.'})  # fmt: skip
    maintenance_title: Optional[str] = field(default=None, metadata={"description": "The maintenance title."})
    maintenance_type: Optional[str] = field(default=None, metadata={"description": "The type of this maintenance."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrivateEndpointConnection:
    kind: ClassVar[str] = "azure_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "group_ids": S("properties", "groupIds"),
        "id": S("id"),
        "name": S("name"),
        "private_endpoint": S("properties", "privateEndpoint", "id"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionState.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
    }
    group_ids: Optional[List[str]] = field(default=None, metadata={'description': 'The group ids for the private endpoint resource.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'Fully qualified resource ID for the resource. E.g. /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName} '})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the resource"})
    private_endpoint: Optional[str] = field(default=None, metadata={"description": "The private endpoint resource."})
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionState] = field(default=None, metadata={'description': 'A collection of information about the state of the connection between service consumer and provider.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureMySQLServerIdentity:
    kind: ClassVar[str] = "azure_my_sql_server_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    principal_id: Optional[str] = field(default=None, metadata={"description": "ObjectId from the KeyVault"})
    tenant_id: Optional[str] = field(default=None, metadata={"description": "TenantId from the KeyVault"})
    type: Optional[str] = field(default=None, metadata={"description": "Type of managed service identity."})
    user_assigned_identities: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Metadata of user assigned identity.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMySQLServerSku:
    kind: ClassVar[str] = "azure_my_sql_server_sku"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "tier": S("tier")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the sku, e.g. Standard_D32s_v3."})
    tier: Optional[str] = field(default=None, metadata={'description': 'The tier of the particular SKU, e.g. GeneralPurpose.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDataEncryption:
    kind: ClassVar[str] = "azure_data_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {
        "geo_backup_key_uri": S("geoBackupKeyURI"),
        "geo_backup_user_assigned_identity_id": S("geoBackupUserAssignedIdentityId"),
        "primary_key_uri": S("primaryKeyURI"),
        "primary_user_assigned_identity_id": S("primaryUserAssignedIdentityId"),
        "type": S("type"),
    }
    geo_backup_key_uri: Optional[str] = field(default=None, metadata={'description': 'Geo backup key uri as key vault can t cross region, need cmk in same region as geo backup'})  # fmt: skip
    geo_backup_user_assigned_identity_id: Optional[str] = field(default=None, metadata={'description': 'Geo backup user identity resource id as identity can t cross region, need identity in same region as geo backup'})  # fmt: skip
    primary_key_uri: Optional[str] = field(default=None, metadata={"description": "Primary key uri"})
    primary_user_assigned_identity_id: Optional[str] = field(default=None, metadata={'description': 'Primary user identity resource id'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The key type, AzureKeyVault for enable cmk, SystemManaged for disable cmk.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureStorage:
    kind: ClassVar[str] = "azure_storage"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_grow": S("autoGrow"),
        "auto_io_scaling": S("autoIoScaling"),
        "iops": S("iops"),
        "log_on_disk": S("logOnDisk"),
        "storage_size_gb": S("storageSizeGB"),
        "storage_sku": S("storageSku"),
    }
    auto_grow: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate whether value is Enabled or Disabled '})  # fmt: skip
    auto_io_scaling: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate whether value is Enabled or Disabled '})  # fmt: skip
    iops: Optional[int] = field(default=None, metadata={"description": "Storage IOPS for a server."})
    log_on_disk: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate whether value is Enabled or Disabled '})  # fmt: skip
    storage_size_gb: Optional[int] = field(default=None, metadata={'description': 'Max storage size allowed for a server.'})  # fmt: skip
    storage_sku: Optional[str] = field(default=None, metadata={"description": "The sku name of the server storage."})


@define(eq=False, slots=False)
class AzureBackup:
    kind: ClassVar[str] = "azure_backup"
    mapping: ClassVar[Dict[str, Bender]] = {
        "backup_interval_hours": S("backupIntervalHours"),
        "backup_retention_days": S("backupRetentionDays"),
        "earliest_restore_date": S("earliestRestoreDate"),
        "geo_redundant_backup": S("geoRedundantBackup"),
    }
    backup_interval_hours: Optional[int] = field(default=None, metadata={'description': 'Backup interval hours for the server.'})  # fmt: skip
    backup_retention_days: Optional[int] = field(default=None, metadata={'description': 'Backup retention days for the server.'})  # fmt: skip
    earliest_restore_date: Optional[datetime] = field(default=None, metadata={'description': 'Earliest restore point creation time (ISO8601 format)'})  # fmt: skip
    geo_redundant_backup: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate whether value is Enabled or Disabled '})  # fmt: skip


@define(eq=False, slots=False)
class AzureHighAvailability:
    kind: ClassVar[str] = "azure_high_availability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "mode": S("mode"),
        "standby_availability_zone": S("standbyAvailabilityZone"),
        "state": S("state"),
    }
    mode: Optional[str] = field(default=None, metadata={"description": "High availability mode for a server."})
    standby_availability_zone: Optional[str] = field(default=None, metadata={'description': 'Availability zone of the standby server.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The state of server high availability."})


@define(eq=False, slots=False)
class AzureNetwork:
    kind: ClassVar[str] = "azure_network"
    mapping: ClassVar[Dict[str, Bender]] = {
        "delegated_subnet_resource_id": S("delegatedSubnetResourceId"),
        "private_dns_zone_resource_id": S("privateDnsZoneResourceId"),
        "public_network_access": S("publicNetworkAccess"),
    }
    delegated_subnet_resource_id: Optional[str] = field(default=None, metadata={'description': 'Delegated subnet resource id used to setup vnet for a server.'})  # fmt: skip
    private_dns_zone_resource_id: Optional[str] = field(default=None, metadata={'description': 'Private DNS zone resource id.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate whether value is Enabled or Disabled '})  # fmt: skip


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
class AzureImportSourceProperties:
    kind: ClassVar[str] = "azure_import_source_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_dir_path": S("dataDirPath"),
        "sas_token": S("sasToken"),
        "storage_type": S("storageType"),
        "storage_url": S("storageUrl"),
    }
    data_dir_path: Optional[str] = field(default=None, metadata={'description': 'Relative path of data directory in storage.'})  # fmt: skip
    sas_token: Optional[str] = field(default=None, metadata={'description': 'Sas token for accessing source storage. Read and list permissions are required for sas token.'})  # fmt: skip
    storage_type: Optional[str] = field(default=None, metadata={"description": "Storage type of import source."})
    storage_url: Optional[str] = field(default=None, metadata={"description": "Uri of the import source storage."})


@define(eq=False, slots=False)
class AzureMysqlServer(MicrosoftResource, BaseDatabase):
    kind: ClassVar[str] = "azure_mysql_server"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="mysql",
        version="2023-12-30",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/flexibleServers",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_mysql_server_backup_v2",
                "azure_mysql_server_backup",
                "azure_mysql_server_private_link_resource",
                "azure_mysql_server_maintenance",
                "azure_mysql_server_log_file",
                "azure_mysql_server_firewall_rule",
                "azure_mysql_server_database",
                "azure_mysql_server_configuration",
                "azure_mysql_server_ad_administrator",
                "azure_mysql_capability_set",
                "azure_mysql_capability",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "location": S("location"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "administrator_login": S("properties", "administratorLogin"),
        "administrator_login_password": S("properties", "administratorLoginPassword"),
        "availability_zone": S("properties", "availabilityZone"),
        "backup": S("properties", "backup") >> Bend(AzureBackup.mapping),
        "create_mode": S("properties", "createMode"),
        "data_encryption": S("properties", "dataEncryption") >> Bend(AzureDataEncryption.mapping),
        "fully_qualified_domain_name": S("properties", "fullyQualifiedDomainName"),
        "high_availability": S("properties", "highAvailability") >> Bend(AzureHighAvailability.mapping),
        "mysql_server_identity": S("identity") >> Bend(AzureMySQLServerIdentity.mapping),
        "import_source_properties": S("properties", "importSourceProperties")
        >> Bend(AzureImportSourceProperties.mapping),
        "server_maintenance_window": S("properties", "maintenanceWindow") >> Bend(AzureMaintenanceWindow.mapping),
        "server_network": S("properties", "network") >> Bend(AzureNetwork.mapping),
        "mysql_server_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzurePrivateEndpointConnection.mapping),
        "replica_capacity": S("properties", "replicaCapacity"),
        "replication_role": S("properties", "replicationRole"),
        "restore_point_in_time": S("properties", "restorePointInTime"),
        "server_sku": S("sku") >> Bend(AzureMySQLServerSku.mapping),
        "source_server_resource_id": S("properties", "sourceServerResourceId"),
        "state": S("properties", "state"),
        "storage": S("properties", "storage") >> Bend(AzureStorage.mapping),
        "version": S("properties", "version"),
        "db_type": K("mysql"),
        "db_status": S("properties", "state")
        >> MapEnum(
            {
                "Disabled": DatabaseInstanceStatus.FAILED,
                "Dropping": DatabaseInstanceStatus.TERMINATED,
                "Ready": DatabaseInstanceStatus.AVAILABLE,
                "Starting": DatabaseInstanceStatus.BUSY,
                "Stopped": DatabaseInstanceStatus.STOPPED,
                "Stopping": DatabaseInstanceStatus.BUSY,
                "Updating": DatabaseInstanceStatus.BUSY,
            }
        ),
        "db_endpoint": S("properties", "fullyQualifiedDomainName"),
        "db_version": S("properties", "version"),
        "db_publicly_accessible": S("properties", "network", "publicNetworkAccess")
        >> MapValue(
            {
                "Disabled": False,
                "Enabled": True,
            },
            default=False,
        ),
        "instance_type": S("sku", "name"),
        "volume_size": S("properties", "storage", "storageSizeGB"),
        "volume_iops": S("properties", "storage", "iops"),
    }
    administrator_login: Optional[str] = field(default=None, metadata={'description': 'The administrator s login name of a server. Can only be specified when the server is being created (and is required for creation).'})  # fmt: skip
    administrator_login_password: Optional[str] = field(default=None, metadata={'description': 'The password of the administrator login (required for server creation).'})  # fmt: skip
    availability_zone: Optional[str] = field(default=None, metadata={'description': 'availability Zone information of the server.'})  # fmt: skip
    backup: Optional[AzureBackup] = field(default=None, metadata={'description': 'Storage Profile properties of a server'})  # fmt: skip
    create_mode: Optional[str] = field(default=None, metadata={'description': 'The mode to create a new MySQL server.'})  # fmt: skip
    data_encryption: Optional[AzureDataEncryption] = field(default=None, metadata={'description': 'The date encryption for cmk.'})  # fmt: skip
    fully_qualified_domain_name: Optional[str] = field(default=None, metadata={'description': 'The fully qualified domain name of a server.'})  # fmt: skip
    high_availability: Optional[AzureHighAvailability] = field(default=None, metadata={'description': 'High availability properties of a server'})  # fmt: skip
    mysql_server_identity: Optional[AzureMySQLServerIdentity] = field(default=None, metadata={'description': 'Properties to configure Identity for Bring your Own Keys'})  # fmt: skip
    import_source_properties: Optional[AzureImportSourceProperties] = field(default=None, metadata={'description': 'Import source related properties.'})  # fmt: skip
    server_maintenance_window: Optional[AzureMaintenanceWindow] = field(default=None, metadata={'description': 'Maintenance window of a server.'})  # fmt: skip
    server_network: Optional[AzureNetwork] = field(default=None, metadata={'description': 'Network related properties of a server'})  # fmt: skip
    mysql_server_private_endpoint_connections: Optional[List[AzurePrivateEndpointConnection]] = field(default=None, metadata={'description': 'PrivateEndpointConnections related properties of a server.'})  # fmt: skip
    replica_capacity: Optional[int] = field(default=None, metadata={'description': 'The maximum number of replicas that a primary server can have.'})  # fmt: skip
    replication_role: Optional[str] = field(default=None, metadata={"description": "The replication role."})
    restore_point_in_time: Optional[datetime] = field(default=None, metadata={'description': 'Restore point creation time (ISO8601 format), specifying the time to restore from.'})  # fmt: skip
    server_sku: Optional[AzureMySQLServerSku] = field(default=None, metadata={'description': 'Billing information related properties of a server.'})  # fmt: skip
    source_server_resource_id: Optional[str] = field(default=None, metadata={'description': 'The source MySQL server id.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The state of a server."})
    storage: Optional[AzureStorage] = field(default=None, metadata={'description': 'Storage Profile properties of a server'})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The version of a server."})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The geo-location where the resource lives'})  # fmt: skip

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        server_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        api_version: str,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{server_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="mysql",
            version=api_version,
            path=path,
            path_parameters=[],
            query_parameters=["api-version"],
            access_path="value",
            expect_array=True,
            expected_error_codes=expected_errors or [],
        )
        items = graph_builder.client.list(api_spec)
        if not items:
            return
        collected = class_instance.collect(items, graph_builder)
        for clazz in collected:
            graph_builder.add_edge(
                self,
                edge_type=EdgeType.default,
                id=clazz.id,
                clazz=class_instance,
            )

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if server_id := self.id:
            resources_to_collect = [
                ("backupsV2", AzureMysqlServerBackupV2, "2023-12-30", ["ServerNotExist"]),
                ("backups", AzureMysqlServerBackup, "2021-05-01", ["ServerNotExist"]),
                ("maintenances", AzureMysqlServerMaintenance, "2023-12-30", None),
                ("logFiles", AzureMysqlServerLogFile, "2023-12-30", ["ServerNotExist"]),
                ("firewallRules", AzureMysqlServerFirewallRule, "2021-05-01", None),
                ("databases", AzureMysqlServerDatabase, "2021-05-01", ["ServerUnavailableForOperation"]),
                ("configurations", AzureMysqlServerConfiguration, "2023-12-30", ["ServerUnavailableForOperation"]),
                ("administrators", AzureMysqlServerADAdministrator, "2023-12-30", None),
            ]

            for resource_type, resource_class, api_version, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    server_id,
                    resource_type,
                    resource_class,
                    api_version,
                    expected_errors,
                )
        if self.data_encryption:
            self.volume_encrypted = True
        else:
            self.volume_encrypted = False

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if location := self.location:
            builder.add_edge(
                self, edge_type=EdgeType.default, clazz=AzureMysqlCapability, display_location_name=location
            )
            builder.add_edge(
                self, edge_type=EdgeType.default, clazz=AzureMysqlCapabilitySet, display_location_name=location
            )


@define(eq=False, slots=False)
class AzureMysqlServerBackup(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_backup"
    # Collect via AzureMysqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
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
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


@define(eq=False, slots=False)
class AzureMysqlServerBackupV2(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_backup_v2"
    # Collect via AzureMysqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "type": S("type"),
        "ctime": S("systemData", "createdAt"),
        "mtime": S("systemData", "lastModifiedAt"),
        "backup_name_v2": S("properties", "backupNameV2"),
        "backup_type": S("properties", "backupType"),
        "completed_time": S("properties", "completedTime"),
        "provisioning_state": S("properties", "provisioningState"),
        "backup_source": S("properties", "source"),
    }
    backup_name_v2: Optional[str] = field(default=None, metadata={"description": "Backup name"})
    backup_type: Optional[str] = field(default=None, metadata={"description": ""})
    completed_time: Optional[datetime] = field(default=None, metadata={'description': 'Backup completed time (ISO8601 format).'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The current provisioning state.'})  # fmt: skip
    backup_source: Optional[str] = field(default=None, metadata={"description": "Backup source"})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={'description': 'The type of the resource. E.g. Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts '})  # fmt: skip


resources: List[Type[MicrosoftResource]] = [
    AzureMysqlServerADAdministrator,
    AzureMysqlCapabilitySet,
    AzureMysqlCapability,
    AzureMysqlServerConfiguration,
    AzureMysqlServerDatabase,
    AzureMysqlServerFirewallRule,
    AzureMysqlServerLogFile,
    AzureMysqlServerMaintenance,
    AzureMysqlServer,
    AzureMysqlServerBackup,
    AzureMysqlServerBackupV2,
]
