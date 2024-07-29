from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Any, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    AzurePrivateLinkServiceConnectionState,
    AzureServerBackup,
    AzureServerDataEncryption,
    AzureServerHighAvailability,
    AzureServerMaintenanceWindow,
    AzureServerNetwork,
    AzureSku,
    GraphBuilder,
    MicrosoftResource,
    AzureSystemData,
)
from fix_plugin_azure.resource.microsoft_graph import MicrosoftGraphUser
from fixlib.baseresources import (
    BaseDatabase,
    BaseDatabaseInstanceType,
    DatabaseInstanceStatus,
    EdgeType,
    ModelReference,
)
from fixlib.graph import BySearchCriteria
from fixlib.json_bender import F, K, AsBool, Bender, S, ForallBend, Bend, MapEnum, MapValue
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
class AzureSkuCapability:
    kind: ClassVar[str] = "azure_sku_capability"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "supported_ha_mode": S("supportedHAMode"),
        "supported_zones": S("supportedZones"),
        "supported_iops": S("supportedIops"),
        "supported_memory_per_v_core_mb": S("supportedMemoryPerVCoreMB"),
        "v_cores": S("vCores"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "vCore name"})
    supported_iops: Optional[int] = field(default=None, metadata={"description": "supported IOPS"})
    supported_memory_per_v_core_mb: Optional[int] = field(default=None, metadata={'description': 'supported memory per vCore in MB'})  # fmt: skip
    v_cores: Optional[int] = field(default=None, metadata={"description": "supported vCores"})
    supported_ha_mode: Optional[List[str]] = field(default=None, metadata={'description': 'Supported high availability mode'})  # fmt: skip
    supported_zones: Optional[List[str]] = field(default=None, metadata={"description": "Supported zones"})


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
        "default_sku": S("defaultSku"),
        "default_storage_size": S("defaultStorageSize"),
        "name": S("name"),
        "supported_server_versions": S("supportedServerVersions") >> ForallBend(AzureServerVersionCapability.mapping),
        "supported_storage_editions": S("supportedStorageEditions")
        >> ForallBend(AzureStorageEditionCapability.mapping),
        "supported_skus": S("supportedSkus") >> ForallBend(AzureSkuCapability.mapping),
    }
    default_sku: Optional[str] = field(default=None, metadata={"description": "Default Sku name"})
    default_storage_size: Optional[int] = field(default=None, metadata={"description": "Default storage size"})
    name: Optional[str] = field(default=None, metadata={"description": "Server edition name"})
    supported_server_versions: Optional[List[AzureServerVersionCapability]] = field(default=None, metadata={'description': 'A list of supported server versions.'})  # fmt: skip
    supported_storage_editions: Optional[List[AzureStorageEditionCapability]] = field(default=None, metadata={'description': 'A list of supported storage editions'})  # fmt: skip
    supported_skus: Optional[List[AzureSkuCapability]] = field(default=None, metadata={'description': 'A list of supported Skus'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMysqlCapability(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_capability"
    # api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
    #     service="mysql",
    #     version="2023-12-30",
    #     path="/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/locations/{location}/capabilities",
    #     path_parameters=["subscriptionId", "location"],
    #     query_parameters=["api-version"],
    #     access_path="value",
    #     expect_array=True,
    # )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("zone"),
        "name": S("zone"),
        "tags": S("tags", default={}),
        "supported_flexible_server_editions": S("supportedFlexibleServerEditions")
        >> ForallBend(AzureServerEditionCapability.mapping),
        "supported_geo_backup_regions": S("supportedGeoBackupRegions"),
        "supported_ha_mode": S("supportedHAMode"),
        "capability_zone": S("zone"),
        "location": S("location"),
    }
    supported_flexible_server_editions: Optional[List[AzureServerEditionCapability]] = field(default=None, metadata={'description': 'A list of supported flexible server editions.'})  # fmt: skip
    supported_geo_backup_regions: Optional[List[str]] = field(default=None, metadata={'description': 'supported geo backup regions'})  # fmt: skip
    supported_ha_mode: Optional[List[str]] = field(default=None, metadata={'description': 'Supported high availability mode'})  # fmt: skip
    capability_zone: Optional[str] = field(default=None, metadata={"description": "zone name"})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        # Create a list of all possible database configurations
        # This method goes through all the options for MySQL databases and lists every possible combination
        server_types = []
        if self.supported_flexible_server_editions:
            for edition in self.supported_flexible_server_editions:
                edition_name = edition.name
                storage_editions = edition.supported_storage_editions or []
                server_versions = edition.supported_server_versions or []

                for storage_edition in storage_editions:
                    storage_edition_dict = {
                        "maxBackupIntervalHours": storage_edition.max_backup_interval_hours,
                        "maxBackupRetentionDays": storage_edition.max_backup_retention_days,
                        "maxStorageSize": storage_edition.max_storage_size,
                        "minBackupIntervalHours": storage_edition.min_backup_interval_hours,
                        "minBackupRetentionDays": storage_edition.min_backup_retention_days,
                        "minStorageSize": storage_edition.min_storage_size,
                        "name": storage_edition.name,
                    }
                    for version in server_versions:
                        version_name = version.name
                        skus = version.supported_skus or []

                        for sku in skus:
                            sku_dict = {
                                "name": sku.name,
                                "vCores": sku.v_cores,
                                "supportedIops": sku.supported_iops,
                                "supportedMemoryPerVCoreMB": sku.supported_memory_per_v_core_mb,
                            }
                            server_type = {
                                "id": f"{sku.name}",
                                "name": f"{edition_name}_{sku.name}",
                                "capability_zone": self.capability_zone,
                                "supported_ha_mode": self.supported_ha_mode,
                                "server_edition_name": edition_name,
                                "storage_edition": storage_edition_dict,
                                "server_version": version_name,
                                "sku": sku_dict,
                                "location": self.location,
                            }
                            server_types.append(server_type)
        AzureMysqlServerType.collect(server_types, graph_builder)


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
class AzureMysqlServerType(MicrosoftResource, BaseDatabaseInstanceType):
    kind: ClassVar[str] = "azure_mysql_server_type"
    # Collect via AzureMysqlCapability()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "capability_zone": S("capability_zone"),
        "supported_ha_mode": S("supported_ha_mode"),
        "server_edition_name": S("server_edition_name"),
        "storage_edition": S("storage_edition") >> Bend(AzureStorageEditionCapability.mapping),
        "server_version": S("server_version"),
        "capability_sku": S("sku") >> Bend(AzureSkuCapability.mapping),
        "display_location": S("location"),
        "instance_cores": S("sku", "vCores"),
        "instance_memory": S("sku", "supportedMemoryPerVCoreMB") >> F(lambda mb: mb / 1024),
    }
    capability_zone: Optional[str] = field(default=None)
    supported_ha_mode: Optional[List[str]] = field(default=None)
    server_edition_name: Optional[str] = field(default=None)
    storage_edition: Optional[AzureStorageEditionCapability] = field(default=None)
    server_version: Optional[str] = field(default=None)
    capability_sku: Optional[AzureSkuCapability] = field(default=None)
    display_location: Optional[str] = field(default=None, metadata={"description": "Resource location."})


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
                "azure_mysql_server_backup",
                "azure_mysql_server_maintenance",
                "azure_mysql_server_log_file",
                "azure_mysql_server_firewall_rule",
                "azure_mysql_server_database",
                "azure_mysql_server_configuration",
                "azure_mysql_server_ad_administrator",
                "azure_mysql_server_type",
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
        "backup": S("properties", "backup") >> Bend(AzureServerBackup.mapping),
        "create_mode": S("properties", "createMode"),
        "data_encryption": S("properties", "dataEncryption") >> Bend(AzureServerDataEncryption.mapping),
        "fully_qualified_domain_name": S("properties", "fullyQualifiedDomainName"),
        "high_availability": S("properties", "highAvailability") >> Bend(AzureServerHighAvailability.mapping),
        "mysql_server_identity": S("identity") >> Bend(AzureMySQLServerIdentity.mapping),
        "import_source_properties": S("properties", "importSourceProperties")
        >> Bend(AzureImportSourceProperties.mapping),
        "server_maintenance_window": S("properties", "maintenanceWindow") >> Bend(AzureServerMaintenanceWindow.mapping),
        "server_network": S("properties", "network") >> Bend(AzureServerNetwork.mapping),
        "mysql_server_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzurePrivateEndpointConnection.mapping),
        "replica_capacity": S("properties", "replicaCapacity"),
        "replication_role": S("properties", "replicationRole"),
        "restore_point_in_time": S("properties", "restorePointInTime"),
        "server_sku": S("sku") >> Bend(AzureSku.mapping),
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
    backup: Optional[AzureServerBackup] = field(default=None, metadata={'description': 'Storage Profile properties of a server'})  # fmt: skip
    create_mode: Optional[str] = field(default=None, metadata={'description': 'The mode to create a new MySQL server.'})  # fmt: skip
    data_encryption: Optional[AzureServerDataEncryption] = field(default=None, metadata={'description': 'The date encryption for cmk.'})  # fmt: skip
    fully_qualified_domain_name: Optional[str] = field(default=None, metadata={'description': 'The fully qualified domain name of a server.'})  # fmt: skip
    high_availability: Optional[AzureServerHighAvailability] = field(default=None, metadata={'description': 'High availability properties of a server'})  # fmt: skip
    mysql_server_identity: Optional[AzureMySQLServerIdentity] = field(default=None, metadata={'description': 'Properties to configure Identity for Bring your Own Keys'})  # fmt: skip
    import_source_properties: Optional[AzureImportSourceProperties] = field(default=None, metadata={'description': 'Import source related properties.'})  # fmt: skip
    server_maintenance_window: Optional[AzureServerMaintenanceWindow] = field(default=None, metadata={'description': 'Maintenance window of a server.'})  # fmt: skip
    server_network: Optional[AzureServerNetwork] = field(default=None, metadata={'description': 'Network related properties of a server'})  # fmt: skip
    mysql_server_private_endpoint_connections: Optional[List[AzurePrivateEndpointConnection]] = field(default=None, metadata={'description': 'PrivateEndpointConnections related properties of a server.'})  # fmt: skip
    replica_capacity: Optional[int] = field(default=None, metadata={'description': 'The maximum number of replicas that a primary server can have.'})  # fmt: skip
    replication_role: Optional[str] = field(default=None, metadata={"description": "The replication role."})
    restore_point_in_time: Optional[datetime] = field(default=None, metadata={'description': 'Restore point creation time (ISO8601 format), specifying the time to restore from.'})  # fmt: skip
    server_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Billing information related properties of a server.'})  # fmt: skip
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
                ("backupsV2", AzureMysqlServerBackup, "2023-12-30", ["ServerNotExist"]),
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

        if location := self.location:

            def collect_capabilities() -> None:
                api_spec = AzureResourceSpec(
                    service="mysql",
                    version="2023-12-30",
                    path="/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/locations/"
                    + f"{location}/capabilities",
                    path_parameters=["subscriptionId"],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                # Set location for further connect_in_graph method
                for item in items:
                    item["location"] = location
                AzureMysqlCapability.collect(items, graph_builder)

            graph_builder.submit_work(service_name, collect_capabilities)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (
            (location := self.location)
            and (version := self.version)
            and (sku := self.server_sku)
            and (sku_type := sku.name)
        ):
            builder.add_edge(
                self,
                edge_type=EdgeType.default,
                clazz=AzureMysqlServerType,
                display_location=location,
                server_version=version,
                id=sku_type,
            )


@define(eq=False, slots=False)
class AzureMysqlServerBackup(MicrosoftResource):
    kind: ClassVar[str] = "azure_mysql_server_backup"
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
    AzureMysqlCapability,
    AzureMysqlServerType,
    AzureMysqlServerConfiguration,
    AzureMysqlServerDatabase,
    AzureMysqlServerFirewallRule,
    AzureMysqlServerLogFile,
    AzureMysqlServerMaintenance,
    AzureMysqlServer,
    AzureMysqlServerBackup,
]
