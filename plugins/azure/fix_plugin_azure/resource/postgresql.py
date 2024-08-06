from __future__ import annotations

import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attr import define, field, evolve

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
from fix_plugin_azure.resource.microsoft_graph import MicrosoftGraphServicePrincipal, MicrosoftGraphUser
from fix_plugin_azure.resource.mysql import (
    AzureServerBackup,
    AzureServerDataEncryption,
    AzureServerHighAvailability,
    AzureServerMaintenanceWindow,
    AzureServerNetwork,
)
from fix_plugin_azure.utils import from_str_to_typed
from fixlib.baseresources import BaseDatabase, BaseDatabaseInstanceType, DatabaseInstanceStatus, ModelReference
from fixlib.graph import BySearchCriteria
from fixlib.json_bender import K, Bender, S, ForallBend, Bend, MapEnum, MapValue
from fixlib.types import Json

service_name = "azure_postgresql"
log = logging.getLogger("fix.plugins.azure")


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
class AzureServerStorageEditionCapability:
    kind: ClassVar[str] = "azure_server_storage_edition_capability"
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
class AzureSupportedServerVersionCapability:
    kind: ClassVar[str] = "azure_supported_server_version_capability"
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
        "supported_server_versions": S("supportedServerVersions")
        >> ForallBend(AzureSupportedServerVersionCapability.mapping),
        "supported_storage_editions": S("supportedStorageEditions")
        >> ForallBend(AzureServerStorageEditionCapability.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Server edition name"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_server_versions: Optional[List[AzureSupportedServerVersionCapability]] = field(default=None, metadata={'description': 'The list of server versions supported by this server edition.'})  # fmt: skip
    supported_storage_editions: Optional[List[AzureServerStorageEditionCapability]] = field(default=None, metadata={'description': 'The list of editions supported by this server edition.'})  # fmt: skip


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
        "supported_server_versions": S("supportedServerVersions")
        >> ForallBend(AzureSupportedServerVersionCapability.mapping),
        "supported_storage_editions": S("supportedStorageEditions")
        >> ForallBend(AzureServerStorageEditionCapability.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Server edition name"})
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_node_types: Optional[List[AzureNodeTypeCapability]] = field(default=None, metadata={'description': 'The list of Node Types supported by this server edition.'})  # fmt: skip
    supported_server_versions: Optional[List[AzureSupportedServerVersionCapability]] = field(default=None, metadata={'description': 'The list of server versions supported by this server edition.'})  # fmt: skip
    supported_storage_editions: Optional[List[AzureServerStorageEditionCapability]] = field(default=None, metadata={'description': 'The list of editions supported by this server edition.'})  # fmt: skip


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
class AzurePostgresqlServerType(MicrosoftResource, BaseDatabaseInstanceType):
    kind: ClassVar[str] = "azure_postgresql_server_type"
    # Collect via AzurePostgresqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "fast_provisioning_supported": S("fastProvisioningSupported"),
        "geo_backup_supported": S("geoBackupSupported"),
        "status": S("status"),
        "supported_ha_mode": S("supportedHAMode"),
        "capability_zone": S("zone"),
        "zone_redundant_ha_and_geo_backup_supported": S("zoneRedundantHaAndGeoBackupSupported"),
        "zone_redundant_ha_supported": S("zoneRedundantHaSupported"),
        "sku_name": S("sku", "name"),
        "sku_tier": S("sku", "tier"),
        "location": S("location"),
        # NOTE: Azure defines location-aware capabilities for several editions.
        # Separate server types are created for all used editions.
        "_supported_fast_provisioning_editions": S("supportedFastProvisioningEditions")
        >> ForallBend(AzureFastProvisioningEditionCapability.mapping),
        "_supported_psql_flexible_server_editions": S("supportedFlexibleServerEditions")
        >> ForallBend(AzureFlexibleServerEditionCapability.mapping),
        "_supported_hyperscale_node_editions": S("supportedHyperscaleNodeEditions")
        >> ForallBend(AzureHyperscaleNodeEditionCapability.mapping),
    }
    _is_provider_link: ClassVar[bool] = False
    fast_provisioning_supported: Optional[bool] = field(
        default=None,
        metadata={"description": "A value indicating whether fast provisioning is supported in this region."},
    )
    geo_backup_supported: Optional[bool] = field(
        default=None,
        metadata={
            "description": "A value indicating whether a new server in this region can have geo-backups to paired region."
        },
    )
    status: Optional[str] = field(default=None, metadata={"description": "The status"})
    supported_ha_mode: Optional[List[str]] = field(
        default=None, metadata={"description": "Supported high availability mode"}
    )
    capability_zone: Optional[str] = field(default=None, metadata={"description": "zone name"})
    zone_redundant_ha_and_geo_backup_supported: Optional[bool] = field(
        default=None,
        metadata={
            "description": "A value indicating whether a new server in this region can have geo-backups to paired region."
        },
    )
    zone_redundant_ha_supported: Optional[bool] = field(
        default=None,
        metadata={"description": "A value indicating whether a new server in this region can support multi zone HA."},
    )
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    # See mapping note: The following properties are not coming from the API directly.
    sku_name: Optional[str] = field(default=None)
    sku_tier: Optional[str] = field(default=None)
    storage_iops: Optional[int] = field(default=None)
    storage_size_gb: Optional[int] = field(default=None)
    storage_tier: Optional[str] = field(default=None)
    storage_type: Optional[str] = field(default=None)
    # See mapping note: only here to map to separate resources for all used editions
    _supported_fast_provisioning_editions: Optional[List[AzureFastProvisioningEditionCapability]] = None
    _supported_psql_flexible_server_editions: Optional[List[AzureFlexibleServerEditionCapability]] = None
    _supported_hyperscale_node_editions: Optional[List[AzureHyperscaleNodeEditionCapability]] = None

    @classmethod
    def collect(cls, raw: List[Json], builder: GraphBuilder) -> List[AzurePostgresqlServerType]:
        result = []

        for js in raw:
            # Get server's sku name and sku tier
            expected_sku_name = js.get("expected_sku_name")
            expected_sku_tier = js.get("expected_sku_tier")
            expected_version = js.get("expected_version")
            instance = cls.from_api(js)
            if isinstance(instance, AzurePostgresqlServerType) and instance._supported_psql_flexible_server_editions:
                location = instance.location
                for edition in instance._supported_psql_flexible_server_editions:
                    if edition.name != expected_sku_tier:
                        continue
                    for version in edition.supported_server_versions or []:
                        if version.name != expected_version:
                            continue
                        for sku in version.supported_vcores or []:
                            if sku.name != expected_sku_name:
                                continue
                            for supported_storage in edition.supported_storage_editions or []:
                                for storage in supported_storage.supported_storage_mb or []:
                                    # use this instance as a template and create a new one for each supported edition
                                    server_type = evolve(
                                        instance,
                                        id=f"{edition.name}_{version.name}_{sku.name}_{storage.name}",
                                        name=f"{edition.name}_{version.name}_{sku.name}_{storage.name}",
                                        sku_name=sku.name,
                                        sku_tier=edition.name,
                                        instance_cores=sku.v_cores or 0,
                                        instance_memory=(
                                            sku.supported_memory_per_vcore_mb // 1024
                                            if sku.supported_memory_per_vcore_mb
                                            else 0
                                        ),
                                        instance_type=sku.name,
                                        storage_iops=storage.supported_iops,
                                        storage_size_gb=(
                                            storage.storage_size_mb // 1024 if storage.storage_size_mb else 0
                                        ),
                                        location=location,
                                    )
                                    if graph_node := builder.add_node(server_type, js):
                                        result.append(graph_node)

        return result


@define(eq=False, slots=False)
class AzurePostgresqlServerConfiguration(MicrosoftResource, AzureProxyResource):
    kind: ClassVar[str] = "azure_postgresql_server_configuration"
    # Collect via AzurePostgresqlServer()
    config: Json = field(factory=dict)

    @classmethod
    def collect_configs(
        cls,
        server_id: str,
        raw: List[Json],
        builder: GraphBuilder,
    ) -> List[AzurePostgresqlServerConfiguration]:
        if not raw:
            return []
        configuration_instance = AzurePostgresqlServerConfiguration(id=server_id)
        for js in raw:
            properties = js.get("properties")
            if not properties:
                continue
            if (
                (data_type := properties.get("dataType"))
                and (val := properties.get("value"))
                and (config_name := js.get("name"))
            ):
                value = from_str_to_typed(data_type, val)
                if not value:
                    continue
                configuration_instance.config[config_name] = value
        if (added := builder.add_node(configuration_instance, configuration_instance.config)) is not None:
            return [added]
        return []


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
class AzurePostgresqlServer(MicrosoftResource, AzureTrackedResource, BaseDatabase):
    kind: ClassVar[str] = "azure_postgresql_server"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="postgresql",
        version="2023-06-01-preview",
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
                "azure_postgresql_server_type",
                "microsoft_graph_service_principal",
                "microsoft_graph_user",
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
        "server_backup": S("properties", "backup") >> Bend(AzureServerBackup.mapping),
        "create_mode": S("properties", "createMode"),
        "data_encryption": S("properties", "dataEncryption") >> Bend(AzureServerDataEncryption.mapping),
        "fully_qualified_domain_name": S("properties", "fullyQualifiedDomainName"),
        "high_availability": S("properties", "highAvailability") >> Bend(AzureServerHighAvailability.mapping),
        "user_identity": S("identity") >> Bend(AzureResourceIdentity.mapping),
        "server_maintenance_window": S("properties", "maintenanceWindow") >> Bend(AzureServerMaintenanceWindow.mapping),
        "minor_version": S("properties", "minorVersion"),
        "server_network": S("properties", "network") >> Bend(AzureServerNetwork.mapping),
        "point_in_time_utc": S("properties", "pointInTimeUTC"),
        "replica_capacity": S("properties", "replicaCapacity"),
        "replication_role": S("properties", "replicationRole"),
        "server_sku": S("sku") >> Bend(AzureSku.mapping),
        "source_server_resource_id": S("properties", "sourceServerResourceId"),
        "state": S("properties", "state"),
        "storage_size_gb": S("properties", "storage", "storageSizeGB"),
        "storage_tier": S("properties", "storage", "tier"),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "version": S("properties", "version"),
        "db_type": K("pg"),
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
    administrator_login_password: Optional[str] = field(default=None, metadata={'description': 'The administrator login password (required for server creation).'})  # fmt: skip
    auth_config: Optional[AzureAuthConfig] = field(default=None, metadata={'description': 'Authentication configuration properties of a server'})  # fmt: skip
    availability_zone: Optional[str] = field(default=None, metadata={'description': 'availability zone information of the server.'})  # fmt: skip
    server_backup: Optional[AzureServerBackup] = field(
        default=None, metadata={"description": "Backup properties of a server"}
    )
    create_mode: Optional[str] = field(default=None, metadata={'description': 'The mode to create a new PostgreSQL server.'})  # fmt: skip
    data_encryption: Optional[AzureServerDataEncryption] = field(default=None, metadata={'description': 'Data encryption properties of a server'})  # fmt: skip
    fully_qualified_domain_name: Optional[str] = field(default=None, metadata={'description': 'The fully qualified domain name of a server.'})  # fmt: skip
    high_availability: Optional[AzureServerHighAvailability] = field(default=None, metadata={'description': 'High availability properties of a server'})  # fmt: skip
    user_identity: Optional[AzureResourceIdentity] = field(default=None, metadata={'description': 'Information describing the identities associated with this application.'})  # fmt: skip
    server_maintenance_window: Optional[AzureServerMaintenanceWindow] = field(default=None, metadata={'description': 'Maintenance window properties of a server.'})  # fmt: skip
    minor_version: Optional[str] = field(default=None, metadata={"description": "The minor version of the server."})
    server_network: Optional[AzureServerNetwork] = field(
        default=None, metadata={"description": "Network properties of a server."}
    )
    point_in_time_utc: Optional[datetime] = field(default=None, metadata={'description': 'Restore point creation time (ISO8601 format), specifying the time to restore from. It s required when createMode is PointInTimeRestore or GeoRestore .'})  # fmt: skip
    replica_capacity: Optional[int] = field(default=None, metadata={"description": "Replicas allowed for a server."})
    replication_role: Optional[str] = field(default=None, metadata={'description': 'Used to indicate role of the server in replication set.'})  # fmt: skip
    server_sku: Optional[AzureSku] = field(default=None, metadata={'description': 'Sku information related properties of a server.'})  # fmt: skip
    source_server_resource_id: Optional[str] = field(default=None, metadata={'description': 'The source server resource ID to restore from. It s required when createMode is PointInTimeRestore or GeoRestore or Replica . This property is returned only for Replica server'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'A state of a server that is visible to user.'})  # fmt: skip
    storage_size_gb: Optional[int] = field(default=None, metadata={"description": "Storage properties of a server"})
    storage_tier: Optional[str] = field(default=None, metadata={"description": "Storage properties of a server"})
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The version of a server."})

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        server_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{server_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="postgresql",
            version="2022-12-01",
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
        if issubclass(AzurePostgresqlServerConfiguration, class_instance):  # type: ignore
            collected = class_instance.collect_configs(self.id, items, graph_builder)  # type: ignore
        else:
            collected = class_instance.collect(items, graph_builder)
        for clazz in collected:
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if server_id := self.id:
            resources_to_collect = [
                (
                    "administrators",
                    AzurePostgresqlServerADAdministrator,
                    ["InternalServerError", "DatabaseDoesNotExist"],
                ),
                ("configurations", AzurePostgresqlServerConfiguration, ["ServerStoppedError", "InternalServerError"]),
                ("databases", AzurePostgresqlServerDatabase, ["ServerStoppedError", "InternalServerError"]),
                ("firewallRules", AzurePostgresqlServerFirewallRule, None),
                ("backups", AzurePostgresqlServerBackup, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    server_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )
        if self.data_encryption:
            self.volume_encrypted = True
        else:
            self.volume_encrypted = False

        if (server_location := self.location) and (sku := self.server_sku) and (version := self.version):

            def collect_capabilities() -> None:

                api_spec = AzureResourceSpec(
                    service="postgresql",
                    version="2022-12-01",
                    path="/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/locations/"
                    + f"{server_location}/capabilities",
                    path_parameters=["subscriptionId"],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                    expected_error_codes=["InternalServerError"],
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                for item in items:
                    # Set location for further connect_in_graph method
                    item["location"] = server_location
                    # Set sku name and tier for SKUs filtering
                    item["expected_sku_name"] = sku.name
                    item["expected_sku_tier"] = sku.tier
                    item["expected_version"] = version
                AzurePostgresqlServerType.collect(items, graph_builder)

            graph_builder.submit_work(service_name, collect_capabilities)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (
            (location := self.location)
            and (vesion := self.version)
            and (sku := self.server_sku)
            and (sku_name := sku.name)
            and (sku_tier := sku.tier)
            and (storage_size := self.storage_size_gb)
        ):
            builder.add_edge(
                self,
                location=location,
                id=f"{sku_tier}_{vesion}_{sku_name}_{storage_size * 1024}",
                clazz=AzurePostgresqlServerType,
            )
        # principal: collected via ms graph -> create a deferred edge
        if mii := self.user_identity:
            if pid := mii.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := mii.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
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
    AzurePostgresqlServerConfiguration,
    AzurePostgresqlServerDatabase,
    AzurePostgresqlServerFirewallRule,
    AzurePostgresqlServer,
    AzurePostgresqlServerType,
    AzurePostgresqlServerBackup,
]
