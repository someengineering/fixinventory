import logging
from datetime import datetime
from typing import Any, ClassVar, Dict, Optional, List, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    AzureResourceIdentity,
    AzureSku,
    GraphBuilder,
    MicrosoftResource,
    parse_json,
    AzurePrivateEndpointConnection,
)
from fix_plugin_azure.resource.microsoft_graph import MicrosoftGraphServicePrincipal, MicrosoftGraphUser
from fix_plugin_azure.resource.network import AzureNetworkSubnet
from fixlib.baseresources import BaseDatabase, DatabaseInstanceStatus, EdgeType, ModelReference
from fixlib.graph import BySearchCriteria
from fixlib.json import value_in_path
from fixlib.json_bender import F, K, Bender, S, ForallBend, Bend, MapEnum
from fixlib.types import Json

service_name = "azure-sql"
log = logging.getLogger("fix.plugins.azure")


@define(eq=False, slots=False)
class AzureSqlServerADAdministrator(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_ad_administrator"
    _kind_display: ClassVar[str] = "Azure SQL Server Ad Administrator"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server AD Administrator is a role that integrates Azure Active Directory authentication with SQL Server. It manages access control for SQL databases using Azure AD credentials, allowing organizations to centralize user management and enforce multi-factor authentication. This role simplifies security administration by applying Azure AD policies and permissions to SQL Server resources."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?tabs=azure-powershell"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "user", "group": "database"}
    _reference_kinds: ClassVar[ModelReference] = {"successors": {"default": [MicrosoftResource.kind]}}
    # Collect via AzureSqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "administrator_type": S("properties", "administratorType"),
        "azure_ad_only_authentication": S("properties", "azureADOnlyAuthentication"),
        "login": S("properties", "login"),
        "sid": S("properties", "sid"),
        "tenant_id": S("properties", "tenantId"),
    }
    administrator_type: Optional[str] = field(default=None, metadata={'description': 'Type of the sever administrator.'})  # fmt: skip
    azure_ad_only_authentication: Optional[bool] = field(default=None, metadata={'description': 'Azure Active Directory only Authentication enabled.'})  # fmt: skip
    login: Optional[str] = field(default=None, metadata={"description": "Login name of the server administrator."})
    sid: Optional[str] = field(default=None, metadata={"description": "SID (object ID) of the server administrator."})
    tenant_id: Optional[str] = field(default=None, metadata={"description": "Tenant ID of the administrator."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if user_id := self.sid:
            builder.add_deferred_edge(
                from_node=self,
                to_node=BySearchCriteria(f'is({MicrosoftGraphUser.kind}) and reported.id=="{user_id}"'),
            )


@define(eq=False, slots=False)
class AzureDatabaseUserIdentity:
    kind: ClassVar[str] = "azure_database_user_identity"
    mapping: ClassVar[Dict[str, Bender]] = {"client_id": S("clientId"), "principal_id": S("principalId")}
    client_id: Optional[str] = field(default=None, metadata={"description": "The Azure Active Directory client id."})
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The Azure Active Directory principal id.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDatabaseIdentity:
    kind: ClassVar[str] = "azure_database_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "tenant_id": S("tenantId"),
        "type": S("type"),
        "user_assigned_identities": S("userAssignedIdentities"),
    }
    tenant_id: Optional[str] = field(default=None, metadata={"description": "The Azure Active Directory tenant id."})
    type: Optional[str] = field(default=None, metadata={"description": "The identity type"})
    user_assigned_identities: Optional[Dict[str, AzureDatabaseUserIdentity]] = field(default=None, metadata={'description': 'The resource ids of the user assigned identities to use'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSqlServerDatabase(MicrosoftResource, BaseDatabase):
    kind: ClassVar[str] = "azure_sql_server_database"
    _kind_display: ClassVar[str] = "Azure SQL Server Database"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Database is a cloud-based relational database service provided by Microsoft. It offers SQL Server functionality in a managed environment, handling tasks like backups, updates, and scaling. Users can store and retrieve structured data, run complex queries, and integrate with applications while Microsoft maintains the underlying infrastructure and ensures data security and availability."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/database/"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "database", "group": "database"}
    # Collect via AzureSqlServer()
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_sql_server_database_workload_group",
                "azure_sql_server_database_geo_backup_policy",
                "azure_sql_server_advisor",
                "microsoft_graph_user",
            ]
        },
        "predecessors": {"default": ["azure_sql_server_elastic_pool"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "location": S("location"),
        "ctime": S("properties", "creationDate"),
        "atime": S("properties", "pausedDate"),
        "auto_pause_delay": S("properties", "autoPauseDelay"),
        "catalog_collation": S("properties", "catalogCollation"),
        "collation": S("properties", "collation"),
        "create_mode": S("properties", "createMode"),
        "creation_date": S("properties", "creationDate"),
        "current_backup_storage_redundancy": S("properties", "currentBackupStorageRedundancy"),
        "current_service_objective_name": S("properties", "currentServiceObjectiveName"),
        "current_sku": S("properties", "currentSku") >> Bend(AzureSku.mapping),
        "database_id": S("properties", "databaseId"),
        "default_secondary_location": S("properties", "defaultSecondaryLocation"),
        "earliest_restore_date": S("properties", "earliestRestoreDate"),
        "elastic_pool_id": S("properties", "elasticPoolId"),
        "failover_group_id": S("properties", "failoverGroupId"),
        "federated_client_id": S("properties", "federatedClientId"),
        "high_availability_replica_count": S("properties", "highAvailabilityReplicaCount"),
        "database_identity": S("identity") >> Bend(AzureDatabaseIdentity.mapping),
        "is_infra_encryption_enabled": S("properties", "isInfraEncryptionEnabled"),
        "is_ledger_on": S("properties", "isLedgerOn"),
        "database_kind": S("kind"),
        "license_type": S("properties", "licenseType"),
        "long_term_retention_backup_resource_id": S("properties", "longTermRetentionBackupResourceId"),
        "maintenance_configuration_id": S("properties", "maintenanceConfigurationId"),
        "managed_by": S("managedBy"),
        "max_log_size_bytes": S("properties", "maxLogSizeBytes"),
        "max_size_bytes": S("properties", "maxSizeBytes"),
        "min_capacity": S("properties", "minCapacity"),
        "paused_date": S("properties", "pausedDate"),
        "read_scale": S("properties", "readScale"),
        "recoverable_database_id": S("properties", "recoverableDatabaseId"),
        "recovery_services_recovery_point_id": S("properties", "recoveryServicesRecoveryPointId"),
        "requested_backup_storage_redundancy": S("properties", "requestedBackupStorageRedundancy"),
        "requested_service_objective_name": S("properties", "requestedServiceObjectiveName"),
        "restorable_dropped_database_id": S("properties", "restorableDroppedDatabaseId"),
        "restore_point_in_time": S("properties", "restorePointInTime"),
        "resumed_date": S("properties", "resumedDate"),
        "sample_name": S("properties", "sampleName"),
        "secondary_type": S("properties", "secondaryType"),
        "database_sku": S("sku") >> Bend(AzureSku.mapping),
        "source_database_deletion_date": S("properties", "sourceDatabaseDeletionDate"),
        "source_database_id": S("properties", "sourceDatabaseId"),
        "source_resource_id": S("properties", "sourceResourceId"),
        "status": S("properties", "status"),
        "zone_redundant": S("properties", "zoneRedundant"),
        "db_type": K("sql"),
        "db_status": S("properties", "state")
        >> MapEnum(
            {
                "AutoClosed": DatabaseInstanceStatus.STOPPED,
                "Copying": DatabaseInstanceStatus.BUSY,
                "Creating": DatabaseInstanceStatus.BUSY,
                "Disabled": DatabaseInstanceStatus.STOPPED,
                "EmergencyMode": DatabaseInstanceStatus.FAILED,
                "Inaccessible": DatabaseInstanceStatus.FAILED,
                "Offline": DatabaseInstanceStatus.STOPPED,
                "OfflineChangingDwPerformanceTiers": DatabaseInstanceStatus.BUSY,
                "OfflineSecondary": DatabaseInstanceStatus.STOPPED,
                "Online": DatabaseInstanceStatus.AVAILABLE,
                "OnlineChangingDwPerformanceTiers": DatabaseInstanceStatus.BUSY,
                "Paused": DatabaseInstanceStatus.STOPPED,
                "Pausing": DatabaseInstanceStatus.BUSY,
                "Recovering": DatabaseInstanceStatus.BUSY,
                "RecoveryPending": DatabaseInstanceStatus.BUSY,
                "Restoring": DatabaseInstanceStatus.BUSY,
                "Resuming": DatabaseInstanceStatus.BUSY,
                "Scaling": DatabaseInstanceStatus.BUSY,
                "Shutdown": DatabaseInstanceStatus.STOPPED,
                "Standby": DatabaseInstanceStatus.AVAILABLE,
                "Starting": DatabaseInstanceStatus.BUSY,
                "Stopped": DatabaseInstanceStatus.STOPPED,
                "Stopping": DatabaseInstanceStatus.BUSY,
                "Suspect": DatabaseInstanceStatus.FAILED,
            },
            default=DatabaseInstanceStatus.UNKNOWN,
        ),
        "instance_type": S("sku", "name"),
        # Convert bytes to gigabytes
        "volume_size": S("properties", "maxSizeBytes") >> F(lambda size: size // 1_073_741_824),
        "volume_encrypted": S("properties", "isInfraEncryptionEnabled"),
    }
    auto_pause_delay: Optional[int] = field(default=None, metadata={'description': 'Time in minutes after which database is automatically paused. A value of -1 means that automatic pause is disabled'})  # fmt: skip
    catalog_collation: Optional[str] = field(default=None, metadata={'description': 'Collation of the metadata catalog.'})  # fmt: skip
    collation: Optional[str] = field(default=None, metadata={"description": "The collation of the database."})
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the mode of database creation. Default: regular database creation. Copy: creates a database as a copy of an existing database. sourceDatabaseId must be specified as the resource ID of the source database. Secondary: creates a database as a secondary replica of an existing database. sourceDatabaseId must be specified as the resource ID of the existing primary database. PointInTimeRestore: Creates a database by restoring a point in time backup of an existing database. sourceDatabaseId must be specified as the resource ID of the existing database, and restorePointInTime must be specified. Recovery: Creates a database by restoring a geo-replicated backup. sourceDatabaseId must be specified as the recoverable database resource ID to restore. Restore: Creates a database by restoring a backup of a deleted database. sourceDatabaseId must be specified. If sourceDatabaseId is the database s original resource ID, then sourceDatabaseDeletionDate must be specified. Otherwise sourceDatabaseId must be the restorable dropped database resource ID and sourceDatabaseDeletionDate is ignored. restorePointInTime may also be specified to restore from an earlier point in time. RestoreLongTermRetentionBackup: Creates a database by restoring from a long term retention vault. recoveryServicesRecoveryPointResourceId must be specified as the recovery point resource ID. Copy, Secondary, and RestoreLongTermRetentionBackup are not supported for DataWarehouse edition.'})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={'description': 'The creation date of the database (ISO8601 format).'})  # fmt: skip
    current_backup_storage_redundancy: Optional[str] = field(default=None, metadata={'description': 'The storage account type used to store backups for this database.'})  # fmt: skip
    current_service_objective_name: Optional[str] = field(default=None, metadata={'description': 'The current service level objective name of the database.'})  # fmt: skip
    current_sku: Optional[AzureSku] = field(default=None, metadata={"description": "An ARM Resource SKU."})
    database_id: Optional[str] = field(default=None, metadata={"description": "The ID of the database."})
    default_secondary_location: Optional[str] = field(default=None, metadata={'description': 'The default secondary region for this database.'})  # fmt: skip
    earliest_restore_date: Optional[datetime] = field(default=None, metadata={'description': 'This records the earliest start date and time that restore is available for this database (ISO8601 format).'})  # fmt: skip
    elastic_pool_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the elastic pool containing this database.'})  # fmt: skip
    failover_group_id: Optional[str] = field(default=None, metadata={'description': 'Failover Group resource identifier that this database belongs to.'})  # fmt: skip
    federated_client_id: Optional[str] = field(default=None, metadata={'description': 'The Client id used for cross tenant per database CMK scenario'})  # fmt: skip
    high_availability_replica_count: Optional[int] = field(default=None, metadata={'description': 'The number of secondary replicas associated with the database that are used to provide high availability. Not applicable to a Hyperscale database within an elastic pool.'})  # fmt: skip
    database_identity: Optional[AzureDatabaseIdentity] = field(default=None, metadata={'description': 'Azure Active Directory identity configuration for a resource.'})  # fmt: skip
    is_infra_encryption_enabled: Optional[bool] = field(default=None, metadata={'description': 'Infra encryption is enabled for this database.'})  # fmt: skip
    is_ledger_on: Optional[bool] = field(default=None, metadata={'description': 'Whether or not this database is a ledger database, which means all tables in the database are ledger tables. Note: the value of this property cannot be changed after the database has been created.'})  # fmt: skip
    database_kind: Optional[str] = field(default=None, metadata={'description': 'Kind of database. This is metadata used for the Azure portal experience.'})  # fmt: skip
    license_type: Optional[str] = field(default=None, metadata={'description': 'The license type to apply for this database. `LicenseIncluded` if you need a license, or `BasePrice` if you have a license and are eligible for the Azure Hybrid Benefit.'})  # fmt: skip
    long_term_retention_backup_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the long term retention backup associated with create operation of this database.'})  # fmt: skip
    maintenance_configuration_id: Optional[str] = field(default=None, metadata={'description': 'Maintenance configuration id assigned to the database. This configuration defines the period when the maintenance updates will occur.'})  # fmt: skip
    managed_by: Optional[str] = field(default=None, metadata={"description": "Resource that manages the database."})
    max_log_size_bytes: Optional[int] = field(default=None, metadata={'description': 'The max log size for this database.'})  # fmt: skip
    max_size_bytes: Optional[int] = field(default=None, metadata={'description': 'The max size of the database expressed in bytes.'})  # fmt: skip
    min_capacity: Optional[float] = field(default=None, metadata={'description': 'Minimal capacity that database will always have allocated, if not paused'})  # fmt: skip
    paused_date: Optional[datetime] = field(default=None, metadata={'description': 'The date when database was paused by user configuration or action(ISO8601 format). Null if the database is ready.'})  # fmt: skip
    read_scale: Optional[str] = field(default=None, metadata={'description': 'The state of read-only routing. If enabled, connections that have application intent set to readonly in their connection string may be routed to a readonly secondary replica in the same region. Not applicable to a Hyperscale database within an elastic pool.'})  # fmt: skip
    recoverable_database_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the recoverable database associated with create operation of this database.'})  # fmt: skip
    recovery_services_recovery_point_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the recovery point associated with create operation of this database.'})  # fmt: skip
    requested_backup_storage_redundancy: Optional[str] = field(default=None, metadata={'description': 'The storage account type to be used to store backups for this database.'})  # fmt: skip
    requested_service_objective_name: Optional[str] = field(default=None, metadata={'description': 'The requested service level objective name of the database.'})  # fmt: skip
    restorable_dropped_database_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the restorable dropped database associated with create operation of this database.'})  # fmt: skip
    restore_point_in_time: Optional[datetime] = field(default=None, metadata={'description': 'Specifies the point in time (ISO8601 format) of the source database that will be restored to create the new database.'})  # fmt: skip
    resumed_date: Optional[datetime] = field(default=None, metadata={'description': 'The date when database was resumed by user action or database login (ISO8601 format). Null if the database is paused.'})  # fmt: skip
    sample_name: Optional[str] = field(default=None, metadata={'description': 'The name of the sample schema to apply when creating this database.'})  # fmt: skip
    secondary_type: Optional[str] = field(default=None, metadata={'description': 'The secondary type of the database if it is a secondary. Valid values are Geo and Named.'})  # fmt: skip
    database_sku: Optional[AzureSku] = field(default=None, metadata={"description": "An ARM Resource SKU."})
    source_database_deletion_date: Optional[datetime] = field(default=None, metadata={'description': 'Specifies the time that the database was deleted.'})  # fmt: skip
    source_database_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the source database associated with create operation of this database.'})  # fmt: skip
    source_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the source associated with the create operation of this database. This property is only supported for DataWarehouse edition and allows to restore across subscriptions. When sourceResourceId is specified, sourceDatabaseId, recoverableDatabaseId, restorableDroppedDatabaseId and sourceDatabaseDeletionDate must not be specified and CreateMode must be PointInTimeRestore, Restore or Recover. When createMode is PointInTimeRestore, sourceResourceId must be the resource ID of the existing database or existing sql pool, and restorePointInTime must be specified. When createMode is Restore, sourceResourceId must be the resource ID of restorable dropped database or restorable dropped sql pool. When createMode is Recover, sourceResourceId must be the resource ID of recoverable database or recoverable sql pool. When source subscription belongs to a different tenant than target subscription, “x-ms-authorization-auxiliary” header must contain authentication token for the source tenant. For more details about “x-ms-authorization-auxiliary” header see https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/authenticate-multi-tenant '})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the database."})
    zone_redundant: Optional[bool] = field(default=None, metadata={'description': 'Whether or not this database is zone redundant, which means the replicas of this database will be spread across multiple availability zones.'})  # fmt: skip
    transparent_data_encryption_status: Optional[str] = field(default=None, metadata={'description': 'The transparent data encryption status for this database.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        database_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_error_codes: Optional[Dict[str, Optional[str]]] = None,
    ) -> None:
        path = f"{database_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="sql",
            version="2021-11-01",
            path=path,
            path_parameters=[],
            query_parameters=["api-version"],
            access_path="value",
            expect_array=True,
            expected_error_codes=expected_error_codes or {},
        )
        items = graph_builder.client.list(api_spec)
        collected = class_instance.collect(items, graph_builder)
        for resource in collected:
            graph_builder.add_edge(self, node=resource)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        def fetch_data_encryption_status(sid: str) -> None:
            api_spec = AzureResourceSpec(
                service="sql",
                version="2021-11-01",
                path=f"{sid}/transparentDataEncryption/current",
                query_parameters=["api-version"],
                expect_array=True,
            )
            # albeit this is a list API, it will only return one element
            if items := graph_builder.client.list(api_spec):
                for item in items:
                    self.transparent_data_encryption_status = value_in_path(item, ["properties", "state"])

        if database_id := self.id:
            graph_builder.submit_work(service_name, fetch_data_encryption_status, database_id)
            resources_to_collect = [
                ("geoBackupPolicies", AzureSqlServerDatabaseGeoBackupPolicy, None),
                (
                    "advisors?$expand=recommendedAction",
                    AzureSqlServerAdvisor,
                    {"DataWarehouseNotSupported": None, "DatabaseDoesNotExist": None},
                ),
                ("workloadGroups", AzureSqlServerDatabaseWorkloadGroup, {"FeatureDisabledOnSelectedEdition": None}),
            ]

            for resource_type, resource_class, expected_error_codes in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    database_id,
                    resource_type,
                    resource_class,
                    expected_error_codes,
                )

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if elastic_pool_id := self.elastic_pool_id:
            builder.add_edge(
                self, edge_type=EdgeType.default, reverse=True, clazz=AzureSqlServerElasticPool, id=elastic_pool_id
            )
        # principal: collected via ms graph -> create a deferred edge
        if (di := self.database_identity) and (uai := di.user_assigned_identities):
            for _, identity_info in uai.items():
                if identity_info and identity_info.principal_id:
                    builder.add_deferred_edge(
                        from_node=self,
                        to_node=BySearchCriteria(
                            f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                        ),
                    )


@define(eq=False, slots=False)
class AzureElasticPoolPerDatabaseSettings:
    kind: ClassVar[str] = "azure_elastic_pool_per_database_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"max_capacity": S("maxCapacity"), "min_capacity": S("minCapacity")}
    max_capacity: Optional[float] = field(default=None, metadata={'description': 'The maximum capacity any one database can consume.'})  # fmt: skip
    min_capacity: Optional[float] = field(default=None, metadata={'description': 'The minimum capacity all databases are guaranteed.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSqlServerElasticPool(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_elastic_pool"
    _kind_display: ClassVar[str] = "Azure SQL Server Elastic Pool"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Elastic Pool is a resource management tool for multiple SQL databases. It allocates a shared set of compute and storage resources across databases, optimizing performance and costs. Administrators can set resource limits for the pool and individual databases, adjusting capacity as needed without affecting application availability or performance."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/database/elastic-pool-overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "profile", "group": "compute"}
    # Collect via AzureSqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "location": S("location"),
        "ctime": S("properties", "creationDate"),
        "creation_date": S("properties", "creationDate"),
        "high_availability_replica_count": S("properties", "highAvailabilityReplicaCount"),
        "elastic_pool_kind": S("kind"),
        "license_type": S("properties", "licenseType"),
        "maintenance_configuration_id": S("properties", "maintenanceConfigurationId"),
        "max_size_bytes": S("properties", "maxSizeBytes"),
        "min_capacity": S("properties", "minCapacity"),
        "per_database_settings": S("properties", "perDatabaseSettings")
        >> Bend(AzureElasticPoolPerDatabaseSettings.mapping),
        "elastic_pool_sku": S("sku") >> Bend(AzureSku.mapping),
        "state": S("properties", "state"),
        "zone_redundant": S("properties", "zoneRedundant"),
    }
    creation_date: Optional[datetime] = field(default=None, metadata={'description': 'The creation date of the elastic pool (ISO8601 format).'})  # fmt: skip
    high_availability_replica_count: Optional[int] = field(default=None, metadata={'description': 'The number of secondary replicas associated with the elastic pool that are used to provide high availability. Applicable only to Hyperscale elastic pools.'})  # fmt: skip
    elastic_pool_kind: Optional[str] = field(default=None, metadata={'description': 'Kind of elastic pool. This is metadata used for the Azure portal experience.'})  # fmt: skip
    license_type: Optional[str] = field(default=None, metadata={'description': 'The license type to apply for this elastic pool.'})  # fmt: skip
    maintenance_configuration_id: Optional[str] = field(default=None, metadata={'description': 'Maintenance configuration id assigned to the elastic pool. This configuration defines the period when the maintenance updates will will occur.'})  # fmt: skip
    max_size_bytes: Optional[int] = field(default=None, metadata={'description': 'The storage limit for the database elastic pool in bytes.'})  # fmt: skip
    min_capacity: Optional[float] = field(default=None, metadata={'description': 'Minimal capacity that serverless pool will not shrink below, if not paused'})  # fmt: skip
    per_database_settings: Optional[AzureElasticPoolPerDatabaseSettings] = field(default=None, metadata={'description': 'Per database settings of an elastic pool.'})  # fmt: skip
    elastic_pool_sku: Optional[AzureSku] = field(default=None, metadata={"description": "An ARM Resource SKU."})
    state: Optional[str] = field(default=None, metadata={"description": "The state of the elastic pool."})
    zone_redundant: Optional[bool] = field(default=None, metadata={'description': 'Whether or not this elastic pool is zone redundant, which means the replicas of this elastic pool will be spread across multiple availability zones.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})


@define(eq=False, slots=False)
class AzureFailoverGroupReadWriteEndpoint:
    kind: ClassVar[str] = "azure_failover_group_read_write_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failover_policy": S("failoverPolicy"),
        "failover_with_data_loss_grace_period_minutes": S("failoverWithDataLossGracePeriodMinutes"),
    }
    failover_policy: Optional[str] = field(default=None, metadata={'description': 'Failover policy of the read-write endpoint for the failover group. If failoverPolicy is Automatic then failoverWithDataLossGracePeriodMinutes is required.'})  # fmt: skip
    failover_with_data_loss_grace_period_minutes: Optional[int] = field(default=None, metadata={'description': 'Grace period before failover with data loss is attempted for the read-write endpoint. If failoverPolicy is Automatic then failoverWithDataLossGracePeriodMinutes is required.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePartnerInfo:
    kind: ClassVar[str] = "azure_partner_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "location": S("location"),
        "replication_role": S("replicationRole"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "Resource identifier of the partner server."})
    location: Optional[str] = field(default=None, metadata={"description": "Geo location of the partner server."})
    replication_role: Optional[str] = field(default=None, metadata={'description': 'Replication role of the partner server.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSqlServerFailoverGroup(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_failover_group"
    _kind_display: ClassVar[str] = "Azure SQL Server Failover Group"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Failover Group is a feature that manages automatic failover for multiple databases across Azure regions. It maintains data synchronization between primary and secondary servers, ensuring database availability during outages or disasters. When failover occurs, the group redirects client connections to the secondary server, minimizing downtime and data loss for mission-critical applications."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/database/auto-failover-group-overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "group", "group": "compute"}
    # Collect via AzureSqlServer()
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_sql_server_database"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "database_ids": S("properties", "databases"),
        "partner_servers": S("properties", "partnerServers") >> ForallBend(AzurePartnerInfo.mapping),
        "group_read_only_endpoint": S("properties", "readOnlyEndpoint", "failoverPolicy"),
        "group_read_write_endpoint": S("properties", "readWriteEndpoint")
        >> Bend(AzureFailoverGroupReadWriteEndpoint.mapping),
        "replication_role": S("properties", "replicationRole"),
        "replication_state": S("properties", "replicationState"),
    }
    database_ids: Optional[List[str]] = field(default=None, metadata={'description': 'List of databases in the failover group.'})  # fmt: skip
    partner_servers: Optional[List[AzurePartnerInfo]] = field(default=None, metadata={'description': 'List of partner server information for the failover group.'})  # fmt: skip
    group_read_only_endpoint: Optional[str] = field(default=None, metadata={'description': 'Read-only endpoint of the failover group instance.'})  # fmt: skip
    group_read_write_endpoint: Optional[AzureFailoverGroupReadWriteEndpoint] = field(default=None, metadata={'description': 'Read-write endpoint of the failover group instance.'})  # fmt: skip
    replication_role: Optional[str] = field(default=None, metadata={'description': 'Local replication role of the failover group instance.'})  # fmt: skip
    replication_state: Optional[str] = field(default=None, metadata={'description': 'Replication state of the failover group instance.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if database_ids := self.database_ids:
            for database_id in database_ids:
                builder.add_edge(
                    self, edge_type=EdgeType.default, reverse=True, clazz=AzureSqlServerDatabase, id=database_id
                )


@define(eq=False, slots=False)
class AzureSqlServerFirewallRule(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_firewall_rule"
    _kind_display: ClassVar[str] = "Azure SQL Server Firewall Rule"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Firewall Rule is a security feature that controls network access to Azure SQL databases and servers. It defines IP address ranges permitted to connect to the database, blocking unauthorized access attempts. Administrators can configure rules at the server or database level, specifying individual IP addresses or address ranges to grant or restrict access."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "firewall", "group": "networking"}
    # Collect via AzureSqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "end_ip_address": S("properties", "endIpAddress"),
        "start_ip_address": S("properties", "startIpAddress"),
    }
    end_ip_address: Optional[str] = field(default=None, metadata={'description': 'The end IP address of the firewall rule. Must be IPv4 format. Must be greater than or equal to startIpAddress. Use value 0.0.0.0 for all Azure-internal IP addresses.'})  # fmt: skip
    start_ip_address: Optional[str] = field(default=None, metadata={'description': 'The start IP address of the firewall rule. Must be IPv4 format. Use value 0.0.0.0 for all Azure-internal IP addresses.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureSqlServerDatabaseGeoBackupPolicy(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_database_geo_backup_policy"
    _kind_display: ClassVar[str] = "Azure SQL Server Database Geo Backup Policy"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Database Geo Backup Policy is a feature that creates automated backups of SQL databases in a secondary region. It provides disaster recovery capabilities by replicating data across geographically distant Azure regions. This policy ensures data protection and business continuity in case of regional outages or failures, minimizing data loss and enabling quick recovery to maintain database availability."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/database/active-geo-replication-overview"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "policy", "group": "database"}
    # Collect via AzureSqlServerDatabase()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "backup_policy_kind": S("kind"),
        "state": S("properties", "state"),
        "storage_type": S("properties", "storageType"),
    }
    backup_policy_kind: Optional[str] = field(default=None, metadata={'description': 'Kind of geo backup policy. This is metadata used for the Azure portal experience.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The state of the geo backup policy."})
    storage_type: Optional[str] = field(default=None, metadata={'description': 'The storage type of the geo backup policy.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureInstanceFailoverGroupReadWriteEndpoint:
    kind: ClassVar[str] = "azure_instance_failover_group_read_write_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failover_policy": S("failoverPolicy"),
        "failover_with_data_loss_grace_period_minutes": S("failoverWithDataLossGracePeriodMinutes"),
    }
    failover_policy: Optional[str] = field(default=None, metadata={'description': 'Failover policy of the read-write endpoint for the failover group. If failoverPolicy is Automatic then failoverWithDataLossGracePeriodMinutes is required.'})  # fmt: skip
    failover_with_data_loss_grace_period_minutes: Optional[int] = field(default=None, metadata={'description': 'Grace period before failover with data loss is attempted for the read-write endpoint. If failoverPolicy is Automatic then failoverWithDataLossGracePeriodMinutes is required.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePartnerRegionInfo:
    kind: ClassVar[str] = "azure_partner_region_info"
    mapping: ClassVar[Dict[str, Bender]] = {"location": S("location"), "replication_role": S("replicationRole")}
    location: Optional[str] = field(default=None, metadata={'description': 'Geo location of the partner managed instances.'})  # fmt: skip
    replication_role: Optional[str] = field(default=None, metadata={'description': 'Replication role of the partner managed instances.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedInstancePairInfo:
    kind: ClassVar[str] = "azure_managed_instance_pair_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "partner_managed_instance_id": S("partnerManagedInstanceId"),
        "primary_managed_instance_id": S("primaryManagedInstanceId"),
    }
    partner_managed_instance_id: Optional[str] = field(default=None, metadata={'description': 'Id of Partner Managed Instance in pair.'})  # fmt: skip
    primary_managed_instance_id: Optional[str] = field(default=None, metadata={'description': 'Id of Primary Managed Instance in pair.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSqlServerManagedInstanceFailoverGroup(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_managed_instance_failover_group"
    _kind_display: ClassVar[str] = "Azure SQL Server Managed Instance Failover Group"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Managed Instance Failover Group is a feature that provides database redundancy and high availability across multiple regions. It automatically replicates databases from a primary managed instance to a secondary instance in a different region. During outages or disasters, it initiates failover to the secondary instance, ensuring continuous data access and minimizing downtime for applications."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/managed-instance/auto-failover-group-overview"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "database", "group": "database"}
    # Collect via AzureSqlServerManagedInstance()
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_sql_server_managed_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "managed_instance_pairs": S("properties", "managedInstancePairs")
        >> ForallBend(AzureManagedInstancePairInfo.mapping),
        "partner_regions": S("properties", "partnerRegions") >> ForallBend(AzurePartnerRegionInfo.mapping),
        "sql_instance_read_only_endpoint": S("properties", "readOnlyEndpoint", "failoverPolicy"),
        "sql_instance_read_write_endpoint": S("properties", "readWriteEndpoint")
        >> Bend(AzureInstanceFailoverGroupReadWriteEndpoint.mapping),
        "replication_role": S("properties", "replicationRole"),
        "replication_state": S("properties", "replicationState"),
    }
    managed_instance_pairs: Optional[List[AzureManagedInstancePairInfo]] = field(default=None, metadata={'description': 'List of managed instance pairs in the failover group.'})  # fmt: skip
    partner_regions: Optional[List[AzurePartnerRegionInfo]] = field(default=None, metadata={'description': 'Partner region information for the failover group.'})  # fmt: skip
    sql_instance_read_only_endpoint: Optional[str] = field(default=None, metadata={'description': 'Read-only endpoint of the failover group instance.'})  # fmt: skip
    sql_instance_read_write_endpoint: Optional[AzureInstanceFailoverGroupReadWriteEndpoint] = field(default=None, metadata={'description': 'Read-write endpoint of the failover group instance.'})  # fmt: skip
    replication_role: Optional[str] = field(default=None, metadata={'description': 'Local replication role of the failover group instance.'})  # fmt: skip
    replication_state: Optional[str] = field(default=None, metadata={'description': 'Replication state of the failover group instance.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if managed_instance_pairs := self.managed_instance_pairs:
            for managed_instance_pair in managed_instance_pairs:
                if (primary_managed_instance_id := managed_instance_pair.primary_managed_instance_id) and (
                    secondary_managed_instance_id := managed_instance_pair.partner_managed_instance_id
                ):
                    builder.add_edge(
                        self,
                        reverse=True,
                        edge_type=EdgeType.default,
                        id=primary_managed_instance_id,
                        clazz=AzureSqlServerManagedInstance,
                    )
                    builder.add_edge(
                        self,
                        reverse=True,
                        edge_type=EdgeType.default,
                        id=secondary_managed_instance_id,
                        clazz=AzureSqlServerManagedInstance,
                    )


@define(eq=False, slots=False)
class AzureSqlServerManagedInstancePool(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_managed_instance_pool"
    _kind_display: ClassVar[str] = "Azure SQL Server Managed Instance Pool"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Managed Instance Pool is a service that hosts multiple SQL Server Managed Instances within a shared resource environment. It provides cost-effective database management by sharing resources across instances while maintaining isolation. Users can create and manage instances within the pool, optimizing resource utilization and reducing operational overhead for database deployments."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/managed-instance/instance-pools-overview"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "cluster", "group": "database"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="sql",
        version="2021-11-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Sql/instancePools",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_network_subnet"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "location": S("location"),
        "license_type": S("properties", "licenseType"),
        "instance_pool_sku": S("sku") >> Bend(AzureSku.mapping),
        "subnet_id": S("properties", "subnetId"),
        "v_cores": S("properties", "vCores"),
    }
    license_type: Optional[str] = field(default=None, metadata={'description': 'The license type. Possible values are LicenseIncluded (price for SQL license is included) and BasePrice (without SQL license price).'})  # fmt: skip
    instance_pool_sku: Optional[AzureSku] = field(default=None, metadata={"description": "An ARM Resource SKU."})
    subnet_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of the subnet to place this instance pool in.'})  # fmt: skip
    v_cores: Optional[int] = field(default=None, metadata={'description': 'Count of vCores belonging to this instance pool.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if subnet_id := self.subnet_id:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureNetworkSubnet, id=subnet_id)


@define(eq=False, slots=False)
class AzureSqlServerJobAgent(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_job_agent"
    _kind_display: ClassVar[str] = "Azure SQL Server Job Agent"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Job Agent is a component of Azure SQL Managed Instance that automates and schedules database maintenance tasks. It executes jobs containing Transact-SQL scripts across multiple databases, performs routine operations, and manages backups. The agent supports recurring schedules, monitors job status, and provides notifications for successful or failed job runs."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/database/job-agent-overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "database"}
    # Collect via AzureSqlServer()
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["azure_sql_server_database"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "location": S("location"),
        "database_id": S("properties", "databaseId"),
        "job_agent_sku": S("sku") >> Bend(AzureSku.mapping),
        "state": S("properties", "state"),
    }
    database_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of the database to store job metadata in.'})  # fmt: skip
    job_agent_sku: Optional[AzureSku] = field(default=None, metadata={"description": "An ARM Resource SKU."})
    state: Optional[str] = field(default=None, metadata={"description": "The state of the job agent."})
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if database_id := self.database_id:
            builder.add_edge(
                self, edge_type=EdgeType.default, reverse=True, clazz=AzureSqlServerDatabase, id=database_id
            )


@define(eq=False, slots=False)
class AzureSqlServerManagedInstanceADAdministrator(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_managed_instance_ad_administrator"
    _kind_display: ClassVar[str] = "Azure SQL Server Managed Instance Ad Administrator"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Managed Instance AD Administrator is a role that manages authentication and authorization for a SQL Managed Instance using Azure Active Directory. It configures and maintains AD integration, sets up single sign-on, and controls access to database resources. This role ensures secure user authentication and simplifies identity management within the SQL Managed Instance environment."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/managed-instance/authentication-aad-configure?view=azuresql#provision-azure-ad-administrator"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "user", "group": "access_control"}
    _reference_kinds: ClassVar[ModelReference] = {"successors": {"default": [MicrosoftResource.kind]}}
    # Collect via AzureSqlManagedInstance()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "administrator_type": S("properties", "administratorType"),
        "login": S("properties", "login"),
        "sid": S("properties", "sid"),
        "tenant_id": S("properties", "tenantId"),
    }
    administrator_type: Optional[str] = field(default=None, metadata={'description': 'Type of the managed instance administrator.'})  # fmt: skip
    login: Optional[str] = field(default=None, metadata={'description': 'Login name of the managed instance administrator.'})  # fmt: skip
    sid: Optional[str] = field(default=None, metadata={'description': 'SID (object ID) of the managed instance administrator.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={'description': 'Tenant ID of the managed instance administrator.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if user_id := self.sid:
            builder.add_deferred_edge(
                from_node=self,
                to_node=BySearchCriteria(f'is({MicrosoftGraphUser.kind}) and reported.id=="{user_id}"'),
            )


@define(eq=False, slots=False)
class AzureSqlServerManagedInstanceDatabase(MicrosoftResource, BaseDatabase):
    kind: ClassVar[str] = "azure_sql_server_managed_instance_database"
    _kind_display: ClassVar[str] = "Azure SQL Server Managed Instance Database"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Managed Instance Database is a cloud-based service that provides SQL Server functionality in Azure. It offers compatibility with on-premises SQL Server databases while handling maintenance, updates, and backups. Users can migrate existing databases to the cloud, retaining features and security settings, and benefit from Azure's infrastructure without managing hardware or software."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/managed-instance/instance-create-quickstart"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "database", "group": "database"}
    # Collect via AzureSqlServerManagedInstance()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "location": S("location"),
        "ctime": S("properties", "creationDate"),
        "auto_complete_restore": S("properties", "autoCompleteRestore"),
        "catalog_collation": S("properties", "catalogCollation"),
        "collation": S("properties", "collation"),
        "create_mode": S("properties", "createMode"),
        "creation_date": S("properties", "creationDate"),
        "default_secondary_location": S("properties", "defaultSecondaryLocation"),
        "earliest_restore_point": S("properties", "earliestRestorePoint"),
        "failover_group_id": S("properties", "failoverGroupId"),
        "last_backup_name": S("properties", "lastBackupName"),
        "long_term_retention_backup_resource_id": S("properties", "longTermRetentionBackupResourceId"),
        "recoverable_database_id": S("properties", "recoverableDatabaseId"),
        "restorable_dropped_database_id": S("properties", "restorableDroppedDatabaseId"),
        "restore_point_in_time": S("properties", "restorePointInTime"),
        "source_database_id": S("properties", "sourceDatabaseId"),
        "status": S("properties", "status"),
        "storage_container_sas_token": S("properties", "storageContainerSasToken"),
        "storage_container_uri": S("properties", "storageContainerUri"),
        "db_type": K("sql"),
        "db_status": S("properties", "state")
        >> MapEnum(
            {
                "Creating": DatabaseInstanceStatus.BUSY,
                "Inaccessible": DatabaseInstanceStatus.FAILED,
                "Offline": DatabaseInstanceStatus.STOPPED,
                "Online": DatabaseInstanceStatus.AVAILABLE,
                "Restoring": DatabaseInstanceStatus.BUSY,
                "Shutdown": DatabaseInstanceStatus.STOPPED,
                "Updating": DatabaseInstanceStatus.BUSY,
            },
            default=DatabaseInstanceStatus.UNKNOWN,
        ),
    }
    auto_complete_restore: Optional[bool] = field(default=None, metadata={'description': 'Whether to auto complete restore of this managed database.'})  # fmt: skip
    catalog_collation: Optional[str] = field(default=None, metadata={'description': 'Collation of the metadata catalog.'})  # fmt: skip
    collation: Optional[str] = field(default=None, metadata={"description": "Collation of the managed database."})
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Managed database create mode. PointInTimeRestore: Create a database by restoring a point in time backup of an existing database. SourceDatabaseName, SourceManagedInstanceName and PointInTime must be specified. RestoreExternalBackup: Create a database by restoring from external backup files. Collation, StorageContainerUri and StorageContainerSasToken must be specified. Recovery: Creates a database by restoring a geo-replicated backup. RecoverableDatabaseId must be specified as the recoverable database resource ID to restore. RestoreLongTermRetentionBackup: Create a database by restoring from a long term retention backup (longTermRetentionBackupResourceId required).'})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "Creation date of the database."})
    default_secondary_location: Optional[str] = field(default=None, metadata={"description": "Geo paired region."})
    earliest_restore_point: Optional[datetime] = field(default=None, metadata={'description': 'Earliest restore point in time for point in time restore.'})  # fmt: skip
    failover_group_id: Optional[str] = field(default=None, metadata={'description': 'Instance Failover Group resource identifier that this managed database belongs to.'})  # fmt: skip
    last_backup_name: Optional[str] = field(default=None, metadata={'description': 'Last backup file name for restore of this managed database.'})  # fmt: skip
    long_term_retention_backup_resource_id: Optional[str] = field(default=None, metadata={'description': 'The name of the Long Term Retention backup to be used for restore of this managed database.'})  # fmt: skip
    recoverable_database_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the recoverable database associated with create operation of this database.'})  # fmt: skip
    restorable_dropped_database_id: Optional[str] = field(default=None, metadata={'description': 'The restorable dropped database resource id to restore when creating this database.'})  # fmt: skip
    restore_point_in_time: Optional[datetime] = field(default=None, metadata={'description': 'Conditional. If createMode is PointInTimeRestore, this value is required. Specifies the point in time (ISO8601 format) of the source database that will be restored to create the new database.'})  # fmt: skip
    source_database_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the source database associated with create operation of this database.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "Status of the database."})
    storage_container_sas_token: Optional[str] = field(default=None, metadata={'description': 'Conditional. If createMode is RestoreExternalBackup, this value is required. Specifies the storage container sas token.'})  # fmt: skip
    storage_container_uri: Optional[str] = field(default=None, metadata={'description': 'Conditional. If createMode is RestoreExternalBackup, this value is required. Specifies the uri of the storage container where backups for this restore are stored.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if database_id := self.id:

            def set_encryption_status() -> None:
                api_spec = AzureResourceSpec(
                    service="sql",
                    version="2021-11-01",
                    path=f"{database_id}/transparentDataEncryption",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)
                if not items:
                    return
                try:
                    state = items[0]["properties"]["state"]
                    if state == "Enabled":
                        self.volume_encrypted = True
                    else:
                        self.volume_encrypted = False
                except KeyError as e:
                    log.warning(f"An error occured while setting volume_encrypted: {e}")

            graph_builder.submit_work(service_name, set_encryption_status)


@define(eq=False, slots=False)
class AzureManagedInstancePrivateLinkServiceConnectionStateProperty:
    kind: ClassVar[str] = "azure_managed_instance_private_link_service_connection_state_property"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions_required": S("actionsRequired"),
        "description": S("description"),
        "status": S("status"),
    }
    actions_required: Optional[str] = field(default=None, metadata={'description': 'The private link service connection description.'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The private link service connection description.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'The private link service connection status.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedInstancePecProperty:
    kind: ClassVar[str] = "azure_managed_instance_pec_property"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "private_endpoint_id": S("properties", "privateEndpoint", "id"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzureManagedInstancePrivateLinkServiceConnectionStateProperty.mapping),
        "provisioning_state": S("properties", "provisioningState"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID."})
    private_endpoint_id: Optional[str] = field(default=None, metadata={"description": ""})
    private_link_service_connection_state: Optional[AzureManagedInstancePrivateLinkServiceConnectionStateProperty] = field(default=None, metadata={'description': ''})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'State of the Private Endpoint Connection.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureManagedInstanceExternalAdministrator:
    kind: ClassVar[str] = "azure_managed_instance_external_administrator"
    mapping: ClassVar[Dict[str, Bender]] = {
        "administrator_type": S("administratorType"),
        "azure_ad_only_authentication": S("azureADOnlyAuthentication"),
        "login": S("login"),
        "principal_type": S("principalType"),
        "sid": S("sid"),
        "tenant_id": S("tenantId"),
    }
    administrator_type: Optional[str] = field(default=None, metadata={'description': 'Type of the sever administrator.'})  # fmt: skip
    azure_ad_only_authentication: Optional[bool] = field(default=None, metadata={'description': 'Azure Active Directory only Authentication enabled.'})  # fmt: skip
    login: Optional[str] = field(default=None, metadata={"description": "Login name of the server administrator."})
    principal_type: Optional[str] = field(default=None, metadata={'description': 'Principal Type of the sever administrator.'})  # fmt: skip
    sid: Optional[str] = field(default=None, metadata={"description": "SID (object ID) of the server administrator."})
    tenant_id: Optional[str] = field(default=None, metadata={"description": "Tenant ID of the administrator."})


@define(eq=False, slots=False)
class AzureServicePrincipal:
    kind: ClassVar[str] = "azure_service_principal"
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_id": S("clientId"),
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
    }
    client_id: Optional[str] = field(default=None, metadata={'description': 'The Azure Active Directory application client id.'})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The Azure Active Directory application object id.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={"description": "The Azure Active Directory tenant id."})
    type: Optional[str] = field(default=None, metadata={"description": "Service principal type."})


@define(eq=False, slots=False)
class AzureSqlServerManagedInstance(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_managed_instance"
    _kind_display: ClassVar[str] = "Azure SQL Server Managed Instance"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Managed Instance is a cloud database service that provides SQL Server compatibility with automated management features. It offers a near-complete parity with on-premises SQL Server instances, including native virtual network support and full SQL Server engine compatibility, while handling routine database management tasks such as backups, patching, and monitoring."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/managed-instance/"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "instance", "group": "database"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="sql",
        version="2021-11-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Sql/managedInstances",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_sql_server_managed_instance_database",
                "azure_sql_server_trust_group",
                "microsoft_graph_service_principal",
                "microsoft_graph_user",
                "azure_sql_server_managed_instance_ad_administrator",
            ]
        },
        "predecessors": {"default": ["azure_sql_server_managed_instance_pool", "azure_network_subnet"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "location": S("location"),
        "administrator_login": S("properties", "administratorLogin"),
        "administrator_login_password": S("properties", "administratorLoginPassword"),
        "managed_instance_administrators": S("properties", "administrators")
        >> Bend(AzureManagedInstanceExternalAdministrator.mapping),
        "collation": S("properties", "collation"),
        "current_backup_storage_redundancy": S("properties", "currentBackupStorageRedundancy"),
        "dns_zone": S("properties", "dnsZone"),
        "dns_zone_partner": S("properties", "dnsZonePartner"),
        "fully_qualified_domain_name": S("properties", "fullyQualifiedDomainName"),
        "managed_instance_identity": S("identity") >> Bend(AzureResourceIdentity.mapping),
        "instance_pool_id": S("properties", "instancePoolId"),
        "key_id": S("properties", "keyId"),
        "license_type": S("properties", "licenseType"),
        "maintenance_configuration_id": S("properties", "maintenanceConfigurationId"),
        "managed_instance_create_mode": S("properties", "managedInstanceCreateMode"),
        "minimal_tls_version": S("properties", "minimalTlsVersion"),
        "primary_user_assigned_identity_id": S("properties", "primaryUserAssignedIdentityId"),
        "instance_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzureManagedInstancePecProperty.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "proxy_override": S("properties", "proxyOverride"),
        "public_data_endpoint_enabled": S("properties", "publicDataEndpointEnabled"),
        "requested_backup_storage_redundancy": S("properties", "requestedBackupStorageRedundancy"),
        "restore_point_in_time": S("properties", "restorePointInTime"),
        "service_principal": S("properties", "servicePrincipal") >> Bend(AzureServicePrincipal.mapping),
        "managed_instance_sku": S("sku") >> Bend(AzureSku.mapping),
        "source_managed_instance_id": S("properties", "sourceManagedInstanceId"),
        "state": S("properties", "state"),
        "storage_size_in_gb": S("properties", "storageSizeInGB"),
        "subnet_id": S("properties", "subnetId"),
        "timezone_id": S("properties", "timezoneId"),
        "v_cores": S("properties", "vCores"),
        "zone_redundant": S("properties", "zoneRedundant"),
    }
    administrator_login: Optional[str] = field(default=None, metadata={'description': 'Administrator username for the managed instance. Can only be specified when the managed instance is being created (and is required for creation).'})  # fmt: skip
    administrator_login_password: Optional[str] = field(default=None, metadata={'description': 'The administrator login password (required for managed instance creation).'})  # fmt: skip
    managed_instance_administrators: Optional[AzureManagedInstanceExternalAdministrator] = field(default=None, metadata={'description': 'Properties of a active directory administrator.'})  # fmt: skip
    collation: Optional[str] = field(default=None, metadata={"description": "Collation of the managed instance."})
    current_backup_storage_redundancy: Optional[str] = field(default=None, metadata={'description': 'The storage account type used to store backups for this instance. The options are Local (LocallyRedundantStorage), Zone (ZoneRedundantStorage), Geo (GeoRedundantStorage) and GeoZone(GeoZoneRedundantStorage)'})  # fmt: skip
    dns_zone: Optional[str] = field(default=None, metadata={'description': 'The Dns Zone that the managed instance is in.'})  # fmt: skip
    dns_zone_partner: Optional[str] = field(default=None, metadata={'description': 'The resource id of another managed instance whose DNS zone this managed instance will share after creation.'})  # fmt: skip
    fully_qualified_domain_name: Optional[str] = field(default=None, metadata={'description': 'The fully qualified domain name of the managed instance.'})  # fmt: skip
    managed_instance_identity: Optional[AzureResourceIdentity] = field(default=None, metadata={'description': 'Azure Active Directory identity configuration for a resource.'})  # fmt: skip
    instance_pool_id: Optional[str] = field(default=None, metadata={'description': 'The Id of the instance pool this managed server belongs to.'})  # fmt: skip
    key_id: Optional[str] = field(default=None, metadata={'description': 'A CMK URI of the key to use for encryption.'})  # fmt: skip
    license_type: Optional[str] = field(default=None, metadata={'description': 'The license type. Possible values are LicenseIncluded (regular price inclusive of a new SQL license) and BasePrice (discounted AHB price for bringing your own SQL licenses).'})  # fmt: skip
    maintenance_configuration_id: Optional[str] = field(default=None, metadata={'description': 'Specifies maintenance configuration id to apply to this managed instance.'})  # fmt: skip
    managed_instance_create_mode: Optional[str] = field(default=None, metadata={'description': 'Specifies the mode of database creation. Default: Regular instance creation. Restore: Creates an instance by restoring a set of backups to specific point in time. RestorePointInTime and SourceManagedInstanceId must be specified.'})  # fmt: skip
    minimal_tls_version: Optional[str] = field(default=None, metadata={'description': 'Minimal TLS version. Allowed values: None , 1.0 , 1.1 , 1.2 '})  # fmt: skip
    primary_user_assigned_identity_id: Optional[str] = field(default=None, metadata={'description': 'The resource id of a user assigned identity to be used by default.'})  # fmt: skip
    instance_private_endpoint_connections: Optional[List[AzureManagedInstancePecProperty]] = field(default=None, metadata={'description': 'List of private endpoint connections on a managed instance.'})  # fmt: skip
    proxy_override: Optional[str] = field(default=None, metadata={'description': 'Connection type used for connecting to the instance.'})  # fmt: skip
    public_data_endpoint_enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether or not the public data endpoint is enabled.'})  # fmt: skip
    requested_backup_storage_redundancy: Optional[str] = field(default=None, metadata={'description': 'The storage account type to be used to store backups for this instance. The options are Local (LocallyRedundantStorage), Zone (ZoneRedundantStorage), Geo (GeoRedundantStorage) and GeoZone(GeoZoneRedundantStorage)'})  # fmt: skip
    restore_point_in_time: Optional[datetime] = field(default=None, metadata={'description': 'Specifies the point in time (ISO8601 format) of the source database that will be restored to create the new database.'})  # fmt: skip
    service_principal: Optional[AzureServicePrincipal] = field(default=None, metadata={'description': 'The managed instance s service principal configuration for a resource.'})  # fmt: skip
    managed_instance_sku: Optional[AzureSku] = field(default=None, metadata={"description": "An ARM Resource SKU."})
    source_managed_instance_id: Optional[str] = field(default=None, metadata={'description': 'The resource identifier of the source managed instance associated with create operation of this instance.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The state of the managed instance."})
    storage_size_in_gb: Optional[int] = field(default=None, metadata={'description': 'Storage size in GB. Minimum value: 32. Maximum value: 16384. Increments of 32 GB allowed only. Maximum value depends on the selected hardware family and number of vCores.'})  # fmt: skip
    subnet_id: Optional[str] = field(default=None, metadata={'description': 'Subnet resource ID for the managed instance.'})  # fmt: skip
    timezone_id: Optional[str] = field(default=None, metadata={'description': 'Id of the timezone. Allowed values are timezones supported by Windows. Windows keeps details on supported timezones, including the id.'})  # fmt: skip
    v_cores: Optional[int] = field(default=None, metadata={'description': 'The number of vCores. Allowed values: 8, 16, 24, 32, 40, 64, 80.'})  # fmt: skip
    zone_redundant: Optional[bool] = field(default=None, metadata={'description': 'Whether or not the multi-az is enabled.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        managed_instance_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
    ) -> None:
        path = f"{managed_instance_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="sql",
            version="2021-11-01",
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
            if isinstance(clazz, AzureSqlServerManagedInstanceDatabase):
                clazz.db_publicly_accessible = self.public_data_endpoint_enabled
                if self.managed_instance_sku and self.managed_instance_sku.name:
                    clazz.instance_type = self.managed_instance_sku.name
                clazz.volume_size = self.storage_size_in_gb
                clazz.db_endpoint = self.fully_qualified_domain_name
            graph_builder.add_edge(
                self,
                edge_type=EdgeType.default,
                id=clazz.id,
                clazz=class_instance,
            )

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if server_id := self.id:
            resources_to_collect = [
                ("databases", AzureSqlServerManagedInstanceDatabase),
                ("serverTrustGroups", AzureSqlServerTrustGroup),
                ("administrators", AzureSqlServerManagedInstanceADAdministrator),
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

            def collect_instance_failover_group() -> None:
                rg = self.resource_group_name
                subscription_id = self.resource_subscription_id
                location = self.location
                if not rg or not subscription_id or not location:
                    return
                api_spec = AzureResourceSpec(
                    service="sql",
                    version="2021-11-01",
                    path=f"/subscriptions/{subscription_id}/resourceGroups/{rg}/providers/Microsoft.Sql/locations/{location}/instanceFailoverGroups",
                    path_parameters=[],
                    query_parameters=["api-version"],
                    access_path="value",
                    expect_array=True,
                )
                items = graph_builder.client.list(api_spec)

                AzureSqlServerManagedInstanceFailoverGroup.collect(items, graph_builder)

            graph_builder.submit_work(service_name, collect_instance_failover_group)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if private_endpoint_connections := self.instance_private_endpoint_connections:
            for private_endpoint_connection in private_endpoint_connections:
                if endpoint_id := private_endpoint_connection.private_endpoint_id:
                    builder.add_edge(
                        self,
                        edge_type=EdgeType.default,
                        clazz=AzurePrivateEndpointConnection,
                        private_endpoint_id=endpoint_id,
                    )
        if instance_pool_id := self.instance_pool_id:
            builder.add_edge(
                self,
                edge_type=EdgeType.default,
                reverse=True,
                clazz=AzureSqlServerManagedInstancePool,
                id=instance_pool_id,
            )
        if subnet_id := self.subnet_id:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureNetworkSubnet, id=subnet_id)

        # principal: collected via ms graph -> create a deferred edge
        if mii := self.managed_instance_identity:
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
class AzureSqlServerVirtualCluster(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_virtual_cluster"
    _kind_display: ClassVar[str] = "Azure SQL Server Virtual Cluster"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Virtual Cluster is a managed database service in Microsoft Azure. It provides SQL Server functionality in a cloud environment, offering high availability and disaster recovery features. Users can deploy, manage, and scale SQL Server databases without maintaining physical infrastructure. The service supports various workloads and integrates with other Azure services for data management and analytics."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/database/virtual-cluster-overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "cluster", "group": "database"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="sql",
        version="2022-05-01-preview",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Sql/virtualClusters",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["azure_sql_server_managed_instance"]},
        "predecessors": {"default": ["azure_network_subnet"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "location": S("location"),
        "child_resources": S("properties", "childResources"),
        "family": S("properties", "family"),
        "maintenance_configuration_id": S("properties", "maintenanceConfigurationId"),
        "subnet_id": S("properties", "subnetId"),
    }
    child_resources: Optional[List[str]] = field(default=None, metadata={'description': 'List of resources in this virtual cluster.'})  # fmt: skip
    family: Optional[str] = field(default=None, metadata={'description': 'If the service has different generations of hardware, for the same SKU, then that can be captured here.'})  # fmt: skip
    maintenance_configuration_id: Optional[str] = field(default=None, metadata={'description': 'Specifies maintenance configuration id to apply to this virtual cluster.'})  # fmt: skip
    subnet_id: Optional[str] = field(default=None, metadata={'description': 'Subnet resource ID for the virtual cluster.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if managed_instance_ids := self.child_resources:
            for managed_instance_id in managed_instance_ids:
                builder.add_edge(
                    self, edge_type=EdgeType.default, clazz=AzureSqlServerManagedInstance, id=managed_instance_id
                )
        if subnet_id := self.subnet_id:
            builder.add_edge(self, edge_type=EdgeType.default, reverse=True, clazz=AzureNetworkSubnet, id=subnet_id)


@define(eq=False, slots=False)
class AzureSqlServerTrustGroup(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_trust_group"
    _kind_display: ClassVar[str] = "Azure SQL Server Trust Group"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Trust Group is a security feature that enhances data protection across multiple SQL Server instances. It creates a trusted boundary for data sharing and communication between servers, reducing the need for individual firewall rules. This group facilitates secure cross-server queries and transactions while maintaining isolation from external networks."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/database/trust-group-concept-overview?view=azuresql"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "group", "group": "access_control"}
    # Collect via AzureSqlServerManagedInstance()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "group_members": S("properties") >> S("groupMembers", default=[]) >> ForallBend(S("serverId")),
        "trust_scopes": S("properties", "trustScopes"),
    }
    group_members: Optional[List[str]] = field(default=None, metadata={'description': 'Group members information for the server trust group.'})  # fmt: skip
    trust_scopes: Optional[List[str]] = field(default=None, metadata={'description': 'Trust scope of the server trust group.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureSqlServerVirtualNetworkRule(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_virtual_network_rule"
    _kind_display: ClassVar[str] = "Azure SQL Server Virtual Network Rule"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Virtual Network Rule is a security feature that controls network access to SQL Server instances. It defines which subnet within an Azure Virtual Network can connect to the SQL Server. This rule enhances database security by restricting access to specific virtual networks, reducing potential attack surfaces and improving data protection."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/database/vnet-service-endpoint-rule-overview"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "networking"}
    # Collect via AzureSqlServer()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "ignore_missing_vnet_service_endpoint": S("properties", "ignoreMissingVnetServiceEndpoint"),
        "state": S("properties", "state"),
        "virtual_network_subnet_id": S("properties", "virtualNetworkSubnetId"),
    }
    ignore_missing_vnet_service_endpoint: Optional[bool] = field(default=None, metadata={'description': 'Create firewall rule before the virtual network has vnet service endpoint enabled.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "Virtual Network Rule State"})
    virtual_network_subnet_id: Optional[str] = field(default=None, metadata={'description': 'The ARM resource id of the virtual network subnet.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureSqlServerDatabaseWorkloadGroup(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_database_workload_group"
    _kind_display: ClassVar[str] = "Azure SQL Server Database Workload Group"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Database Workload Group is a resource management feature that organizes database queries into groups with defined resource limits. It controls CPU, memory, and concurrent request usage for each group, ensuring fair resource distribution and preventing resource contention. This feature helps manage workload priorities and maintain performance across different database tasks."  # fmt: skip
    _docs_url: ClassVar[str] = (
        "https://learn.microsoft.com/en-us/azure/azure-sql/database/workload-group-resource-governor-overview"
    )
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "group", "group": "compute"}
    # Collect via AzureSqlServerDatabase()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "importance": S("properties", "importance"),
        "max_resource_percent": S("properties", "maxResourcePercent"),
        "max_resource_percent_per_request": S("properties", "maxResourcePercentPerRequest"),
        "min_resource_percent": S("properties", "minResourcePercent"),
        "min_resource_percent_per_request": S("properties", "minResourcePercentPerRequest"),
        "query_execution_timeout": S("properties", "queryExecutionTimeout"),
    }
    importance: Optional[str] = field(default=None, metadata={"description": "The workload group importance level."})
    max_resource_percent: Optional[int] = field(default=None, metadata={'description': 'The workload group cap percentage resource.'})  # fmt: skip
    max_resource_percent_per_request: Optional[float] = field(default=None, metadata={'description': 'The workload group request maximum grant percentage.'})  # fmt: skip
    min_resource_percent: Optional[int] = field(default=None, metadata={'description': 'The workload group minimum percentage resource.'})  # fmt: skip
    min_resource_percent_per_request: Optional[float] = field(default=None, metadata={'description': 'The workload group request minimum grant percentage.'})  # fmt: skip
    query_execution_timeout: Optional[int] = field(default=None, metadata={'description': 'The workload group query execution timeout.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureRecommendedActionStateInfo:
    kind: ClassVar[str] = "azure_recommended_action_state_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_initiated_by": S("actionInitiatedBy"),
        "current_value": S("currentValue"),
        "last_modified": S("lastModified"),
    }
    action_initiated_by: Optional[str] = field(default=None, metadata={'description': 'Gets who initiated the execution of this recommended action. Possible Value are: User -> When user explicity notified system to apply the recommended action. System -> When auto-execute status of this advisor was set to Enabled , in which case the system applied it.'})  # fmt: skip
    current_value: Optional[str] = field(default=None, metadata={'description': 'Current state the recommended action is in. Some commonly used states are: Active -> recommended action is active and no action has been taken yet. Pending -> recommended action is approved for and is awaiting execution. Executing -> recommended action is being applied on the user database. Verifying -> recommended action was applied and is being verified of its usefulness by the system. Success -> recommended action was applied and improvement found during verification. Pending Revert -> verification found little or no improvement so recommended action is queued for revert or user has manually reverted. Reverting -> changes made while applying recommended action are being reverted on the user database. Reverted -> successfully reverted the changes made by recommended action on user database. Ignored -> user explicitly ignored/discarded the recommended action. '})  # fmt: skip
    last_modified: Optional[datetime] = field(default=None, metadata={'description': 'Gets the time when the state was last modified'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRecommendedActionImplementationInfo:
    kind: ClassVar[str] = "azure_recommended_action_implementation_info"
    mapping: ClassVar[Dict[str, Bender]] = {"method": S("method"), "script": S("script")}
    method: Optional[str] = field(default=None, metadata={'description': 'Gets the method in which this recommended action can be manually implemented. e.g., TSql, AzurePowerShell.'})  # fmt: skip
    script: Optional[str] = field(default=None, metadata={'description': 'Gets the manual implementation script. e.g., T-SQL script that could be executed on the database.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRecommendedActionErrorInfo:
    kind: ClassVar[str] = "azure_recommended_action_error_info"
    mapping: ClassVar[Dict[str, Bender]] = {"error_code": S("errorCode"), "is_retryable": S("isRetryable")}
    error_code: Optional[str] = field(default=None, metadata={'description': 'Gets the reason why the recommended action was put to error state. e.g., DatabaseHasQdsOff, IndexAlreadyExists'})  # fmt: skip
    is_retryable: Optional[str] = field(default=None, metadata={'description': 'Gets whether the error could be ignored and recommended action could be retried. Possible values are: Yes/No'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRecommendedActionImpactRecord:
    kind: ClassVar[str] = "azure_recommended_action_impact_record"
    mapping: ClassVar[Dict[str, Bender]] = {
        "absolute_value": S("absoluteValue"),
        "change_value_absolute": S("changeValueAbsolute"),
        "change_value_relative": S("changeValueRelative"),
        "dimension_name": S("dimensionName"),
        "unit": S("unit"),
    }
    absolute_value: Optional[float] = field(default=None, metadata={'description': 'Gets the absolute value of this dimension if applicable. e.g., Number of Queries affected'})  # fmt: skip
    change_value_absolute: Optional[float] = field(default=None, metadata={'description': 'Gets the absolute change in the value of this dimension. e.g., Absolute Disk space change in Megabytes'})  # fmt: skip
    change_value_relative: Optional[float] = field(default=None, metadata={'description': 'Gets the relative change in the value of this dimension. e.g., Relative Disk space change in Percentage'})  # fmt: skip
    dimension_name: Optional[str] = field(default=None, metadata={'description': 'Gets the name of the impact dimension. e.g., CPUChange, DiskSpaceChange, NumberOfQueriesAffected.'})  # fmt: skip
    unit: Optional[str] = field(default=None, metadata={'description': 'Gets the name of the impact dimension. e.g., CPUChange, DiskSpaceChange, NumberOfQueriesAffected.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRecommendedActionMetricInfo:
    kind: ClassVar[str] = "azure_recommended_action_metric_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_name": S("metricName"),
        "start_time": S("startTime"),
        "time_grain": S("timeGrain"),
        "unit": S("unit"),
        "value": S("value"),
    }
    metric_name: Optional[str] = field(default=None, metadata={'description': 'Gets the name of the metric. e.g., CPU, Number of Queries.'})  # fmt: skip
    start_time: Optional[datetime] = field(default=None, metadata={'description': 'Gets the start time of time interval given by this MetricInfo.'})  # fmt: skip
    time_grain: Optional[str] = field(default=None, metadata={'description': 'Gets the duration of time interval for the value given by this MetricInfo. e.g., PT1H (1 hour)'})  # fmt: skip
    unit: Optional[str] = field(default=None, metadata={'description': 'Gets the unit in which metric is measured. e.g., DTU, Frequency'})  # fmt: skip
    value: Optional[float] = field(default=None, metadata={'description': 'Gets the value of the metric in the time interval given by this MetricInfo.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRecommendedAction:
    kind: ClassVar[str] = "azure_recommended_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "type": S("type"),
        "recommended_action_details": S("properties", "details"),
        "error_details": S("properties", "errorDetails") >> Bend(AzureRecommendedActionErrorInfo.mapping),
        "estimated_impact": S("properties", "estimatedImpact")
        >> ForallBend(AzureRecommendedActionImpactRecord.mapping),
        "execute_action_duration": S("properties", "executeActionDuration"),
        "execute_action_initiated_by": S("properties", "executeActionInitiatedBy"),
        "execute_action_initiated_time": S("properties", "executeActionInitiatedTime"),
        "execute_action_start_time": S("properties", "executeActionStartTime"),
        "implementation_details": S("properties", "implementationDetails")
        >> Bend(AzureRecommendedActionImplementationInfo.mapping),
        "is_archived_action": S("properties", "isArchivedAction"),
        "is_executable_action": S("properties", "isExecutableAction"),
        "is_revertable_action": S("properties", "isRevertableAction"),
        "recommended_action_kind": S("kind"),
        "last_refresh": S("properties", "lastRefresh"),
        "linked_objects": S("properties", "linkedObjects"),
        "observed_impact": S("properties", "observedImpact") >> ForallBend(AzureRecommendedActionImpactRecord.mapping),
        "recommendation_reason": S("properties", "recommendationReason"),
        "revert_action_duration": S("properties", "revertActionDuration"),
        "revert_action_initiated_by": S("properties", "revertActionInitiatedBy"),
        "revert_action_initiated_time": S("properties", "revertActionInitiatedTime"),
        "revert_action_start_time": S("properties", "revertActionStartTime"),
        "score": S("properties", "score"),
        "state": S("properties", "state") >> Bend(AzureRecommendedActionStateInfo.mapping),
        "time_series": S("properties", "timeSeries") >> ForallBend(AzureRecommendedActionMetricInfo.mapping),
        "valid_since": S("properties", "validSince"),
    }
    recommended_action_details: Optional[Dict[str, Any]] = field(default=None, metadata={'description': 'Gets additional details specific to this recommended action.'})  # fmt: skip
    error_details: Optional[AzureRecommendedActionErrorInfo] = field(default=None, metadata={'description': 'Contains error information for an Azure SQL Database, Server or Elastic Pool Recommended Action.'})  # fmt: skip
    estimated_impact: Optional[List[AzureRecommendedActionImpactRecord]] = field(default=None, metadata={'description': 'Gets the estimated impact info for this recommended action e.g., Estimated CPU gain, Estimated Disk Space change'})  # fmt: skip
    execute_action_duration: Optional[str] = field(default=None, metadata={'description': 'Gets the time taken for applying this recommended action on user resource. e.g., time taken for index creation'})  # fmt: skip
    execute_action_initiated_by: Optional[str] = field(default=None, metadata={'description': 'Gets if approval for applying this recommended action was given by user/system.'})  # fmt: skip
    execute_action_initiated_time: Optional[datetime] = field(default=None, metadata={'description': 'Gets the time when this recommended action was approved for execution.'})  # fmt: skip
    execute_action_start_time: Optional[datetime] = field(default=None, metadata={'description': 'Gets the time when system started applying this recommended action on the user resource. e.g., index creation start time'})  # fmt: skip
    implementation_details: Optional[AzureRecommendedActionImplementationInfo] = field(default=None, metadata={'description': 'Contains information for manual implementation for an Azure SQL Database, Server or Elastic Pool Recommended Action.'})  # fmt: skip
    is_archived_action: Optional[bool] = field(default=None, metadata={'description': 'Gets if this recommended action was suggested some time ago but user chose to ignore this and system added a new recommended action again.'})  # fmt: skip
    is_executable_action: Optional[bool] = field(default=None, metadata={'description': 'Gets if this recommended action is actionable by user'})  # fmt: skip
    is_revertable_action: Optional[bool] = field(default=None, metadata={'description': 'Gets if changes applied by this recommended action can be reverted by user'})  # fmt: skip
    recommended_action_kind: Optional[str] = field(default=None, metadata={"description": "Resource kind."})
    last_refresh: Optional[datetime] = field(default=None, metadata={'description': 'Gets time when this recommended action was last refreshed.'})  # fmt: skip
    linked_objects: Optional[List[str]] = field(default=None, metadata={"description": "Gets the linked objects, if any."})  # fmt: skip
    observed_impact: Optional[List[AzureRecommendedActionImpactRecord]] = field(default=None, metadata={'description': 'Gets the observed/actual impact info for this recommended action e.g., Actual CPU gain, Actual Disk Space change'})  # fmt: skip
    recommendation_reason: Optional[str] = field(default=None, metadata={'description': 'Gets the reason for recommending this action. e.g., DuplicateIndex'})  # fmt: skip
    revert_action_duration: Optional[str] = field(default=None, metadata={'description': 'Gets the time taken for reverting changes of this recommended action on user resource. e.g., time taken for dropping the created index.'})  # fmt: skip
    revert_action_initiated_by: Optional[str] = field(default=None, metadata={'description': 'Gets if approval for reverting this recommended action was given by user/system.'})  # fmt: skip
    revert_action_initiated_time: Optional[datetime] = field(default=None, metadata={'description': 'Gets the time when this recommended action was approved for revert.'})  # fmt: skip
    revert_action_start_time: Optional[datetime] = field(default=None, metadata={'description': 'Gets the time when system started reverting changes of this recommended action on user resource. e.g., time when index drop is executed.'})  # fmt: skip
    score: Optional[int] = field(default=None, metadata={'description': 'Gets the impact of this recommended action. Possible values are 1 - Low impact, 2 - Medium Impact and 3 - High Impact'})  # fmt: skip
    state: Optional[AzureRecommendedActionStateInfo] = field(default=None, metadata={'description': 'Contains information of current state for an Azure SQL Database, Server or Elastic Pool Recommended Action.'})  # fmt: skip
    time_series: Optional[List[AzureRecommendedActionMetricInfo]] = field(default=None, metadata={'description': 'Gets the time series info of metrics for this recommended action e.g., CPU consumption time series'})  # fmt: skip
    valid_since: Optional[datetime] = field(default=None, metadata={'description': 'Gets the time since when this recommended action is valid.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    id: Optional[str] = field(default=None, metadata={"description": "Resource ID."})
    name: Optional[str] = field(default=None, metadata={"description": "Resource name."})


@define(eq=False, slots=False)
class AzureSqlServerAdvisor(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server_advisor"
    _kind_display: ClassVar[str] = "Azure SQL Server Advisor"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server Advisor is a performance optimization tool for SQL databases in Microsoft Azure. It analyzes database usage patterns and provides recommendations to improve query performance, indexing strategies, and overall database efficiency. The advisor identifies potential issues, suggests corrective actions, and offers guidance on implementing its recommendations to enhance database operations."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/database/advisor-overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "profile", "group": "database"}
    # Collect via AzureSqlServer() and AzureSqlServerDatabase()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "advisor_status": S("properties", "advisorStatus"),
        "auto_execute_status": S("properties", "autoExecuteStatus"),
        "auto_execute_status_inherited_from": S("properties", "autoExecuteStatusInheritedFrom"),
        "advisor_kind": S("kind"),
        "last_checked": S("properties", "lastChecked"),
        "recommendations_status": S("properties", "recommendationsStatus"),
        "recommended_actions": S("properties", "recommendedActions") >> ForallBend(AzureRecommendedAction.mapping),
    }
    advisor_status: Optional[str] = field(default=None, metadata={'description': 'Gets the status of availability of this advisor to customers. Possible values are GA , PublicPreview , LimitedPublicPreview and PrivatePreview .'})  # fmt: skip
    auto_execute_status: Optional[str] = field(default=None, metadata={'description': 'Gets the auto-execute status (whether to let the system execute the recommendations) of this advisor. Possible values are Enabled and Disabled '})  # fmt: skip
    auto_execute_status_inherited_from: Optional[str] = field(default=None, metadata={'description': 'Gets the resource from which current value of auto-execute status is inherited. Auto-execute status can be set on (and inherited from) different levels in the resource hierarchy. Possible values are Subscription , Server , ElasticPool , Database and Default (when status is not explicitly set on any level).'})  # fmt: skip
    advisor_kind: Optional[str] = field(default=None, metadata={"description": "Resource kind."})
    last_checked: Optional[datetime] = field(default=None, metadata={'description': 'Gets the time when the current resource was analyzed for recommendations by this advisor.'})  # fmt: skip
    recommendations_status: Optional[str] = field(default=None, metadata={'description': 'Gets that status of recommendations for this advisor and reason for not having any recommendations. Possible values include, but are not limited to, Ok (Recommendations available),LowActivity (not enough workload to analyze), DbSeemsTuned (Database is doing well), etc.'})  # fmt: skip
    recommended_actions: Optional[List[AzureRecommendedAction]] = field(default=None, metadata={'description': 'Gets the recommended actions for this advisor.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})


@define(eq=False, slots=False)
class AzureServerExternalAdministrator:
    kind: ClassVar[str] = "azure_server_external_administrator"
    mapping: ClassVar[Dict[str, Bender]] = {
        "administrator_type": S("administratorType"),
        "azure_ad_only_authentication": S("azureADOnlyAuthentication"),
        "login": S("login"),
        "principal_type": S("principalType"),
        "sid": S("sid"),
        "tenant_id": S("tenantId"),
    }
    administrator_type: Optional[str] = field(default=None, metadata={'description': 'Type of the sever administrator.'})  # fmt: skip
    azure_ad_only_authentication: Optional[bool] = field(default=None, metadata={'description': 'Azure Active Directory only Authentication enabled.'})  # fmt: skip
    login: Optional[str] = field(default=None, metadata={"description": "Login name of the server administrator."})
    principal_type: Optional[str] = field(default=None, metadata={'description': 'Principal Type of the sever administrator.'})  # fmt: skip
    sid: Optional[str] = field(default=None, metadata={"description": "SID (object ID) of the server administrator."})
    tenant_id: Optional[str] = field(default=None, metadata={"description": "Tenant ID of the administrator."})


@define(eq=False, slots=False)
class AzureSqlServerBlobAuditingPolicy:
    kind: ClassVar[str] = "azure_sql_server_blob_auditing_policy"
    # collected via AzureSqlServer
    mapping: ClassVar[Dict[str, Bender]] = {
        "audit_actions_and_groups": S("properties", "auditActionsAndGroups"),
        "is_azure_monitor_target_enabled": S("properties", "isAzureMonitorTargetEnabled"),
        "is_devops_audit_enabled": S("properties", "isDevopsAuditEnabled"),
        "is_managed_identity_in_use": S("properties", "isManagedIdentityInUse"),
        "is_storage_secondary_key_in_use": S("properties", "isStorageSecondaryKeyInUse"),
        "queue_delay_ms": S("properties", "queueDelayMs"),
        "retention_days": S("properties", "retentionDays"),
        "state": S("properties", "state"),
        "storage_account_access_key": S("properties", "storageAccountAccessKey"),
        "storage_account_subscription_id": S("properties", "storageAccountSubscriptionId"),
        "storage_endpoint": S("properties", "storageEndpoint"),
    }
    audit_actions_and_groups: Optional[List[str]] = field(default=None, metadata={'description': 'Specifies the Actions-Groups and Actions to audit. The recommended set of action groups to use is the following combination - this will audit all the queries and stored procedures executed against the database, as well as successful and failed logins: BATCH_COMPLETED_GROUP, SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP, FAILED_DATABASE_AUTHENTICATION_GROUP. This above combination is also the set that is configured by default when enabling auditing from the Azure portal. The supported action groups to audit are (note: choose only specific groups that cover your auditing needs. Using unnecessary groups could lead to very large quantities of audit records): APPLICATION_ROLE_CHANGE_PASSWORD_GROUP BACKUP_RESTORE_GROUP DATABASE_LOGOUT_GROUP DATABASE_OBJECT_CHANGE_GROUP DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP DATABASE_OBJECT_PERMISSION_CHANGE_GROUP DATABASE_OPERATION_GROUP DATABASE_PERMISSION_CHANGE_GROUP DATABASE_PRINCIPAL_CHANGE_GROUP DATABASE_PRINCIPAL_IMPERSONATION_GROUP DATABASE_ROLE_MEMBER_CHANGE_GROUP FAILED_DATABASE_AUTHENTICATION_GROUP SCHEMA_OBJECT_ACCESS_GROUP SCHEMA_OBJECT_CHANGE_GROUP SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP USER_CHANGE_PASSWORD_GROUP BATCH_STARTED_GROUP BATCH_COMPLETED_GROUP DBCC_GROUP DATABASE_OWNERSHIP_CHANGE_GROUP DATABASE_CHANGE_GROUP LEDGER_OPERATION_GROUP These are groups that cover all sql statements and stored procedures executed against the database, and should not be used in combination with other groups as this will result in duplicate audit logs. For more information, see [Database-Level Audit Action Groups](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions#database-level-audit-action-groups). For Database auditing policy, specific Actions can also be specified (note that Actions cannot be specified for Server auditing policy). The supported actions to audit are: SELECT UPDATE INSERT DELETE EXECUTE RECEIVE REFERENCES The general form for defining an action to be audited is: {action} ON {object} BY {principal} Note that <object> in the above format can refer to an object like a table, view, or stored procedure, or an entire database or schema. For the latter cases, the forms DATABASE::{db_name} and SCHEMA::{schema_name} are used, respectively. For example: SELECT on dbo.myTable by public SELECT on DATABASE::myDatabase by public SELECT on SCHEMA::mySchema by public For more information, see [Database-Level Audit Actions](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions#database-level-audit-actions)'})  # fmt: skip
    is_azure_monitor_target_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether audit events are sent to Azure Monitor. In order to send the events to Azure Monitor, specify State as Enabled and IsAzureMonitorTargetEnabled as true. When using REST API to configure auditing, Diagnostic Settings with SQLSecurityAuditEvents diagnostic logs category on the database should be also created. Note that for server level audit you should use the master database as {databaseName}. Diagnostic Settings URI format: PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/providers/microsoft.insights/diagnosticSettings/{settingsName}?api-version=2017-05-01-preview For more information, see [Diagnostic Settings REST API](https://go.microsoft.com/fwlink/?linkid=2033207) or [Diagnostic Settings PowerShell](https://go.microsoft.com/fwlink/?linkid=2033043).'})  # fmt: skip
    is_devops_audit_enabled: Optional[bool] = field(default=None, metadata={'description': 'Specifies the state of devops audit. If state is Enabled, devops logs will be sent to Azure Monitor. In order to send the events to Azure Monitor, specify State as Enabled , IsAzureMonitorTargetEnabled as true and IsDevopsAuditEnabled as true When using REST API to configure auditing, Diagnostic Settings with DevOpsOperationsAudit diagnostic logs category on the master database should also be created. Diagnostic Settings URI format: PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Sql/servers/{serverName}/databases/master/providers/microsoft.insights/diagnosticSettings/{settingsName}?api-version=2017-05-01-preview For more information, see [Diagnostic Settings REST API](https://go.microsoft.com/fwlink/?linkid=2033207) or [Diagnostic Settings PowerShell](https://go.microsoft.com/fwlink/?linkid=2033043).'})  # fmt: skip
    is_managed_identity_in_use: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether Managed Identity is used to access blob storage'})  # fmt: skip
    is_storage_secondary_key_in_use: Optional[bool] = field(default=None, metadata={'description': 'Specifies whether storageAccountAccessKey value is the storage s secondary key.'})  # fmt: skip
    queue_delay_ms: Optional[int] = field(default=None, metadata={'description': 'Specifies the amount of time in milliseconds that can elapse before audit actions are forced to be processed. The default minimum value is 1000 (1 second). The maximum is 2,147,483,647.'})  # fmt: skip
    retention_days: Optional[int] = field(default=None, metadata={'description': 'Specifies the number of days to keep in the audit logs in the storage account.'})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={'description': 'Specifies the state of the audit. If state is Enabled, storageEndpoint or isAzureMonitorTargetEnabled are required.'})  # fmt: skip
    storage_account_access_key: Optional[str] = field(default=None, metadata={'description': 'Specifies the identifier key of the auditing storage account. If state is Enabled and storageEndpoint is specified, not specifying the storageAccountAccessKey will use SQL server system-assigned managed identity to access the storage. Prerequisites for using managed identity authentication: 1. Assign SQL Server a system-assigned managed identity in Azure Active Directory (AAD). 2. Grant SQL Server identity access to the storage account by adding Storage Blob Data Contributor RBAC role to the server identity. For more information, see [Auditing to storage using Managed Identity authentication](https://go.microsoft.com/fwlink/?linkid=2114355)'})  # fmt: skip
    storage_account_subscription_id: Optional[str] = field(default=None, metadata={'description': 'Specifies the blob storage subscription Id.'})  # fmt: skip
    storage_endpoint: Optional[str] = field(default=None, metadata={'description': 'Specifies the blob storage endpoint (e.g. https://MyAccount.blob.core.windows.net). If state is Enabled, storageEndpoint or isAzureMonitorTargetEnabled is required.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSqlEncryptionProtector:
    kind: ClassVar[str] = "azure_sql_encryption_protector"
    # version="2021-11-01",
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_rotation_enabled": S("properties", "autoRotationEnabled"),
        "protector_kind": S("kind"),
        "server_key_name": S("properties", "serverKeyName"),
        "server_key_type": S("properties", "serverKeyType"),
        "subregion": S("properties", "subregion"),
        "thumbprint": S("properties", "thumbprint"),
        "uri": S("properties", "uri"),
    }
    auto_rotation_enabled: Optional[bool] = field(default=None, metadata={'description': 'Key auto rotation opt-in flag. Either true or false.'})  # fmt: skip
    protector_kind: Optional[str] = field(default=None, metadata={'description': 'Kind of encryption protector. This is metadata used for the Azure portal experience.'})  # fmt: skip
    server_key_name: Optional[str] = field(default=None, metadata={"description": "The name of the server key."})
    server_key_type: Optional[str] = field(default=None, metadata={'description': 'The encryption protector type like ServiceManaged , AzureKeyVault .'})  # fmt: skip
    subregion: Optional[str] = field(default=None, metadata={"description": "Subregion of the encryption protector."})
    thumbprint: Optional[str] = field(default=None, metadata={"description": "Thumbprint of the server key."})
    uri: Optional[str] = field(default=None, metadata={"description": "The URI of the server key."})


@define(eq=False, slots=False)
class AzureSqlServer(MicrosoftResource):
    kind: ClassVar[str] = "azure_sql_server"
    _kind_display: ClassVar[str] = "Azure SQL Server"
    _kind_service: ClassVar[Optional[str]] = service_name
    _kind_description: ClassVar[str] = "Azure SQL Server is a cloud-based relational database service provided by Microsoft. It offers SQL Server functionality in a managed environment, including automatic updates, backups, and performance optimization. Users can create, scale, and maintain databases without managing infrastructure, while benefiting from built-in security features and integration with other Azure services."  # fmt: skip
    _docs_url: ClassVar[str] = "https://learn.microsoft.com/en-us/azure/azure-sql/database/"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "database", "group": "database"}
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="sql",
        version="2021-11-01",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_sql_server_database",
                "azure_sql_server_elastic_pool",
                "azure_sql_server_failover_group",
                "azure_sql_server_firewall_rule",
                "azure_sql_server_job_agent",
                "azure_sql_server_virtual_network_rule",
                "azure_sql_server_advisor",
                "microsoft_graph_service_principal",
                "microsoft_graph_user",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "type": S("type"),
        "location": S("location"),
        "administrator_login": S("properties", "administratorLogin"),
        "administrator_login_password": S("properties", "administratorLoginPassword"),
        "server_administrators": S("properties", "administrators") >> Bend(AzureServerExternalAdministrator.mapping),
        "federated_client_id": S("properties", "federatedClientId"),
        "fully_qualified_domain_name": S("properties", "fullyQualifiedDomainName"),
        "server_identity": S("identity") >> Bend(AzureResourceIdentity.mapping),
        "key_id": S("properties", "keyId"),
        "server_kind": S("kind"),
        "minimal_tls_version": S("properties", "minimalTlsVersion"),
        "primary_user_assigned_identity_id": S("properties", "primaryUserAssignedIdentityId"),
        "server_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzurePrivateEndpointConnection.mapping),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "restrict_outbound_network_access": S("properties", "restrictOutboundNetworkAccess"),
        "state": S("properties", "state"),
        "version": S("properties", "version"),
        "workspace_feature": S("properties", "workspaceFeature"),
    }
    administrator_login: Optional[str] = field(default=None, metadata={'description': 'Administrator username for the server. Once created it cannot be changed.'})  # fmt: skip
    administrator_login_password: Optional[str] = field(default=None, metadata={'description': 'The administrator login password (required for server creation).'})  # fmt: skip
    server_administrators: Optional[AzureServerExternalAdministrator] = field(default=None, metadata={'description': 'Properties of a active directory administrator.'})  # fmt: skip
    federated_client_id: Optional[str] = field(default=None, metadata={'description': 'The Client id used for cross tenant CMK scenario'})  # fmt: skip
    fully_qualified_domain_name: Optional[str] = field(default=None, metadata={'description': 'The fully qualified domain name of the server.'})  # fmt: skip
    server_identity: Optional[AzureResourceIdentity] = field(default=None, metadata={'description': 'Azure Active Directory identity configuration for a resource.'})  # fmt: skip
    key_id: Optional[str] = field(default=None, metadata={'description': 'A CMK URI of the key to use for encryption.'})  # fmt: skip
    server_kind: Optional[str] = field(default=None, metadata={'description': 'Kind of sql server. This is metadata used for the Azure portal experience.'})  # fmt: skip
    minimal_tls_version: Optional[str] = field(default=None, metadata={'description': 'Minimal TLS version. Allowed values: 1.0 , 1.1 , 1.2 '})  # fmt: skip
    primary_user_assigned_identity_id: Optional[str] = field(default=None, metadata={'description': 'The resource id of a user assigned identity to be used by default.'})  # fmt: skip
    server_private_endpoint_connections: Optional[List[AzurePrivateEndpointConnection]] = field(default=None, metadata={'description': 'List of private endpoint connections on a server'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Whether or not public endpoint access is allowed for this server. Value is optional but if passed in, must be Enabled or Disabled '})  # fmt: skip
    restrict_outbound_network_access: Optional[str] = field(default=None, metadata={'description': 'Whether or not to restrict outbound network access for this server. Value is optional but if passed in, must be Enabled or Disabled '})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The state of the server."})
    version: Optional[str] = field(default=None, metadata={"description": "The version of the server."})
    workspace_feature: Optional[str] = field(default=None, metadata={'description': 'Whether or not existing server has a workspace created and if it allows connection from workspace'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Resource type."})
    location: Optional[str] = field(default=None, metadata={"description": "Resource location."})
    blob_auditing_policy: Optional[AzureSqlServerBlobAuditingPolicy] = field(default=None, metadata={'description': 'The blob auditing policy for the server.'})  # fmt: skip
    encryption_protector: Optional[AzureSqlEncryptionProtector] = field(default=None, metadata={'description': 'The encryption protector for the server.'})  # fmt: skip

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        server_id: str,
        resource_type: str,
        version: str,
        class_instance: MicrosoftResource,
    ) -> None:
        path = f"{server_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="sql",
            version=version,
            path=path,
            path_parameters=[],
            query_parameters=["api-version"],
            access_path="value",
            expect_array=True,
        )
        items = graph_builder.client.list(api_spec)
        for resource in class_instance.collect(items, graph_builder):
            # In case if we collect DB, then set properties
            if isinstance(resource, AzureSqlServerDatabase):
                if self.public_network_access == "Enabled":
                    resource.db_publicly_accessible = True
                else:
                    resource.db_publicly_accessible = False
                resource.db_version = self.version
                resource.db_endpoint = self.fully_qualified_domain_name
            graph_builder.add_edge(self, node=resource)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:

        def fetch_nested_prop(sid: str, cls: Type[Any], path_part: str, version: str, prop: str) -> None:
            api_spec = AzureResourceSpec(
                service="sql",
                version=version,
                path=f"{sid}/{path_part}",
                query_parameters=["api-version"],
                access_path="value",
                expect_array=True,
            )
            # albeit this is a list API, it will only return one element
            if items := graph_builder.client.list(api_spec):
                for item in items:
                    setattr(self, prop, parse_json(item, cls, graph_builder, cls.mapping))

        if server_id := self.id:
            resources_to_collect = [
                ("databases", AzureSqlServerDatabase, "2021-11-01"),
                ("elasticPools", AzureSqlServerElasticPool, "2021-11-01"),
                ("failoverGroups", AzureSqlServerFailoverGroup, "2021-11-01"),
                ("firewallRules", AzureSqlServerFirewallRule, "2021-11-01"),
                ("jobAgents", AzureSqlServerJobAgent, "2021-11-01"),
                ("virtualNetworkRules", AzureSqlServerVirtualNetworkRule, "2021-11-01"),
                ("advisors?$expand=recommendedActions", AzureSqlServerAdvisor, "2021-11-01"),
                ("administrators", AzureSqlServerADAdministrator, "2021-11-01"),
            ]
            for resource_type, resource_class, resource_version in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    server_id,
                    resource_type,
                    resource_version,
                    resource_class,
                )

            props_to_set = [
                (AzureSqlServerBlobAuditingPolicy, "auditingSettings", "2022-05-01-preview", "blob_auditing_policy"),
                (AzureSqlEncryptionProtector, "encryptionProtector", "2021-11-01", "encryption_protector"),
            ]
            for args in props_to_set:
                graph_builder.submit_work(service_name, fetch_nested_prop, server_id, *args)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # principal: collected via ms graph -> create a deferred edge
        if si := self.server_identity:
            if pid := si.principal_id:
                builder.add_deferred_edge(
                    from_node=self,
                    to_node=BySearchCriteria(f'is({MicrosoftGraphServicePrincipal.kind}) and reported.id=="{pid}"'),
                )
            if uai := si.user_assigned_identities:
                for _, identity_info in uai.items():
                    if identity_info and identity_info.principal_id:
                        builder.add_deferred_edge(
                            from_node=self,
                            to_node=BySearchCriteria(
                                f'is({MicrosoftGraphUser.kind}) and reported.id=="{identity_info.principal_id}"'
                            ),
                        )


resources: List[Type[MicrosoftResource]] = [
    AzureSqlServerADAdministrator,
    AzureSqlServerDatabase,
    AzureSqlServerElasticPool,
    AzureSqlServerFailoverGroup,
    AzureSqlServerFirewallRule,
    AzureSqlServerDatabaseGeoBackupPolicy,
    AzureSqlServerManagedInstanceFailoverGroup,
    AzureSqlServerManagedInstancePool,
    AzureSqlServerJobAgent,
    AzureSqlServerManagedInstanceADAdministrator,
    AzureSqlServerManagedInstanceDatabase,
    AzureSqlServerManagedInstance,
    AzureSqlServer,
    AzureSqlServerVirtualCluster,
    AzureSqlServerTrustGroup,
    AzureSqlServerVirtualNetworkRule,
    AzureSqlServerDatabaseWorkloadGroup,
    AzureSqlServerAdvisor,
]
