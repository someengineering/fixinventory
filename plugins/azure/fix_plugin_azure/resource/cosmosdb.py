from __future__ import annotations

from datetime import datetime
import logging
from typing import ClassVar, Dict, Optional, List, Type

from attr import define, field

from fix_plugin_azure.azure_client import AzureResourceSpec
from fix_plugin_azure.resource.base import (
    AzureBaseUsage,
    AzureProxyResource,
    AzureResourceIdentity,
    AzureSystemData,
    AzureTrackedResource,
    GraphBuilder,
    MicrosoftResource,
)
from fixlib.baseresources import ModelReference
from fixlib.json_bender import K, Bender, S, ForallBend, Bend
from fixlib.types import Json

service_name = "azure_cosmosdb"
log = logging.getLogger("fix.plugins.azure")


@define(eq=False, slots=False)
class AzureManagedCassandraReaperStatus:
    kind: ClassVar[str] = "azure_managed_cassandra_reaper_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "healthy": S("healthy"),
        "repair_run_ids": S("repairRunIds"),
        "repair_schedules": S("repairSchedules"),
    }
    healthy: Optional[bool] = field(default=None, metadata={"description": ""})
    repair_run_ids: Optional[Dict[str, str]] = field(default=None, metadata={"description": ""})
    repair_schedules: Optional[Dict[str, str]] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureThroughputPolicyResource:
    kind: ClassVar[str] = "azure_throughput_policy_resource"
    mapping: ClassVar[Dict[str, Bender]] = {"increment_percent": S("incrementPercent"), "is_enabled": S("isEnabled")}
    increment_percent: Optional[int] = field(default=None, metadata={'description': 'Represents the percentage by which throughput can increase every time throughput policy kicks in.'})  # fmt: skip
    is_enabled: Optional[bool] = field(default=None, metadata={'description': 'Determines whether the ThroughputPolicy is active or not'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAutoUpgradePolicyResource:
    kind: ClassVar[str] = "azure_auto_upgrade_policy_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "throughput_policy": S("throughputPolicy") >> Bend(AzureThroughputPolicyResource.mapping)
    }
    throughput_policy: Optional[AzureThroughputPolicyResource] = field(default=None, metadata={'description': 'Cosmos DB resource throughput policy'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAutoscaleSettingsResource:
    kind: ClassVar[str] = "azure_autoscale_settings_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_upgrade_policy": S("autoUpgradePolicy") >> Bend(AzureAutoUpgradePolicyResource.mapping),
        "max_throughput": S("maxThroughput"),
        "target_max_throughput": S("targetMaxThroughput"),
    }
    auto_upgrade_policy: Optional[AzureAutoUpgradePolicyResource] = field(default=None, metadata={'description': 'Cosmos DB resource auto-upgrade policy'})  # fmt: skip
    max_throughput: Optional[int] = field(default=None, metadata={'description': 'Represents maximum throughput container can scale up to.'})  # fmt: skip
    target_max_throughput: Optional[int] = field(default=None, metadata={'description': 'Represents target maximum throughput container can scale up to once offer is no longer in pending state.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureThroughputSettingsResource:
    kind: ClassVar[str] = "azure_throughput_settings_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoscale_settings": S("autoscaleSettings") >> Bend(AzureAutoscaleSettingsResource.mapping),
        "instant_maximum_throughput": S("instantMaximumThroughput"),
        "minimum_throughput": S("minimumThroughput"),
        "offer_replace_pending": S("offerReplacePending"),
        "soft_allowed_maximum_throughput": S("softAllowedMaximumThroughput"),
        "throughput": S("throughput"),
    }
    autoscale_settings: Optional[AzureAutoscaleSettingsResource] = field(default=None, metadata={'description': 'Cosmos DB provisioned throughput settings object'})  # fmt: skip
    instant_maximum_throughput: Optional[str] = field(default=None, metadata={'description': 'The offer throughput value to instantly scale up without triggering splits'})  # fmt: skip
    minimum_throughput: Optional[str] = field(default=None, metadata={'description': 'The minimum throughput of the resource'})  # fmt: skip
    offer_replace_pending: Optional[str] = field(default=None, metadata={'description': 'The throughput replace is pending'})  # fmt: skip
    soft_allowed_maximum_throughput: Optional[str] = field(default=None, metadata={'description': 'The maximum throughput value or the maximum maxThroughput value (for autoscale) that can be specified'})  # fmt: skip
    throughput: Optional[int] = field(default=None, metadata={'description': 'Value of the Cosmos DB resource throughput. Either throughput is required or autoscaleSettings is required, but not both.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureConnectionError:
    kind: ClassVar[str] = "azure_connection_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "connection_state": S("connectionState"),
        "exception": S("exception"),
        "i_p_from": S("iPFrom"),
        "i_p_to": S("iPTo"),
        "port": S("port"),
    }
    connection_state: Optional[str] = field(default=None, metadata={'description': 'The kind of connection error that occurred.'})  # fmt: skip
    exception: Optional[str] = field(default=None, metadata={'description': 'Detailed error message about the failed connection.'})  # fmt: skip
    i_p_from: Optional[str] = field(default=None, metadata={'description': 'The IP of host that originated the failed connection.'})  # fmt: skip
    i_p_to: Optional[str] = field(default=None, metadata={'description': 'The IP that the connection attempted to reach.'})  # fmt: skip
    port: Optional[int] = field(default=None, metadata={'description': 'The TCP port the connection was attempted on.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCassandraError:
    kind: ClassVar[str] = "azure_cassandra_error"
    mapping: ClassVar[Dict[str, Bender]] = {
        "additional_error_info": S("additionalErrorInfo"),
        "code": S("code"),
        "message": S("message"),
        "target": S("target"),
    }
    additional_error_info: Optional[str] = field(default=None, metadata={'description': 'Additional information about the error.'})  # fmt: skip
    code: Optional[str] = field(default=None, metadata={"description": "The code of error that occurred."})
    message: Optional[str] = field(default=None, metadata={"description": "The message of the error."})
    target: Optional[str] = field(default=None, metadata={"description": "The target resource of the error."})


@define(eq=False, slots=False)
class AzureAddressStateStatusCassandraprocessstatusLoadTokensSizeHostidRackTimestampDiskusedkbDiskfreekbMemoryusedkbMemorybuffersandcachedkbMemoryfreekbMemorytotalkbCpuusage:
    kind: ClassVar[str] = (
        "azure_address_state_status_cassandraprocessstatus_load_tokens_size_hostid_rack_timestamp_diskusedkb_diskfreekb_memoryusedkb_memorybuffersandcachedkb_memoryfreekb_memorytotalkb_cpuusage"
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "address": S("address"),
        "cassandra_process_status": S("cassandraProcessStatus"),
        "cpu_usage": S("cpuUsage"),
        "disk_free_kb": S("diskFreeKB"),
        "disk_used_kb": S("diskUsedKB"),
        "host_id": S("hostID"),
        "load": S("load"),
        "memory_buffers_and_cached_kb": S("memoryBuffersAndCachedKB"),
        "memory_free_kb": S("memoryFreeKB"),
        "memory_total_kb": S("memoryTotalKB"),
        "memory_used_kb": S("memoryUsedKB"),
        "rack": S("rack"),
        "size": S("size"),
        "state": S("state"),
        "status": S("status"),
        "timestamp": S("timestamp"),
        "tokens": S("tokens"),
    }
    address: Optional[str] = field(default=None, metadata={"description": "The node s IP address."})
    cassandra_process_status: Optional[str] = field(default=None, metadata={'description': 'Cassandra service status on this node'})  # fmt: skip
    cpu_usage: Optional[float] = field(default=None, metadata={'description': 'A float representing the current system-wide CPU utilization as a percentage.'})  # fmt: skip
    disk_free_kb: Optional[int] = field(default=None, metadata={'description': 'The amount of disk free, in kB, of the directory /var/lib/cassandra.'})  # fmt: skip
    disk_used_kb: Optional[int] = field(default=None, metadata={'description': 'The amount of disk used, in kB, of the directory /var/lib/cassandra.'})  # fmt: skip
    host_id: Optional[str] = field(default=None, metadata={"description": "The network ID of the node."})
    load: Optional[str] = field(default=None, metadata={'description': 'The amount of file system data in the data directory (e.g., 47.66 kB), excluding all content in the snapshots subdirectories. Because all SSTable data files are included, any data that is not cleaned up (such as TTL-expired cells or tombstones) is counted.'})  # fmt: skip
    memory_buffers_and_cached_kb: Optional[int] = field(default=None, metadata={'description': 'Memory used by kernel buffers (Buffers in /proc/meminfo) and page cache and slabs (Cached and SReclaimable in /proc/meminfo), in kB.'})  # fmt: skip
    memory_free_kb: Optional[int] = field(default=None, metadata={'description': 'Unused memory (MemFree and SwapFree in /proc/meminfo), in kB.'})  # fmt: skip
    memory_total_kb: Optional[int] = field(default=None, metadata={'description': 'Total installed memory (MemTotal and SwapTotal in /proc/meminfo), in kB.'})  # fmt: skip
    memory_used_kb: Optional[int] = field(default=None, metadata={'description': 'Used memory (calculated as total - free - buffers - cache), in kB.'})  # fmt: skip
    rack: Optional[str] = field(default=None, metadata={"description": "The rack this node is part of."})
    size: Optional[int] = field(default=None, metadata={"description": ""})
    state: Optional[str] = field(default=None, metadata={"description": "The state of the node in Cassandra ring."})
    status: Optional[str] = field(default=None, metadata={"description": ""})
    timestamp: Optional[str] = field(default=None, metadata={'description': 'The timestamp when these statistics were captured.'})  # fmt: skip
    tokens: Optional[List[str]] = field(default=None, metadata={"description": "List of tokens this node covers."})


@define(eq=False, slots=False)
class AzureNameSeednodesNodes:
    kind: ClassVar[str] = "azure_name_seednodes_nodes"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "nodes": S("nodes")
        >> ForallBend(
            AzureAddressStateStatusCassandraprocessstatusLoadTokensSizeHostidRackTimestampDiskusedkbDiskfreekbMemoryusedkbMemorybuffersandcachedkbMemoryfreekbMemorytotalkbCpuusage.mapping
        ),
        "seed_nodes": S("seedNodes"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of this Datacenter."})
    nodes: Optional[List[AzureAddressStateStatusCassandraprocessstatusLoadTokensSizeHostidRackTimestampDiskusedkbDiskfreekbMemoryusedkbMemorybuffersandcachedkbMemoryfreekbMemorytotalkbCpuusage]] = field(default=None, metadata={'description': ''})  # fmt: skip
    seed_nodes: Optional[List[str]] = field(default=None, metadata={'description': 'A list of all seed nodes in the cluster, managed and unmanaged.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBCassandraClusterPublicStatus(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_cassandra_cluster_public_status"
    # Collect via AzureCosmosDBCassandraCluster()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "connection_errors": S("connectionErrors") >> ForallBend(AzureConnectionError.mapping),
        "data_centers": S("dataCenters") >> ForallBend(AzureNameSeednodesNodes.mapping),
        "e_tag": S("eTag"),
        "status_errors": S("errors") >> ForallBend(AzureCassandraError.mapping),
        "reaper_status": S("reaperStatus") >> Bend(AzureManagedCassandraReaperStatus.mapping),
    }
    connection_errors: Optional[List[AzureConnectionError]] = field(default=None, metadata={'description': 'List relevant information about any connection errors to the Datacenters.'})  # fmt: skip
    data_centers: Optional[List[AzureNameSeednodesNodes]] = field(default=None, metadata={'description': 'List of the status of each datacenter in this cluster.'})  # fmt: skip
    status_errors: Optional[List[AzureCassandraError]] = field(default=None, metadata={'description': 'List relevant information about any errors about cluster, data center and connection error.'})  # fmt: skip
    reaper_status: Optional[AzureManagedCassandraReaperStatus] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureARMResourceProperties:
    kind: ClassVar[str] = "azure_arm_resource_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "location": S("location"),
        "type": S("type"),
    }
    location: Optional[str] = field(default=None, metadata={'description': 'The location of the resource group to which the resource belongs.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of Azure resource."})


@define(eq=False, slots=False)
class AzureExtendedResourceProperties:
    kind: ClassVar[str] = "azure_extended_resource_properties"
    mapping: ClassVar[Dict[str, Bender]] = {"etag": S("_etag"), "_rid": S("rid"), "_ts": S("ts")}
    etag: Optional[str] = field(default=None, metadata={'description': 'A system generated property representing the resource etag required for optimistic concurrency control.'})  # fmt: skip
    rid: Optional[str] = field(default=None, metadata={'description': 'A system generated property. A unique identifier.'})  # fmt: skip
    ts: Optional[float] = field(default=None, metadata={'description': 'A system generated property that denotes the last updated timestamp of the resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBResource(AzureThroughputSettingsResource, AzureExtendedResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_resource"
    mapping: ClassVar[Dict[str, Bender]] = (
        AzureThroughputSettingsResource.mapping | AzureExtendedResourceProperties.mapping | {}
    )


@define(eq=False, slots=False)
class AzureOptionsResource:
    kind: ClassVar[str] = "azure_options_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoscale_settings": S("autoscaleSettings", "maxThroughput"),
        "throughput": S("throughput"),
    }
    autoscale_settings: Optional[int] = field(default=None, metadata={"description": ""})
    throughput: Optional[int] = field(default=None, metadata={'description': 'Value of the Cosmos DB resource throughput or autoscaleSettings. Use the ThroughputSetting resource when retrieving offer details.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCassandraKeyspaceResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_cassandra_keyspace_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {"id": S("id")}
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB Cassandra keyspace"})


@define(eq=False, slots=False)
class AzureCosmosDBCassandraKeyspace(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_cassandra_keyspace"
    # Collect via AzureCosmosDBAccount()
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_cosmos_db_cassandra_table",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "cassandra_keyspace_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "cassandra_keyspace_resource": S("properties", "resource") >> Bend(AzureCassandraKeyspaceResource.mapping),
    }
    cassandra_keyspace_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    cassandra_keyspace_resource: Optional[AzureCassandraKeyspaceResource] = field(
        default=None, metadata={"description": ""}
    )

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        account_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{account_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="cosmos-db",
            version="2024-05-15",
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
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if account_id := self.id:
            resources_to_collect = [
                ("tables", AzureCosmosDBCassandraTable, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    account_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )


@define(eq=False, slots=False)
class AzureColumn:
    kind: ClassVar[str] = "azure_column"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "type": S("type")}
    name: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB Cassandra table column"})
    type: Optional[str] = field(default=None, metadata={"description": "Type of the Cosmos DB Cassandra table column"})


@define(eq=False, slots=False)
class AzureClusterKey:
    kind: ClassVar[str] = "azure_cluster_key"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "order_by": S("orderBy")}
    name: Optional[str] = field(default=None, metadata={'description': 'Name of the Cosmos DB Cassandra table cluster key'})  # fmt: skip
    order_by: Optional[str] = field(default=None, metadata={'description': 'Order of the Cosmos DB Cassandra table cluster key, only support Asc and Desc '})  # fmt: skip


@define(eq=False, slots=False)
class AzureCassandraSchema:
    kind: ClassVar[str] = "azure_cassandra_schema"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_keys": S("clusterKeys") >> ForallBend(AzureClusterKey.mapping),
        "columns": S("columns") >> ForallBend(AzureColumn.mapping),
        "partition_keys": S("partitionKeys", default=[]) >> ForallBend(S("name")),
    }
    cluster_keys: Optional[List[AzureClusterKey]] = field(
        default=None, metadata={"description": "List of cluster key."}
    )
    columns: Optional[List[AzureColumn]] = field(
        default=None, metadata={"description": "List of Cassandra table columns."}
    )
    partition_keys: Optional[List[str]] = field(default=None, metadata={"description": "List of partition key."})


@define(eq=False, slots=False)
class AzureCassandraTableResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_cassandra_table_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {
        "analytical_storage_ttl": S("analyticalStorageTtl"),
        "default_ttl": S("defaultTtl"),
        "id": S("id"),
        "schema": S("schema") >> Bend(AzureCassandraSchema.mapping),
    }
    analytical_storage_ttl: Optional[int] = field(default=None, metadata={"description": "Analytical TTL."})
    default_ttl: Optional[int] = field(default=None, metadata={'description': 'Time to live of the Cosmos DB Cassandra table'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB Cassandra table"})
    schema: Optional[AzureCassandraSchema] = field(default=None, metadata={'description': 'Cosmos DB Cassandra table schema'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBCassandraTable(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_cassandra_table"
    # Collect via AzureCosmosDBCassandraKeyspace()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "cassandra_table_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "cassandra_table_resource": S("properties", "resource") >> Bend(AzureCassandraTableResource.mapping),
    }
    cassandra_table_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    cassandra_table_resource: Optional[AzureCassandraTableResource] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureARMProxyResource:
    kind: ClassVar[str] = "azure_arm_proxy_resource"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "name": S("name"), "type": S("type")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the database account."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of Azure resource."})


@define(eq=False, slots=False)
class AzureKeyWrapMetadata:
    kind: ClassVar[str] = "azure_key_wrap_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "algorithm": S("algorithm"),
        "name": S("name"),
        "type": S("type"),
        "value": S("value"),
    }
    algorithm: Optional[str] = field(default=None, metadata={'description': 'Algorithm used in wrapping and unwrapping of the data encryption key.'})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={'description': 'The name of associated KeyEncryptionKey (aka CustomerManagedKey).'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "ProviderName of KeyStoreProvider."})
    value: Optional[str] = field(default=None, metadata={"description": "Reference / link to the KeyEncryptionKey."})


@define(eq=False, slots=False)
class AzureClientEncryptionKeyResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_client_encryption_key_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {
        "encryption_algorithm": S("encryptionAlgorithm"),
        "id": S("id"),
        "key_wrap_metadata": S("keyWrapMetadata") >> Bend(AzureKeyWrapMetadata.mapping),
        "wrapped_data_encryption_key": S("wrappedDataEncryptionKey"),
    }
    encryption_algorithm: Optional[str] = field(default=None, metadata={'description': 'Encryption algorithm that will be used along with this client encryption key to encrypt/decrypt data.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Name of the ClientEncryptionKey"})
    key_wrap_metadata: Optional[AzureKeyWrapMetadata] = field(default=None, metadata={'description': 'Represents key wrap metadata that a key wrapping provider can use to wrap/unwrap a client encryption key.'})  # fmt: skip
    wrapped_data_encryption_key: Optional[str] = field(default=None, metadata={'description': 'Wrapped (encrypted) form of the key represented as a byte array.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBSqlDatabaseClientEncryptionKey(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_sql_database_client_encryption_key"
    # Collect via AzureCosmosDBSqlDatabase()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "encryption_key_resource": S("properties", "resource") >> Bend(AzureClientEncryptionKeyResource.mapping),
    }
    encryption_key_resource: Optional[AzureClientEncryptionKeyResource] = field(
        default=None, metadata={"description": ""}
    )


@define(eq=False, slots=False)
class AzureManagedCassandraManagedServiceIdentity:
    kind: ClassVar[str] = "azure_managed_cassandra_managed_service_identity"
    mapping: ClassVar[Dict[str, Bender]] = {
        "principal_id": S("principalId"),
        "tenant_id": S("tenantId"),
        "type": S("type"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The object id of the identity resource.'})  # fmt: skip
    tenant_id: Optional[str] = field(default=None, metadata={"description": "The tenant id of the resource."})
    type: Optional[str] = field(default=None, metadata={"description": "The type of the resource."})


@define(eq=False, slots=False)
class AzureManagedCassandraARMResourceProperties:
    kind: ClassVar[str] = "azure_managed_cassandra_arm_resource_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "identity": S("identity") >> Bend(AzureManagedCassandraManagedServiceIdentity.mapping),
        "location": S("location"),
        "type": S("type"),
    }
    identity: Optional[AzureManagedCassandraManagedServiceIdentity] = field(default=None, metadata={'description': 'Identity for the resource.'})  # fmt: skip
    location: Optional[str] = field(default=None, metadata={'description': 'The location of the resource group to which the resource belongs.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of Azure resource."})


@define(eq=False, slots=False)
class AzureCosmosDBCassandraCluster(MicrosoftResource, AzureManagedCassandraARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_cassandra_cluster"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="cosmos-db",
        version="2024-05-15",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/cassandraClusters",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_cosmos_db_cassandra_cluster_public_status",
                "azure_cosmos_db_cassandra_cluster_data_center",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureManagedCassandraARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "authentication_method": S("properties", "authenticationMethod"),
        "azure_connection_method": S("properties", "azureConnectionMethod"),
        "cassandra_audit_logging_enabled": S("properties", "cassandraAuditLoggingEnabled"),
        "cassandra_version": S("properties", "cassandraVersion"),
        "client_certificates": S("properties") >> S("clientCertificates", default=[]) >> ForallBend(S("pem")),
        "cluster_name_override": S("properties", "clusterNameOverride"),
        "cluster_deallocated": S("properties", "deallocated"),
        "delegated_management_subnet_id": S("properties", "delegatedManagementSubnetId"),
        "external_gossip_certificates": S("properties")
        >> S("externalGossipCertificates", default=[])
        >> ForallBend(S("pem")),
        "external_seed_nodes": S("properties") >> S("externalSeedNodes", default=[]) >> ForallBend(S("ipAddress")),
        "gossip_certificates": S("properties") >> S("gossipCertificates", default=[]) >> ForallBend(S("pem")),
        "hours_between_backups": S("properties", "hoursBetweenBackups"),
        "initial_cassandra_admin_password": S("properties", "initialCassandraAdminPassword"),
        "private_link_resource_id": S("properties", "privateLinkResourceId"),
        "prometheus_endpoint": S("properties", "prometheusEndpoint", "ipAddress"),
        "provision_error": S("properties", "provisionError") >> Bend(AzureCassandraError.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "repair_enabled": S("properties", "repairEnabled"),
        "restore_from_backup_id": S("properties", "restoreFromBackupId"),
        "seed_nodes": S("properties") >> S("seedNodes", default=[]) >> ForallBend(S("ipAddress")),
    }
    authentication_method: Optional[str] = field(default=None, metadata={'description': 'Which authentication method Cassandra should use to authenticate clients. None turns off authentication, so should not be used except in emergencies. Cassandra is the default password based authentication. The default is Cassandra .'})  # fmt: skip
    azure_connection_method: Optional[str] = field(default=None, metadata={'description': 'How to connect to the azure services needed for running the cluster'})  # fmt: skip
    cassandra_audit_logging_enabled: Optional[bool] = field(default=None, metadata={'description': 'Whether Cassandra audit logging is enabled'})  # fmt: skip
    cassandra_version: Optional[str] = field(default=None, metadata={'description': 'Which version of Cassandra should this cluster converge to running (e.g., 3.11). When updated, the cluster may take some time to migrate to the new version.'})  # fmt: skip
    client_certificates: Optional[List[str]] = field(default=None, metadata={'description': 'List of TLS certificates used to authorize clients connecting to the cluster. All connections are TLS encrypted whether clientCertificates is set or not, but if clientCertificates is set, the managed Cassandra cluster will reject all connections not bearing a TLS client certificate that can be validated from one or more of the public certificates in this property.'})  # fmt: skip
    cluster_name_override: Optional[str] = field(default=None, metadata={'description': 'If you need to set the clusterName property in cassandra.yaml to something besides the resource name of the cluster, set the value to use on this property.'})  # fmt: skip
    cluster_deallocated: Optional[bool] = field(default=None, metadata={'description': 'Whether the cluster and associated data centers has been deallocated.'})  # fmt: skip
    delegated_management_subnet_id: Optional[str] = field(default=None, metadata={'description': 'Resource id of a subnet that this cluster s management service should have its network interface attached to. The subnet must be routable to all subnets that will be delegated to data centers. The resource id must be of the form /subscriptions/<subscription id>/resourceGroups/<resource group>/providers/Microsoft.Network/virtualNetworks/<virtual network>/subnets/<subnet> '})  # fmt: skip
    external_gossip_certificates: Optional[List[str]] = field(default=None, metadata={'description': 'List of TLS certificates used to authorize gossip from unmanaged data centers. The TLS certificates of all nodes in unmanaged data centers must be verifiable using one of the certificates provided in this property.'})  # fmt: skip
    external_seed_nodes: Optional[List[str]] = field(default=None, metadata={'description': 'List of IP addresses of seed nodes in unmanaged data centers. These will be added to the seed node lists of all managed nodes.'})  # fmt: skip
    gossip_certificates: Optional[List[str]] = field(default=None, metadata={'description': 'List of TLS certificates that unmanaged nodes must trust for gossip with managed nodes. All managed nodes will present TLS client certificates that are verifiable using one of the certificates provided in this property.'})  # fmt: skip
    hours_between_backups: Optional[int] = field(default=None, metadata={'description': '(Deprecated) Number of hours to wait between taking a backup of the cluster.'})  # fmt: skip
    initial_cassandra_admin_password: Optional[str] = field(default=None, metadata={'description': 'Initial password for clients connecting as admin to the cluster. Should be changed after cluster creation. Returns null on GET. This field only applies when the authenticationMethod field is Cassandra .'})  # fmt: skip
    private_link_resource_id: Optional[str] = field(default=None, metadata={'description': 'If the Connection Method is VPN, this is the Id of the private link resource that the datacenters need to connect to.'})  # fmt: skip
    prometheus_endpoint: Optional[str] = field(default=None, metadata={"description": ""})
    provision_error: Optional[AzureCassandraError] = field(default=None, metadata={"description": ""})
    repair_enabled: Optional[bool] = field(default=None, metadata={'description': 'Should automatic repairs run on this cluster? If omitted, this is true, and should stay true unless you are running a hybrid cluster where you are already doing your own repairs.'})  # fmt: skip
    restore_from_backup_id: Optional[str] = field(default=None, metadata={'description': 'To create an empty cluster, omit this field or set it to null. To restore a backup into a new cluster, set this field to the resource id of the backup.'})  # fmt: skip
    seed_nodes: Optional[List[str]] = field(default=None, metadata={'description': 'List of IP addresses of seed nodes in the managed data centers. These should be added to the seed node lists of all unmanaged nodes.'})  # fmt: skip

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        account_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{account_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="cosmos-db",
            version="2024-05-15",
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
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if account_id := self.id:
            resources_to_collect = [
                ("status", AzureCosmosDBCassandraClusterPublicStatus, None),
                ("dataCenters", AzureCosmosDBCassandraClusterDataCenter, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    account_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )


@define(eq=False, slots=False)
class AzureAuthenticationMethodLdapProperties:
    kind: ClassVar[str] = "azure_authentication_method_ldap_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "connection_timeout_in_ms": S("connectionTimeoutInMs"),
        "search_base_distinguished_name": S("searchBaseDistinguishedName"),
        "search_filter_template": S("searchFilterTemplate"),
        "server_certificates": S("serverCertificates", default=[]) >> ForallBend(S("pem")),
        "server_hostname": S("serverHostname"),
        "server_port": S("serverPort"),
        "service_user_distinguished_name": S("serviceUserDistinguishedName"),
        "service_user_password": S("serviceUserPassword"),
    }
    connection_timeout_in_ms: Optional[int] = field(default=None, metadata={'description': 'Timeout for connecting to the LDAP server in miliseconds. The default is 5000 ms.'})  # fmt: skip
    search_base_distinguished_name: Optional[str] = field(default=None, metadata={'description': 'Distinguished name of the object to start the recursive search of users from.'})  # fmt: skip
    search_filter_template: Optional[str] = field(default=None, metadata={'description': 'Template to use for searching. Defaults to (cn=%s) where %s will be replaced by the username used to login.'})  # fmt: skip
    server_certificates: Optional[List[str]] = field(default=None, metadata={"description": ""})
    server_hostname: Optional[str] = field(default=None, metadata={"description": "Hostname of the LDAP server."})
    server_port: Optional[int] = field(default=None, metadata={"description": "Port of the LDAP server."})
    service_user_distinguished_name: Optional[str] = field(default=None, metadata={'description': 'Distinguished name of the look up user account, who can look up user details on authentication.'})  # fmt: skip
    service_user_password: Optional[str] = field(default=None, metadata={'description': 'Password of the look up user.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBCassandraClusterDataCenter(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_cassandra_cluster_data_center"
    # Collect via AzureCosmosDBCassandraCluster()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "authentication_method_ldap_properties": S("properties", "authenticationMethodLdapProperties")
        >> Bend(AzureAuthenticationMethodLdapProperties.mapping),
        "availability_zone_support": S("properties", "availabilityZone"),
        "backup_storage_customer_key_uri": S("properties", "backupStorageCustomerKeyUri"),
        "base64_encoded_cassandra_yaml_fragment": S("properties", "base64EncodedCassandraYamlFragment"),
        "data_center_location": S("properties", "dataCenterLocation"),
        "datacenter_deallocated": S("properties", "deallocated"),
        "delegated_subnet_id": S("properties", "delegatedSubnetId"),
        "disk_capacity": S("properties", "diskCapacity"),
        "datacenter_disk_sku": S("properties", "diskSku"),
        "managed_disk_customer_key_uri": S("properties", "managedDiskCustomerKeyUri"),
        "node_count": S("properties", "nodeCount"),
        "private_endpoint_ip_address": S("properties", "privateEndpointIpAddress"),
        "provision_error": S("properties", "provisionError") >> Bend(AzureCassandraError.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "seed_nodes": S("properties") >> S("seedNodes", default=[]) >> ForallBend(S("ipAddress")),
        "datacenter_sku": S("properties", "sku"),
    }
    authentication_method_ldap_properties: Optional[AzureAuthenticationMethodLdapProperties] = field(default=None, metadata={'description': 'Ldap authentication method properties. This feature is in preview.'})  # fmt: skip
    availability_zone_support: Optional[bool] = field(default=None, metadata={'description': 'If the data center has Availability Zone support, apply it to the Virtual Machine ScaleSet that host the cassandra data center virtual machines.'})  # fmt: skip
    backup_storage_customer_key_uri: Optional[str] = field(default=None, metadata={'description': 'Indicates the Key Uri of the customer key to use for encryption of the backup storage account.'})  # fmt: skip
    base64_encoded_cassandra_yaml_fragment: Optional[str] = field(default=None, metadata={'description': 'A fragment of a cassandra.yaml configuration file to be included in the cassandra.yaml for all nodes in this data center. The fragment should be Base64 encoded, and only a subset of keys are allowed.'})  # fmt: skip
    data_center_location: Optional[str] = field(default=None, metadata={'description': 'The region this data center should be created in.'})  # fmt: skip
    datacenter_deallocated: Optional[bool] = field(default=None, metadata={'description': 'Whether the data center has been deallocated.'})  # fmt: skip
    delegated_subnet_id: Optional[str] = field(default=None, metadata={'description': 'Resource id of a subnet the nodes in this data center should have their network interfaces connected to. The subnet must be in the same region specified in dataCenterLocation and must be able to route to the subnet specified in the cluster s delegatedManagementSubnetId property. This resource id will be of the form /subscriptions/<subscription id>/resourceGroups/<resource group>/providers/Microsoft.Network/virtualNetworks/<virtual network>/subnets/<subnet> .'})  # fmt: skip
    disk_capacity: Optional[int] = field(default=None, metadata={'description': 'Number of disks attached to each node. Default is 4.'})  # fmt: skip
    datacenter_disk_sku: Optional[str] = field(default=None, metadata={'description': 'Disk SKU used for data centers. Default value is P30.'})  # fmt: skip
    managed_disk_customer_key_uri: Optional[str] = field(default=None, metadata={'description': 'Key uri to use for encryption of managed disks. Ensure the system assigned identity of the cluster has been assigned appropriate permissions(key get/wrap/unwrap permissions) on the key.'})  # fmt: skip
    node_count: Optional[int] = field(default=None, metadata={'description': 'The number of nodes the data center should have. This is the desired number. After it is set, it may take some time for the data center to be scaled to match. To monitor the number of nodes and their status, use the fetchNodeStatus method on the cluster.'})  # fmt: skip
    private_endpoint_ip_address: Optional[str] = field(default=None, metadata={'description': 'Ip of the VPN Endpoint for this data center.'})  # fmt: skip
    provision_error: Optional[AzureCassandraError] = field(default=None, metadata={"description": ""})
    seed_nodes: Optional[List[str]] = field(default=None, metadata={'description': 'IP addresses for seed nodes in this data center. This is for reference. Generally you will want to use the seedNodes property on the cluster, which aggregates the seed nodes from all data centers in the cluster.'})  # fmt: skip
    datacenter_sku: Optional[str] = field(default=None, metadata={'description': 'Virtual Machine SKU used for data centers. Default value is Standard_DS14_v2'})  # fmt: skip


@define(eq=False, slots=False)
class AzureConsistencyPolicy:
    kind: ClassVar[str] = "azure_consistency_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_consistency_level": S("defaultConsistencyLevel"),
        "max_interval_in_seconds": S("maxIntervalInSeconds"),
        "max_staleness_prefix": S("maxStalenessPrefix"),
    }
    default_consistency_level: Optional[str] = field(default=None, metadata={'description': 'The default consistency level and configuration settings of the Cosmos DB account.'})  # fmt: skip
    max_interval_in_seconds: Optional[int] = field(default=None, metadata={'description': 'When used with the Bounded Staleness consistency level, this value represents the time amount of staleness (in seconds) tolerated. Accepted range for this value is 5 - 86400. Required when defaultConsistencyPolicy is set to BoundedStaleness .'})  # fmt: skip
    max_staleness_prefix: Optional[int] = field(default=None, metadata={'description': 'When used with the Bounded Staleness consistency level, this value represents the number of stale requests tolerated. Accepted range for this value is 1 – 2,147,483,647. Required when defaultConsistencyPolicy is set to BoundedStaleness .'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAccountLocation:
    kind: ClassVar[str] = "azure_account_location"
    mapping: ClassVar[Dict[str, Bender]] = {
        "document_endpoint": S("documentEndpoint"),
        "failover_priority": S("failoverPriority"),
        "id": S("id"),
        "is_zone_redundant": S("isZoneRedundant"),
        "location_name": S("locationName"),
        "provisioning_state": S("provisioningState"),
    }
    document_endpoint: Optional[str] = field(default=None, metadata={'description': 'The connection endpoint for the specific region. Example: https://&lt;accountName&gt;-&lt;locationName&gt;.documents.azure.com:443/'})  # fmt: skip
    failover_priority: Optional[int] = field(default=None, metadata={'description': 'The failover priority of the region. A failover priority of 0 indicates a write region. The maximum value for a failover priority = (total number of regions - 1). Failover priority values must be unique for each of the regions in which the database account exists.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'The unique identifier of the region within the database account. Example: &lt;accountName&gt;-&lt;locationName&gt;.'})  # fmt: skip
    is_zone_redundant: Optional[bool] = field(default=None, metadata={'description': 'Flag to indicate whether or not this region is an AvailabilityZone region'})  # fmt: skip
    location_name: Optional[str] = field(default=None, metadata={"description": "The name of the region."})
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'The status of the Cosmos DB account at the time the operation was called. The status can be one of following. Creating – the Cosmos DB account is being created. When an account is in Creating state, only properties that are specified as input for the Create Cosmos DB account operation are returned. Succeeded – the Cosmos DB account is active for use. Updating – the Cosmos DB account is being updated. Deleting – the Cosmos DB account is being deleted. Failed – the Cosmos DB account failed creation. DeletionFailed – the Cosmos DB account deletion failed.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureFailoverPolicy:
    kind: ClassVar[str] = "azure_failover_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failover_priority": S("failoverPriority"),
        "id": S("id"),
        "location_name": S("locationName"),
    }
    failover_priority: Optional[int] = field(default=None, metadata={'description': 'The failover priority of the region. A failover priority of 0 indicates a write region. The maximum value for a failover priority = (total number of regions - 1). Failover priority values must be unique for each of the regions in which the database account exists.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={'description': 'The unique identifier of the region in which the database account replicates to. Example: &lt;accountName&gt;-&lt;locationName&gt;.'})  # fmt: skip
    location_name: Optional[str] = field(default=None, metadata={'description': 'The name of the region in which the database account exists.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureAccountVirtualNetworkRule:
    kind: ClassVar[str] = "azure_account_virtual_network_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "ignore_missing_v_net_service_endpoint": S("ignoreMissingVNetServiceEndpoint"),
    }
    id: Optional[str] = field(default=None, metadata={'description': 'Resource ID of a subnet, for example: /subscriptions/{subscriptionId}/resourceGroups/{groupName}/providers/Microsoft.Network/virtualNetworks/{virtualNetworkName}/subnets/{subnetName}.'})  # fmt: skip
    ignore_missing_v_net_service_endpoint: Optional[bool] = field(default=None, metadata={'description': 'Create firewall rule before the virtual network has vnet service endpoint enabled.'})  # fmt: skip


@define(eq=False, slots=False)
class AzurePrivateLinkServiceConnectionStateProperty:
    kind: ClassVar[str] = "azure_private_link_service_connection_state_property"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions_required": S("actionsRequired"),
        "description": S("description"),
        "status": S("status"),
    }
    actions_required: Optional[str] = field(default=None, metadata={'description': 'Any action that is required beyond basic workflow (approve/ reject/ disconnect)'})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={'description': 'The private link service connection description.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'The private link service connection status.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDatabaseAccountPrivateEndpointConnection(AzureProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_private_endpoint_connection"
    mapping: ClassVar[Dict[str, Bender]] = AzureProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "group_id": S("properties", "groupId"),
        "private_endpoint": S("properties", "privateEndpoint", "id"),
        "private_link_service_connection_state": S("properties", "privateLinkServiceConnectionState")
        >> Bend(AzurePrivateLinkServiceConnectionStateProperty.mapping),
        "provisioning_state": S("properties", "provisioningState"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Private endpoint connection name."})
    id: Optional[str] = field(default=None, metadata={"description": "Private endpoint connection ID."})
    group_id: Optional[str] = field(default=None, metadata={"description": "Group id of the private endpoint."})
    private_endpoint: Optional[str] = field(default=None, metadata={'description': 'Private endpoint which the connection belongs to.'})  # fmt: skip
    private_link_service_connection_state: Optional[AzurePrivateLinkServiceConnectionStateProperty] = field(default=None, metadata={'description': 'Connection State of the Private Endpoint Connection.'})  # fmt: skip
    provisioning_state: Optional[str] = field(default=None, metadata={'description': 'Provisioning state of the private endpoint.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestoreParametersBase:
    kind: ClassVar[str] = "azure_restore_parameters_base"
    mapping: ClassVar[Dict[str, Bender]] = {
        "restore_source": S("restoreSource"),
        "restore_timestamp_in_utc": S("restoreTimestampInUtc"),
    }
    restore_source: Optional[str] = field(default=None, metadata={'description': 'The id of the restorable database account from which the restore has to be initiated. For example: /subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/locations/{location}/restorableDatabaseAccounts/{restorableDatabaseAccountName}'})  # fmt: skip
    restore_timestamp_in_utc: Optional[datetime] = field(default=None, metadata={'description': 'Time to which the account has to be restored (ISO-8601 format).'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDatabaseRestoreResource:
    kind: ClassVar[str] = "azure_database_restore_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "collection_names": S("collectionNames"),
        "database_name": S("databaseName"),
    }
    collection_names: Optional[List[str]] = field(default=None, metadata={'description': 'The names of the collections available for restore.'})  # fmt: skip
    database_name: Optional[str] = field(default=None, metadata={'description': 'The name of the database available for restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureGremlinDatabaseRestoreResource:
    kind: ClassVar[str] = "azure_gremlin_database_restore_resource"
    mapping: ClassVar[Dict[str, Bender]] = {"database_name": S("databaseName"), "graph_names": S("graphNames")}
    database_name: Optional[str] = field(default=None, metadata={'description': 'The name of the gremlin database available for restore.'})  # fmt: skip
    graph_names: Optional[List[str]] = field(default=None, metadata={'description': 'The names of the graphs available for restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestoreParameters(AzureRestoreParametersBase):
    kind: ClassVar[str] = "azure_restore_parameters"
    mapping: ClassVar[Dict[str, Bender]] = AzureRestoreParametersBase.mapping | {
        "databases_to_restore": S("databasesToRestore") >> ForallBend(AzureDatabaseRestoreResource.mapping),
        "gremlin_databases_to_restore": S("gremlinDatabasesToRestore")
        >> ForallBend(AzureGremlinDatabaseRestoreResource.mapping),
        "restore_mode": S("restoreMode"),
        "tables_to_restore": S("tablesToRestore"),
    }
    databases_to_restore: Optional[List[AzureDatabaseRestoreResource]] = field(default=None, metadata={'description': 'List of specific databases available for restore.'})  # fmt: skip
    gremlin_databases_to_restore: Optional[List[AzureGremlinDatabaseRestoreResource]] = field(default=None, metadata={'description': 'List of specific gremlin databases available for restore.'})  # fmt: skip
    restore_mode: Optional[str] = field(default=None, metadata={"description": "Describes the mode of the restore."})
    tables_to_restore: Optional[List[str]] = field(default=None, metadata={'description': 'List of specific tables available for restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureBackupPolicyMigrationState:
    kind: ClassVar[str] = "azure_backup_policy_migration_state"
    mapping: ClassVar[Dict[str, Bender]] = {
        "start_time": S("startTime"),
        "status": S("status"),
        "target_type": S("targetType"),
    }
    start_time: Optional[datetime] = field(default=None, metadata={'description': 'Time at which the backup policy migration started (ISO-8601 format).'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Describes the status of migration between backup policy types.'})  # fmt: skip
    target_type: Optional[str] = field(default=None, metadata={"description": "Describes the mode of backups."})


@define(eq=False, slots=False)
class AzureBackupPolicy:
    kind: ClassVar[str] = "azure_backup_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "migration_state": S("migrationState") >> Bend(AzureBackupPolicyMigrationState.mapping),
        "type": S("type"),
    }
    migration_state: Optional[AzureBackupPolicyMigrationState] = field(default=None, metadata={'description': 'The object representing the state of the migration between the backup policies.'})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Describes the mode of backups."})


@define(eq=False, slots=False)
class AzureCorsPolicy:
    kind: ClassVar[str] = "azure_cors_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allowed_headers": S("allowedHeaders"),
        "allowed_methods": S("allowedMethods"),
        "allowed_origins": S("allowedOrigins"),
        "exposed_headers": S("exposedHeaders"),
        "max_age_in_seconds": S("maxAgeInSeconds"),
    }
    allowed_headers: Optional[str] = field(default=None, metadata={'description': 'The request headers that the origin domain may specify on the CORS request.'})  # fmt: skip
    allowed_methods: Optional[str] = field(default=None, metadata={'description': 'The methods (HTTP request verbs) that the origin domain may use for a CORS request.'})  # fmt: skip
    allowed_origins: Optional[str] = field(default=None, metadata={'description': 'The origin domains that are permitted to make a request against the service via CORS.'})  # fmt: skip
    exposed_headers: Optional[str] = field(default=None, metadata={'description': 'The response headers that may be sent in the response to the CORS request and exposed by the browser to the request issuer.'})  # fmt: skip
    max_age_in_seconds: Optional[int] = field(default=None, metadata={'description': 'The maximum amount time that a browser should cache the preflight OPTIONS request.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureDatabaseAccountKeysMetadata:
    kind: ClassVar[str] = "azure_database_account_keys_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "primary_master_key": S("primaryMasterKey", "generationTime"),
        "primary_readonly_master_key": S("primaryReadonlyMasterKey", "generationTime"),
        "secondary_master_key": S("secondaryMasterKey", "generationTime"),
        "secondary_readonly_master_key": S("secondaryReadonlyMasterKey", "generationTime"),
    }
    primary_master_key: Optional[datetime] = field(default=None, metadata={'description': 'The metadata related to an access key for a given database account.'})  # fmt: skip
    primary_readonly_master_key: Optional[datetime] = field(default=None, metadata={'description': 'The metadata related to an access key for a given database account.'})  # fmt: skip
    secondary_master_key: Optional[datetime] = field(default=None, metadata={'description': 'The metadata related to an access key for a given database account.'})  # fmt: skip
    secondary_readonly_master_key: Optional[datetime] = field(default=None, metadata={'description': 'The metadata related to an access key for a given database account.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBAccount(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_account"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="cosmos-db",
        version="2024-05-15",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_cosmos_db_cassandra_keyspace",
                "azure_cosmos_db_account_read_only_keys",
                "azure_cosmos_db_gremlin_database",
                "azure_cosmos_db_mongo_db_database",
                "azure_cosmos_db_mongo_db_role_definition",
                "azure_cosmos_db_mongo_db_user_definition",
                "azure_cosmos_db_notebook_workspace",
                "azure_cosmos_db_private_link_resource",
                "azure_cosmos_db_table",
                "azure_cosmos_db_account_usage",
                "azure_cosmos_db_sql_database",
                "azure_cosmos_db_sql_role_assignment",
                "azure_cosmos_db_sql_role_definition",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "ctime": S("systemData", "createdAt"),
        "analytical_storage_configuration": S("properties", "analyticalStorageConfiguration", "schemaType"),
        "api_properties": S("properties", "apiProperties", "serverVersion"),
        "backup_policy": S("properties", "backupPolicy") >> Bend(AzureBackupPolicy.mapping),
        "capabilities": S("properties") >> S("capabilities", default=[]) >> ForallBend(S("name")),
        "capacity": S("properties", "capacity", "totalThroughputLimit"),
        "connector_offer": S("properties", "connectorOffer"),
        "consistency_policy": S("properties", "consistencyPolicy") >> Bend(AzureConsistencyPolicy.mapping),
        "account_cors": S("properties", "cors") >> ForallBend(AzureCorsPolicy.mapping),
        "create_mode": S("properties", "createMode"),
        "customer_managed_key_status": S("properties", "customerManagedKeyStatus"),
        "database_account_offer_type": S("properties", "databaseAccountOfferType"),
        "default_identity": S("properties", "defaultIdentity"),
        "disable_key_based_metadata_write_access": S("properties", "disableKeyBasedMetadataWriteAccess"),
        "disable_local_auth": S("properties", "disableLocalAuth"),
        "document_endpoint": S("properties", "documentEndpoint"),
        "enable_analytical_storage": S("properties", "enableAnalyticalStorage"),
        "enable_automatic_failover": S("properties", "enableAutomaticFailover"),
        "enable_burst_capacity": S("properties", "enableBurstCapacity"),
        "enable_cassandra_connector": S("properties", "enableCassandraConnector"),
        "enable_free_tier": S("properties", "enableFreeTier"),
        "enable_multiple_write_locations": S("properties", "enableMultipleWriteLocations"),
        "enable_partition_merge": S("properties", "enablePartitionMerge"),
        "failover_policies": S("properties", "failoverPolicies") >> ForallBend(AzureFailoverPolicy.mapping),
        "account_identity": S("identity") >> Bend(AzureResourceIdentity.mapping),
        "instance_id": S("properties", "instanceId"),
        "ip_rules": S("properties") >> S("ipRules", default=[]) >> ForallBend(S("ipAddressOrRange")),
        "is_virtual_network_filter_enabled": S("properties", "isVirtualNetworkFilterEnabled"),
        "key_vault_key_uri": S("properties", "keyVaultKeyUri"),
        "keys_metadata": S("properties", "keysMetadata") >> Bend(AzureDatabaseAccountKeysMetadata.mapping),
        "resource_kind": S("kind"),
        "account_locations": S("properties", "locations") >> ForallBend(AzureAccountLocation.mapping),
        "minimal_tls_version": S("properties", "minimalTlsVersion"),
        "network_acl_bypass": S("properties", "networkAclBypass"),
        "network_acl_bypass_resource_ids": S("properties", "networkAclBypassResourceIds"),
        "account_private_endpoint_connections": S("properties", "privateEndpointConnections")
        >> ForallBend(AzureDatabaseAccountPrivateEndpointConnection.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "public_network_access": S("properties", "publicNetworkAccess"),
        "read_locations": S("properties", "readLocations") >> ForallBend(AzureAccountLocation.mapping),
        "account_restore_parameters": S("properties", "restoreParameters") >> Bend(AzureRestoreParameters.mapping),
        "system_data": S("systemData") >> Bend(AzureSystemData.mapping),
        "virtual_network_rules": S("properties", "virtualNetworkRules")
        >> ForallBend(AzureAccountVirtualNetworkRule.mapping),
        "write_locations": S("properties", "writeLocations") >> ForallBend(AzureAccountLocation.mapping),
    }
    analytical_storage_configuration: Optional[str] = field(default=None, metadata={'description': 'Analytical storage specific properties.'})  # fmt: skip
    api_properties: Optional[str] = field(default=None, metadata={"description": ""})
    backup_policy: Optional[AzureBackupPolicy] = field(default=None, metadata={'description': 'The object representing the policy for taking backups on an account.'})  # fmt: skip
    capabilities: Optional[List[str]] = field(default=None, metadata={'description': 'List of Cosmos DB capabilities for the account'})  # fmt: skip
    capacity: Optional[int] = field(default=None, metadata={'description': 'The object that represents all properties related to capacity enforcement on an account.'})  # fmt: skip
    connector_offer: Optional[str] = field(default=None, metadata={'description': 'The cassandra connector offer type for the Cosmos DB C* database account.'})  # fmt: skip
    consistency_policy: Optional[AzureConsistencyPolicy] = field(default=None, metadata={'description': 'The consistency policy for the Cosmos DB database account.'})  # fmt: skip
    account_cors: Optional[List[AzureCorsPolicy]] = field(default=None, metadata={'description': 'The CORS policy for the Cosmos DB database account.'})  # fmt: skip
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the mode of account creation.'})  # fmt: skip
    customer_managed_key_status: Optional[str] = field(default=None, metadata={'description': 'Indicates the status of the Customer Managed Key feature on the account. In case there are errors, the property provides troubleshooting guidance.'})  # fmt: skip
    database_account_offer_type: Optional[str] = field(default=None, metadata={'description': 'The offer type for the Cosmos DB database account.'})  # fmt: skip
    default_identity: Optional[str] = field(default=None, metadata={'description': 'The default identity for accessing key vault used in features like customer managed keys. The default identity needs to be explicitly set by the users. It can be FirstPartyIdentity , SystemAssignedIdentity and more.'})  # fmt: skip
    disable_key_based_metadata_write_access: Optional[bool] = field(default=None, metadata={'description': 'Disable write operations on metadata resources (databases, containers, throughput) via account keys'})  # fmt: skip
    disable_local_auth: Optional[bool] = field(default=None, metadata={'description': 'Opt-out of local authentication and ensure only MSI and AAD can be used exclusively for authentication.'})  # fmt: skip
    document_endpoint: Optional[str] = field(default=None, metadata={'description': 'The connection endpoint for the Cosmos DB database account.'})  # fmt: skip
    enable_analytical_storage: Optional[bool] = field(default=None, metadata={'description': 'Flag to indicate whether to enable storage analytics.'})  # fmt: skip
    enable_automatic_failover: Optional[bool] = field(default=None, metadata={'description': 'Enables automatic failover of the write region in the rare event that the region is unavailable due to an outage. Automatic failover will result in a new write region for the account and is chosen based on the failover priorities configured for the account.'})  # fmt: skip
    enable_burst_capacity: Optional[bool] = field(default=None, metadata={'description': 'Flag to indicate enabling/disabling of Burst Capacity feature on the account'})  # fmt: skip
    enable_cassandra_connector: Optional[bool] = field(default=None, metadata={'description': 'Enables the cassandra connector on the Cosmos DB C* account'})  # fmt: skip
    enable_free_tier: Optional[bool] = field(default=None, metadata={'description': 'Flag to indicate whether Free Tier is enabled.'})  # fmt: skip
    enable_multiple_write_locations: Optional[bool] = field(default=None, metadata={'description': 'Enables the account to write in multiple locations'})  # fmt: skip
    enable_partition_merge: Optional[bool] = field(default=None, metadata={'description': 'Flag to indicate enabling/disabling of Partition Merge feature on the account'})  # fmt: skip
    failover_policies: Optional[List[AzureFailoverPolicy]] = field(default=None, metadata={'description': 'An array that contains the regions ordered by their failover priorities.'})  # fmt: skip
    account_identity: Optional[AzureResourceIdentity] = field(default=None, metadata={'description': 'Identity for the resource.'})  # fmt: skip
    instance_id: Optional[str] = field(default=None, metadata={'description': 'A unique identifier assigned to the database account'})  # fmt: skip
    ip_rules: Optional[List[str]] = field(default=None, metadata={"description": "Array of IpAddressOrRange objects."})
    is_virtual_network_filter_enabled: Optional[bool] = field(default=None, metadata={'description': 'Flag to indicate whether to enable/disable Virtual Network ACL rules.'})  # fmt: skip
    key_vault_key_uri: Optional[str] = field(default=None, metadata={"description": "The URI of the key vault"})
    keys_metadata: Optional[AzureDatabaseAccountKeysMetadata] = field(default=None, metadata={'description': 'The metadata related to each access key for the given Cosmos DB database account.'})  # fmt: skip
    resource_kind: Optional[str] = field(default=None, metadata={'description': 'Indicates the type of database account. This can only be set at database account creation.'})  # fmt: skip
    account_locations: Optional[List[AzureAccountLocation]] = field(default=None, metadata={'description': 'An array that contains all of the locations enabled for the Cosmos DB account.'})  # fmt: skip
    minimal_tls_version: Optional[str] = field(default=None, metadata={'description': 'Indicates the minimum allowed Tls version. The default value is Tls 1.2. Cassandra and Mongo APIs only work with Tls 1.2.'})  # fmt: skip
    network_acl_bypass: Optional[str] = field(default=None, metadata={'description': 'Indicates what services are allowed to bypass firewall checks.'})  # fmt: skip
    network_acl_bypass_resource_ids: Optional[List[str]] = field(default=None, metadata={'description': 'An array that contains the Resource Ids for Network Acl Bypass for the Cosmos DB account.'})  # fmt: skip
    account_private_endpoint_connections: Optional[List[AzureDatabaseAccountPrivateEndpointConnection]] = field(default=None, metadata={'description': 'List of Private Endpoint Connections configured for the Cosmos DB account.'})  # fmt: skip
    public_network_access: Optional[str] = field(default=None, metadata={'description': 'Whether requests from Public Network are allowed'})  # fmt: skip
    read_locations: Optional[List[AzureAccountLocation]] = field(default=None, metadata={'description': 'An array that contains of the read locations enabled for the Cosmos DB account.'})  # fmt: skip
    account_restore_parameters: Optional[AzureRestoreParameters] = field(default=None, metadata={'description': 'Parameters to indicate the information about the restore.'})  # fmt: skip
    system_data: Optional[AzureSystemData] = field(default=None, metadata={'description': 'Metadata pertaining to creation and last modification of the resource.'})  # fmt: skip
    virtual_network_rules: Optional[List[AzureAccountVirtualNetworkRule]] = field(default=None, metadata={'description': 'List of Virtual Network ACL rules configured for the Cosmos DB account.'})  # fmt: skip
    write_locations: Optional[List[AzureAccountLocation]] = field(default=None, metadata={'description': 'An array that contains the write location for the Cosmos DB account.'})  # fmt: skip

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        account_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{account_id}/{resource_type}"
        if issubclass(AzureCosmosDBAccountReadOnlyKeys, class_instance):  # type: ignore
            api_spec = AzureResourceSpec(
                service="cosmos-db",
                version="2024-05-15",
                path=path,
                path_parameters=[],
                query_parameters=["api-version"],
                access_path=None,
                expect_array=False,
                expected_error_codes=expected_errors or [],
            )
        else:
            api_spec = AzureResourceSpec(
                service="cosmos-db",
                version="2024-05-15",
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
        if issubclass(AzureCosmosDBAccountReadOnlyKeys, class_instance):  # type: ignore
            collected = class_instance.collect_keys(account_id, items, graph_builder)  # type: ignore
        elif issubclass(AzureCosmosDBAccountUsage, class_instance):  # type: ignore
            collected = class_instance.collect_usages(account_id, items, graph_builder)  # type: ignore
        else:
            collected = class_instance.collect(items, graph_builder)
        for clazz in collected:
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if account_id := self.id:
            resources_to_collect = [
                ("cassandraKeyspaces", AzureCosmosDBCassandraKeyspace, None),
                ("readonlykeys", AzureCosmosDBAccountReadOnlyKeys, None),
                ("gremlinDatabases", AzureCosmosDBGremlinDatabase, None),
                ("mongodbDatabases", AzureCosmosDBMongoDBDatabase, None),
                ("mongodbRoleDefinitions", AzureCosmosDBMongoDBRoleDefinition, None),
                ("mongodbUserDefinitions", AzureCosmosDBMongoDBUserDefinition, None),
                ("notebookWorkspaces", AzureCosmosDBNotebookWorkspace, None),
                ("privateLinkResources", AzureCosmosDBPrivateLinkResource, None),
                ("tables", AzureCosmosDBTable, None),
                ("usages", AzureCosmosDBAccountUsage, ["SubscriptionHasNoUsages"]),
            ]
            # For fetching SQL resources required 'GlobalDocumentDB' kind
            if self.resource_kind == "GlobalDocumentDB":
                resources_to_collect.extend(
                    [
                        ("sqlDatabases", AzureCosmosDBSqlDatabase, None),
                        ("sqlRoleAssignments", AzureCosmosDBSqlRoleAssignment, None),
                        ("sqlRoleDefinitions", AzureCosmosDBSqlRoleDefinition, None),
                    ]
                )
            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    account_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )


@define(eq=False, slots=False)
class AzureCosmosDBAccountReadOnlyKeys(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_account_read_only_keys"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "primary_readonly_master_key": S("primaryReadonlyMasterKey"),
        "secondary_readonly_master_key": S("secondaryReadonlyMasterKey"),
    }
    primary_readonly_master_key: Optional[str] = field(default=None, metadata={'description': 'Base 64 encoded value of the primary read-only key.'})  # fmt: skip
    secondary_readonly_master_key: Optional[str] = field(default=None, metadata={'description': 'Base 64 encoded value of the secondary read-only key.'})  # fmt: skip

    @classmethod
    def collect_keys(
        cls, account_id: str, raw: List[Json], builder: GraphBuilder
    ) -> List[AzureCosmosDBAccountReadOnlyKeys]:
        result = []
        for js in raw:
            # map from api
            if instance := cls.from_api(js, builder):
                # Set account id to resource name and id
                instance.name = instance.id = account_id
                if (added := builder.add_node(instance, js)) is not None:
                    result.append(added)
        return result


@define(eq=False, slots=False)
class AzureResourceRestoreParameters(AzureRestoreParametersBase):
    kind: ClassVar[str] = "azure_resource_restore_parameters"
    mapping: ClassVar[Dict[str, Bender]] = AzureRestoreParametersBase.mapping | {}


@define(eq=False, slots=False)
class AzureGremlinDatabaseResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_gremlin_database_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {
        "create_mode": S("createMode"),
        "id": S("id"),
        "restore_parameters": S("restoreParameters") >> Bend(AzureResourceRestoreParameters.mapping),
    }
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the mode of account creation.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB Gremlin database"})
    restore_parameters: Optional[AzureResourceRestoreParameters] = field(default=None, metadata={'description': 'Parameters to indicate the information about the restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBGremlinDatabase(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_gremlin_database"
    # Collect via AzureCosmosDBAccount()
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_cosmos_db_gremlin_graph",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "gremlin_database_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "gremlin_database_resource": S("properties", "resource") >> Bend(AzureGremlinDatabaseResource.mapping),
    }
    gremlin_database_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    gremlin_database_resource: Optional[AzureGremlinDatabaseResource] = field(
        default=None, metadata={"description": ""}
    )

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        account_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{account_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="cosmos-db",
            version="2024-05-15",
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
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if account_id := self.id:
            resources_to_collect = [
                ("graphs", AzureCosmosDBGremlinGraph, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    account_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )


@define(eq=False, slots=False)
class AzureIndexes:
    kind: ClassVar[str] = "azure_indexes"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_type": S("dataType"),
        "resource_kind": S("kind"),
        "precision": S("precision"),
    }
    data_type: Optional[str] = field(default=None, metadata={'description': 'The datatype for which the indexing behavior is applied to.'})  # fmt: skip
    resource_kind: Optional[str] = field(default=None, metadata={"description": "Indicates the type of index."})
    precision: Optional[int] = field(default=None, metadata={'description': 'The precision of the index. -1 is maximum precision.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureIncludedPath:
    kind: ClassVar[str] = "azure_included_path"
    mapping: ClassVar[Dict[str, Bender]] = {
        "indexes": S("indexes") >> ForallBend(AzureIndexes.mapping),
        "path": S("path"),
    }
    indexes: Optional[List[AzureIndexes]] = field(
        default=None, metadata={"description": "List of indexes for this path"}
    )
    path: Optional[str] = field(default=None, metadata={'description': 'The path for which the indexing behavior applies to. Index paths typically start with root and end with wildcard (/path/*)'})  # fmt: skip


@define(eq=False, slots=False)
class AzureSpatialSpec:
    kind: ClassVar[str] = "azure_spatial_spec"
    mapping: ClassVar[Dict[str, Bender]] = {"path": S("path"), "types": S("types")}
    path: Optional[str] = field(default=None, metadata={'description': 'The path for which the indexing behavior applies to. Index paths typically start with root and end with wildcard (/path/*)'})  # fmt: skip
    types: Optional[List[str]] = field(default=None, metadata={"description": "List of path s spatial type"})


@define(eq=False, slots=False)
class AzureCompositePath:
    kind: ClassVar[str] = "azure_composite_path"
    mapping: ClassVar[Dict[str, Bender]] = {"path": S("path"), "order": S("order")}
    path: Optional[str] = field(default=None, metadata={'description': 'The path for which the indexing behavior applies to. Index paths typically start with root and end with wildcard (/path/*)'})  # fmt: skip
    order: Optional[str] = field(default=None, metadata={"description": "Sort order for composite paths."})


@define(eq=False, slots=False)
class AzureIndexingPolicy:
    kind: ClassVar[str] = "azure_indexing_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "automatic": S("automatic"),
        "composite_indexes": S("compositeIndexes") >> ForallBend(AzureCompositePath.mapping),
        "excluded_paths": S("excludedPaths", default=[]) >> ForallBend(S("path")),
        "included_paths": S("includedPaths") >> ForallBend(AzureIncludedPath.mapping),
        "indexing_mode": S("indexingMode"),
        "spatial_indexes": S("spatialIndexes") >> ForallBend(AzureSpatialSpec.mapping),
    }
    automatic: Optional[bool] = field(default=None, metadata={'description': 'Indicates if the indexing policy is automatic'})  # fmt: skip
    composite_indexes: Optional[List[AzureCompositePath]] = field(default=None, metadata={'description': 'List of composite path list'})  # fmt: skip
    excluded_paths: Optional[List[str]] = field(default=None, metadata={'description': 'List of paths to exclude from indexing'})  # fmt: skip
    included_paths: Optional[List[AzureIncludedPath]] = field(default=None, metadata={'description': 'List of paths to include in the indexing'})  # fmt: skip
    indexing_mode: Optional[str] = field(default=None, metadata={"description": "Indicates the indexing mode."})
    spatial_indexes: Optional[List[AzureSpatialSpec]] = field(default=None, metadata={'description': 'List of spatial specifics'})  # fmt: skip


@define(eq=False, slots=False)
class AzureContainerPartitionKey:
    kind: ClassVar[str] = "azure_container_partition_key"
    mapping: ClassVar[Dict[str, Bender]] = {
        "resource_kind": S("kind"),
        "paths": S("paths"),
        "system_key": S("systemKey"),
        "version": S("version"),
    }
    resource_kind: Optional[str] = field(default=None, metadata={'description': 'Indicates the kind of algorithm used for partitioning. For MultiHash, multiple partition keys (upto three maximum) are supported for container create'})  # fmt: skip
    paths: Optional[List[str]] = field(default=None, metadata={'description': 'List of paths using which data within the container can be partitioned'})  # fmt: skip
    system_key: Optional[bool] = field(default=None, metadata={'description': 'Indicates if the container is using a system generated partition key'})  # fmt: skip
    version: Optional[int] = field(default=None, metadata={'description': 'Indicates the version of the partition key definition'})  # fmt: skip


@define(eq=False, slots=False)
class AzureUniqueKey:
    kind: ClassVar[str] = "azure_unique_key"
    mapping: ClassVar[Dict[str, Bender]] = {"paths": S("paths")}
    paths: Optional[List[str]] = field(default=None, metadata={'description': 'List of paths must be unique for each document in the Azure Cosmos DB service'})  # fmt: skip


@define(eq=False, slots=False)
class AzureUniqueKeyPolicy:
    kind: ClassVar[str] = "azure_unique_key_policy"
    mapping: ClassVar[Dict[str, Bender]] = {"unique_keys": S("uniqueKeys") >> ForallBend(AzureUniqueKey.mapping)}
    unique_keys: Optional[List[AzureUniqueKey]] = field(default=None, metadata={'description': 'List of unique keys on that enforces uniqueness constraint on documents in the collection in the Azure Cosmos DB service.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureConflictResolutionPolicy:
    kind: ClassVar[str] = "azure_conflict_resolution_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "conflict_resolution_path": S("conflictResolutionPath"),
        "conflict_resolution_procedure": S("conflictResolutionProcedure"),
        "mode": S("mode"),
    }
    conflict_resolution_path: Optional[str] = field(default=None, metadata={'description': 'The conflict resolution path in the case of LastWriterWins mode.'})  # fmt: skip
    conflict_resolution_procedure: Optional[str] = field(default=None, metadata={'description': 'The procedure to resolve conflicts in the case of custom mode.'})  # fmt: skip
    mode: Optional[str] = field(default=None, metadata={"description": "Indicates the conflict resolution mode."})


@define(eq=False, slots=False)
class AzureGremlinGraphResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_gremlin_graph_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {
        "analytical_storage_ttl": S("analyticalStorageTtl"),
        "conflict_resolution_policy": S("conflictResolutionPolicy") >> Bend(AzureConflictResolutionPolicy.mapping),
        "create_mode": S("createMode"),
        "default_ttl": S("defaultTtl"),
        "id": S("id"),
        "indexing_policy": S("indexingPolicy") >> Bend(AzureIndexingPolicy.mapping),
        "partition_key": S("partitionKey") >> Bend(AzureContainerPartitionKey.mapping),
        "restore_parameters": S("restoreParameters") >> Bend(AzureResourceRestoreParameters.mapping),
        "unique_key_policy": S("uniqueKeyPolicy") >> Bend(AzureUniqueKeyPolicy.mapping),
    }
    analytical_storage_ttl: Optional[int] = field(default=None, metadata={"description": "Analytical TTL."})
    conflict_resolution_policy: Optional[AzureConflictResolutionPolicy] = field(default=None, metadata={'description': 'The conflict resolution policy for the container.'})  # fmt: skip
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the mode of account creation.'})  # fmt: skip
    default_ttl: Optional[int] = field(default=None, metadata={"description": "Default time to live"})
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB Gremlin graph"})
    indexing_policy: Optional[AzureIndexingPolicy] = field(default=None, metadata={'description': 'Cosmos DB indexing policy'})  # fmt: skip
    partition_key: Optional[AzureContainerPartitionKey] = field(default=None, metadata={'description': 'The configuration of the partition key to be used for partitioning data into multiple partitions'})  # fmt: skip
    restore_parameters: Optional[AzureResourceRestoreParameters] = field(default=None, metadata={'description': 'Parameters to indicate the information about the restore.'})  # fmt: skip
    unique_key_policy: Optional[AzureUniqueKeyPolicy] = field(default=None, metadata={'description': 'The unique key policy configuration for specifying uniqueness constraints on documents in the collection in the Azure Cosmos DB service.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBGremlinGraph(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_gremlin_graph"
    # Collect via AzureCosmosDBGremlinDatabase()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "gremlin_graph_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "gremlin_graph_resource": S("properties", "resource") >> Bend(AzureGremlinGraphResource.mapping),
    }
    gremlin_graph_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    gremlin_graph_resource: Optional[AzureGremlinGraphResource] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureMongoIndexKeys:
    kind: ClassVar[str] = "azure_mongo_index_keys"
    mapping: ClassVar[Dict[str, Bender]] = {"keys": S("keys")}
    keys: Optional[List[str]] = field(default=None, metadata={'description': 'List of keys for each MongoDB collection in the Azure Cosmos DB service'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMongoIndexOptions:
    kind: ClassVar[str] = "azure_mongo_index_options"
    mapping: ClassVar[Dict[str, Bender]] = {"expire_after_seconds": S("expireAfterSeconds"), "unique": S("unique")}
    expire_after_seconds: Optional[int] = field(default=None, metadata={"description": "Expire after seconds"})
    unique: Optional[bool] = field(default=None, metadata={"description": "Is unique or not"})


@define(eq=False, slots=False)
class AzureMongoIndex:
    kind: ClassVar[str] = "azure_mongo_index"
    mapping: ClassVar[Dict[str, Bender]] = {
        "key": S("key") >> Bend(AzureMongoIndexKeys.mapping),
        "options": S("options") >> Bend(AzureMongoIndexOptions.mapping),
    }
    key: Optional[AzureMongoIndexKeys] = field(default=None, metadata={'description': 'Cosmos DB MongoDB collection resource object'})  # fmt: skip
    options: Optional[AzureMongoIndexOptions] = field(default=None, metadata={'description': 'Cosmos DB MongoDB collection index options'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMongoDBCollectionResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_mongo_db_collection_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {
        "analytical_storage_ttl": S("analyticalStorageTtl"),
        "create_mode": S("createMode"),
        "id": S("id"),
        "indexes": S("indexes") >> ForallBend(AzureMongoIndex.mapping),
        "restore_parameters": S("restoreParameters") >> Bend(AzureResourceRestoreParameters.mapping),
        "shard_key": S("shardKey"),
    }
    analytical_storage_ttl: Optional[int] = field(default=None, metadata={"description": "Analytical TTL."})
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the mode of account creation.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB MongoDB collection"})
    indexes: Optional[List[AzureMongoIndex]] = field(default=None, metadata={"description": "List of index keys"})
    restore_parameters: Optional[AzureResourceRestoreParameters] = field(default=None, metadata={'description': 'Parameters to indicate the information about the restore.'})  # fmt: skip
    shard_key: Optional[Dict[str, str]] = field(default=None, metadata={'description': 'The shard key and partition kind pair, only support Hash partition kind'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBMongoDBCollection(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_mongo_db_collection"
    # Collect via AzureCosmosDBMongoDBDatabase()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "mongodb_collection_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "mongodb_collection_resource": S("properties", "resource") >> Bend(AzureMongoDBCollectionResource.mapping),
    }
    mongodb_collection_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    mongodb_collection_resource: Optional[AzureMongoDBCollectionResource] = field(
        default=None, metadata={"description": ""}
    )


@define(eq=False, slots=False)
class AzureMongoDBDatabaseResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_mongo_db_database_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {
        "create_mode": S("createMode"),
        "id": S("id"),
        "restore_parameters": S("restoreParameters") >> Bend(AzureResourceRestoreParameters.mapping),
    }
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the mode of account creation.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB MongoDB database"})
    restore_parameters: Optional[AzureResourceRestoreParameters] = field(default=None, metadata={'description': 'Parameters to indicate the information about the restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBMongoDBDatabase(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_mongo_db_database"
    # Collect via AzureCosmosDBAccount()
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_cosmos_db_mongo_db_collection",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "mongodb_database_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "mongodb_database_resource": S("properties", "resource") >> Bend(AzureMongoDBDatabaseResource.mapping),
    }
    mongodb_database_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    mongodb_database_resource: Optional[AzureMongoDBDatabaseResource] = field(
        default=None, metadata={"description": ""}
    )

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        account_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{account_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="cosmos-db",
            version="2024-05-15",
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
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if account_id := self.id:
            resources_to_collect = [
                ("collections", AzureCosmosDBMongoDBCollection, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    account_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )


@define(eq=False, slots=False)
class AzureDbCollection:
    kind: ClassVar[str] = "azure_db_collection"
    mapping: ClassVar[Dict[str, Bender]] = {"collection": S("collection"), "db": S("db")}
    collection: Optional[str] = field(default=None, metadata={'description': 'The collection name the role is applied.'})  # fmt: skip
    db: Optional[str] = field(default=None, metadata={"description": "The database name the role is applied."})


@define(eq=False, slots=False)
class AzurePrivilege:
    kind: ClassVar[str] = "azure_privilege"
    mapping: ClassVar[Dict[str, Bender]] = {
        "actions": S("actions"),
        "resource": S("resource") >> Bend(AzureDbCollection.mapping),
    }
    actions: Optional[List[str]] = field(
        default=None, metadata={"description": "An array of actions that are allowed."}
    )
    resource: Optional[AzureDbCollection] = field(default=None, metadata={'description': 'An Azure Cosmos DB Mongo DB Resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRole:
    kind: ClassVar[str] = "azure_role"
    mapping: ClassVar[Dict[str, Bender]] = {"db": S("db"), "role": S("role")}
    db: Optional[str] = field(default=None, metadata={"description": "The database name the role is applied."})
    role: Optional[str] = field(default=None, metadata={"description": "The role name."})


@define(eq=False, slots=False)
class AzureCosmosDBMongoDBRoleDefinition(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_mongo_db_role_definition"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "database_name": S("properties", "databaseName"),
        "definition_privileges": S("properties", "privileges") >> ForallBend(AzurePrivilege.mapping),
        "role_name": S("properties", "roleName"),
        "definition_roles": S("properties", "roles") >> ForallBend(AzureRole.mapping),
    }
    database_name: Optional[str] = field(default=None, metadata={'description': 'The database name for which access is being granted for this Role Definition.'})  # fmt: skip
    definition_privileges: Optional[List[AzurePrivilege]] = field(default=None, metadata={'description': 'A set of privileges contained by the Role Definition. This will allow application of this Role Definition on the entire database account or any underlying Database / Collection. Scopes higher than Database are not enforceable as privilege.'})  # fmt: skip
    role_name: Optional[str] = field(default=None, metadata={'description': 'A user-friendly name for the Role Definition. Must be unique for the database account.'})  # fmt: skip
    definition_roles: Optional[List[AzureRole]] = field(default=None, metadata={'description': 'The set of roles inherited by this Role Definition.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBMongoDBUserDefinition(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_mongo_db_user_definition"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "custom_data": S("properties", "customData"),
        "database_name": S("properties", "databaseName"),
        "user_mechanisms": S("properties", "mechanisms"),
        "user_password": S("properties", "password"),
        "user_roles": S("properties", "roles") >> ForallBend(AzureRole.mapping),
        "user_name": S("properties", "userName"),
    }
    custom_data: Optional[str] = field(default=None, metadata={'description': 'A custom definition for the USer Definition.'})  # fmt: skip
    database_name: Optional[str] = field(default=None, metadata={'description': 'The database name for which access is being granted for this User Definition.'})  # fmt: skip
    user_mechanisms: Optional[str] = field(default=None, metadata={'description': 'The Mongo Auth mechanism. For now, we only support auth mechanism SCRAM-SHA-256.'})  # fmt: skip
    user_password: Optional[str] = field(default=None, metadata={'description': 'The password for User Definition. Response does not contain user password.'})  # fmt: skip
    user_roles: Optional[List[AzureRole]] = field(default=None, metadata={'description': 'The set of roles inherited by the User Definition.'})  # fmt: skip
    user_name: Optional[str] = field(default=None, metadata={"description": "The user name for User Definition."})


@define(eq=False, slots=False)
class AzureCosmosDBNotebookWorkspace(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_notebook_workspace"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "notebook_server_endpoint": S("properties", "notebookServerEndpoint"),
        "status": S("properties", "status"),
    }
    notebook_server_endpoint: Optional[str] = field(default=None, metadata={'description': 'Specifies the endpoint of Notebook server.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Status of the notebook workspace. Possible values are: Creating, Online, Deleting, Failed, Updating.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBPrivateLinkResource(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_private_link_resource"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "link_group_id": S("properties", "groupId"),
        "required_members": S("properties", "requiredMembers"),
        "required_zone_names": S("properties", "requiredZoneNames"),
    }
    link_group_id: Optional[str] = field(default=None, metadata={"description": "The private link resource group id."})
    required_members: Optional[List[str]] = field(default=None, metadata={'description': 'The private link resource required member names.'})  # fmt: skip
    required_zone_names: Optional[List[str]] = field(default=None, metadata={'description': 'The private link resource required zone names.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorableLocationResource:
    kind: ClassVar[str] = "azure_restorable_location_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "creation_time": S("creationTime"),
        "deletion_time": S("deletionTime"),
        "location_name": S("locationName"),
        "regional_database_account_instance_id": S("regionalDatabaseAccountInstanceId"),
    }
    creation_time: Optional[datetime] = field(default=None, metadata={'description': 'The creation time of the regional restorable database account (ISO-8601 format).'})  # fmt: skip
    deletion_time: Optional[datetime] = field(default=None, metadata={'description': 'The time at which the regional restorable database account has been deleted (ISO-8601 format).'})  # fmt: skip
    location_name: Optional[str] = field(default=None, metadata={'description': 'The location of the regional restorable account.'})  # fmt: skip
    regional_database_account_instance_id: Optional[str] = field(default=None, metadata={'description': 'The instance id of the regional restorable account.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableAccount(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_account"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="cosmos-db",
        version="2024-05-15",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/restorableDatabaseAccounts",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "azure_cosmos_db_restorable_gremlin_database",
                "azure_cosmos_db_restorable_gremlin_graph",
                "azure_cosmos_db_restorable_gremlin_resource",
                "azure_cosmos_db_restorable_mongo_db_collection",
                "azure_cosmos_db_restorable_mongo_db_database",
                "azure_cosmos_db_restorable_mongo_db_resource",
                "azure_cosmos_db_restorable_sql_container",
                "azure_cosmos_db_restorable_sql_database",
                "azure_cosmos_db_restorable_sql_resource",
                "azure_cosmos_db_restorable_table",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "account_name": S("properties", "accountName"),
        "api_type": S("properties", "apiType"),
        "ctime": S("properties", "creationTime"),
        "creation_time": S("properties", "creationTime"),
        "deletion_time": S("properties", "deletionTime"),
        "oldest_restorable_time": S("properties", "oldestRestorableTime"),
        "restorable_locations": S("properties", "restorableLocations")
        >> ForallBend(AzureRestorableLocationResource.mapping),
    }
    account_name: Optional[str] = field(default=None, metadata={'description': 'The name of the global database account'})  # fmt: skip
    api_type: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the API type of the restorable database account.'})  # fmt: skip
    creation_time: Optional[datetime] = field(default=None, metadata={'description': 'The creation time of the restorable database account (ISO-8601 format).'})  # fmt: skip
    deletion_time: Optional[datetime] = field(default=None, metadata={'description': 'The time at which the restorable database account has been deleted (ISO-8601 format).'})  # fmt: skip
    oldest_restorable_time: Optional[datetime] = field(default=None, metadata={'description': 'The least recent time at which the database account can be restored to (ISO-8601 format).'})  # fmt: skip
    restorable_locations: Optional[List[AzureRestorableLocationResource]] = field(default=None, metadata={'description': 'List of regions where the of the database account can be restored from.'})  # fmt: skip

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        account_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{account_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="cosmos-db",
            version="2024-05-15",
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
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if account_id := self.id:
            resources_to_collect = [
                ("restorableGremlinDatabases", AzureCosmosDBRestorableGremlinDatabase, None),
                ("restorableGraphs", AzureCosmosDBRestorableGremlinGraph, None),
                ("restorableGremlinResources", AzureCosmosDBRestorableGremlinResource, None),
                ("restorableMongodbCollections", AzureCosmosDBRestorableMongoDBCollection, None),
                ("restorableMongodbDatabases", AzureCosmosDBRestorableMongoDBDatabase, None),
                ("restorableMongodbResources", AzureCosmosDBRestorableMongoDBResource, None),
                ("restorableSqlContainers", AzureCosmosDBRestorableSqlContainer, None),
                ("restorableSqlDatabases", AzureCosmosDBRestorableSqlDatabase, None),
                ("restorableSqlResources", AzureCosmosDBRestorableSqlResource, None),
                ("restorableTables", AzureCosmosDBRestorableTable, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    account_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )


@define(eq=False, slots=False)
class AzureClientEncryptionIncludedPath:
    kind: ClassVar[str] = "azure_client_encryption_included_path"
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_encryption_key_id": S("clientEncryptionKeyId"),
        "encryption_algorithm": S("encryptionAlgorithm"),
        "encryption_type": S("encryptionType"),
        "path": S("path"),
    }
    client_encryption_key_id: Optional[str] = field(default=None, metadata={'description': 'The identifier of the Client Encryption Key to be used to encrypt the path.'})  # fmt: skip
    encryption_algorithm: Optional[str] = field(default=None, metadata={'description': 'The encryption algorithm which will be used. Eg - AEAD_AES_256_CBC_HMAC_SHA256.'})  # fmt: skip
    encryption_type: Optional[str] = field(default=None, metadata={'description': 'The type of encryption to be performed. Eg - Deterministic, Randomized.'})  # fmt: skip
    path: Optional[str] = field(default=None, metadata={"description": "Path that needs to be encrypted."})


@define(eq=False, slots=False)
class AzureClientEncryptionPolicy:
    kind: ClassVar[str] = "azure_client_encryption_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "included_paths": S("includedPaths") >> ForallBend(AzureClientEncryptionIncludedPath.mapping),
        "policy_format_version": S("policyFormatVersion"),
    }
    included_paths: Optional[List[AzureClientEncryptionIncludedPath]] = field(default=None, metadata={'description': 'Paths of the item that need encryption along with path-specific settings.'})  # fmt: skip
    policy_format_version: Optional[int] = field(default=None, metadata={'description': 'Version of the client encryption policy definition. Supported versions are 1 and 2. Version 2 supports id and partition key path encryption. '})  # fmt: skip


@define(eq=False, slots=False)
class AzureComputedProperty:
    kind: ClassVar[str] = "azure_computed_property"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "query": S("query")}
    name: Optional[str] = field(default=None, metadata={'description': 'The name of a computed property, for example - cp_lowerName '})  # fmt: skip
    query: Optional[str] = field(default=None, metadata={'description': 'The query that evaluates the value for computed property, for example - SELECT VALUE LOWER(c.name) FROM c '})  # fmt: skip


@define(eq=False, slots=False)
class AzureSqlContainerResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_sql_container_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {
        "analytical_storage_ttl": S("analyticalStorageTtl"),
        "client_encryption_policy": S("clientEncryptionPolicy") >> Bend(AzureClientEncryptionPolicy.mapping),
        "computed_properties": S("computedProperties") >> ForallBend(AzureComputedProperty.mapping),
        "conflict_resolution_policy": S("conflictResolutionPolicy") >> Bend(AzureConflictResolutionPolicy.mapping),
        "create_mode": S("createMode"),
        "default_ttl": S("defaultTtl"),
        "id": S("id"),
        "indexing_policy": S("indexingPolicy") >> Bend(AzureIndexingPolicy.mapping),
        "partition_key": S("partitionKey") >> Bend(AzureContainerPartitionKey.mapping),
        "restore_parameters": S("restoreParameters") >> Bend(AzureResourceRestoreParameters.mapping),
        "unique_key_policy": S("uniqueKeyPolicy") >> Bend(AzureUniqueKeyPolicy.mapping),
    }
    analytical_storage_ttl: Optional[int] = field(default=None, metadata={"description": "Analytical TTL."})
    client_encryption_policy: Optional[AzureClientEncryptionPolicy] = field(default=None, metadata={'description': 'Cosmos DB client encryption policy.'})  # fmt: skip
    computed_properties: Optional[List[AzureComputedProperty]] = field(default=None, metadata={'description': 'List of computed properties'})  # fmt: skip
    conflict_resolution_policy: Optional[AzureConflictResolutionPolicy] = field(default=None, metadata={'description': 'The conflict resolution policy for the container.'})  # fmt: skip
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the mode of account creation.'})  # fmt: skip
    default_ttl: Optional[int] = field(default=None, metadata={"description": "Default time to live"})
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB SQL container"})
    indexing_policy: Optional[AzureIndexingPolicy] = field(default=None, metadata={'description': 'Cosmos DB indexing policy'})  # fmt: skip
    partition_key: Optional[AzureContainerPartitionKey] = field(default=None, metadata={'description': 'The configuration of the partition key to be used for partitioning data into multiple partitions'})  # fmt: skip
    restore_parameters: Optional[AzureResourceRestoreParameters] = field(default=None, metadata={'description': 'Parameters to indicate the information about the restore.'})  # fmt: skip
    unique_key_policy: Optional[AzureUniqueKeyPolicy] = field(default=None, metadata={'description': 'The unique key policy configuration for specifying uniqueness constraints on documents in the collection in the Azure Cosmos DB service.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBSqlDatabaseContainer(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_sql_database_container"
    # Collect via AzureCosmosDBSqlDatabase()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "sql_database_container_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "sql_database_container": S("properties", "resource") >> Bend(AzureSqlContainerResource.mapping),
    }
    sql_database_container_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    sql_database_container: Optional[AzureSqlContainerResource] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureSqlDatabaseResource:
    kind: ClassVar[str] = "azure_sql_database_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "create_mode": S("createMode"),
        "id": S("id"),
        "restore_parameters": S("restoreParameters") >> Bend(AzureResourceRestoreParameters.mapping),
    }
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the mode of account creation.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB SQL database"})
    restore_parameters: Optional[AzureResourceRestoreParameters] = field(default=None, metadata={'description': 'Parameters to indicate the information about the restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCollsUsers(AzureSqlDatabaseResource, AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_colls_users"
    mapping: ClassVar[Dict[str, Bender]] = (
        AzureSqlDatabaseResource.mapping | AzureCosmosDBResource.mapping | {"colls": S("_colls"), "users": S("_users")}
    )
    colls: Optional[str] = field(default=None, metadata={'description': 'A system generated property that specified the addressable path of the collections resource.'})  # fmt: skip
    users: Optional[str] = field(default=None, metadata={'description': 'A system generated property that specifies the addressable path of the users resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBSqlDatabase(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_sql_database"
    # Collect via AzureCosmosDBAccount()
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                AzureCosmosDBSqlDatabaseContainer.kind,
                AzureCosmosDBSqlDatabaseClientEncryptionKey.kind,
                "azure_cosmos_db_sql_throughput_setting",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "sql_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "sql_database": S("properties", "resource") >> Bend(AzureCollsUsers.mapping),
    }
    sql_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    sql_database: Optional[AzureCollsUsers] = field(default=None, metadata={"description": ""})

    def _collect_items(
        self,
        graph_builder: GraphBuilder,
        database_id: str,
        resource_type: str,
        class_instance: MicrosoftResource,
        expected_errors: Optional[List[str]] = None,
    ) -> None:
        path = f"{database_id}/{resource_type}"
        api_spec = AzureResourceSpec(
            service="cosmos-db",
            version="2024-05-15",
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
            graph_builder.add_edge(self, node=clazz)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if database_id := self.id:
            resources_to_collect = [
                ("containers", AzureCosmosDBSqlDatabaseContainer, None),
                ("clientEncryptionKeys", AzureCosmosDBSqlDatabaseClientEncryptionKey, None),
                ("throughputSettings/default", AzureCosmosDBSqlThroughputSetting, None),
            ]

            for resource_type, resource_class, expected_errors in resources_to_collect:
                graph_builder.submit_work(
                    service_name,
                    self._collect_items,
                    graph_builder,
                    database_id,
                    resource_type,
                    resource_class,
                    expected_errors,
                )


@define(eq=False, slots=False)
class AzureCosmosDBSqlRoleAssignment(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_sql_role_assignment"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "principal_id": S("properties", "principalId"),
        "role_definition_id": S("properties", "roleDefinitionId"),
        "scope": S("properties", "scope"),
    }
    principal_id: Optional[str] = field(default=None, metadata={'description': 'The unique identifier for the associated AAD principal in the AAD graph to which access is being granted through this Role Assignment. Tenant ID for the principal is inferred using the tenant associated with the subscription.'})  # fmt: skip
    role_definition_id: Optional[str] = field(default=None, metadata={'description': 'The unique identifier for the associated Role Definition.'})  # fmt: skip
    scope: Optional[str] = field(default=None, metadata={'description': 'The data plane resource path for which access is being granted through this Role Assignment.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRolePermission:
    kind: ClassVar[str] = "azure_role_permission"
    mapping: ClassVar[Dict[str, Bender]] = {"data_actions": S("dataActions"), "not_data_actions": S("notDataActions")}
    data_actions: Optional[List[str]] = field(default=None, metadata={'description': 'An array of data actions that are allowed.'})  # fmt: skip
    not_data_actions: Optional[List[str]] = field(default=None, metadata={'description': 'An array of data actions that are denied.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBSqlRoleDefinition(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_sql_role_definition"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "assignable_scopes": S("properties", "assignableScopes"),
        "role_permissions": S("properties", "permissions") >> ForallBend(AzureRolePermission.mapping),
        "role_name": S("properties", "roleName"),
    }
    assignable_scopes: Optional[List[str]] = field(default=None, metadata={'description': 'A set of fully qualified Scopes at or below which Role Assignments may be created using this Role Definition. This will allow application of this Role Definition on the entire database account or any underlying Database / Collection. Must have at least one element. Scopes higher than Database account are not enforceable as assignable Scopes. Note that resources referenced in assignable Scopes need not exist.'})  # fmt: skip
    role_permissions: Optional[List[AzureRolePermission]] = field(default=None, metadata={'description': 'The set of operations allowed through this Role Definition.'})  # fmt: skip
    role_name: Optional[str] = field(default=None, metadata={'description': 'A user-friendly name for the Role Definition. Must be unique for the database account.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureTableResource(AzureCosmosDBResource):
    kind: ClassVar[str] = "azure_table_resource"
    mapping: ClassVar[Dict[str, Bender]] = AzureCosmosDBResource.mapping | {
        "create_mode": S("createMode"),
        "id": S("id"),
        "restore_parameters": S("restoreParameters") >> Bend(AzureResourceRestoreParameters.mapping),
    }
    create_mode: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the mode of account creation.'})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Name of the Cosmos DB table"})
    restore_parameters: Optional[AzureResourceRestoreParameters] = field(default=None, metadata={'description': 'Parameters to indicate the information about the restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBTable(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_table"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "table_options": S("properties", "options") >> Bend(AzureOptionsResource.mapping),
        "table_resource": S("properties", "resource") >> Bend(AzureTableResource.mapping),
    }
    table_options: Optional[AzureOptionsResource] = field(default=None, metadata={"description": ""})
    table_resource: Optional[AzureTableResource] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureCosmosDBSqlThroughputSetting(MicrosoftResource, AzureARMResourceProperties):
    kind: ClassVar[str] = "azure_cosmos_db_sql_throughput_setting"
    # Collect via AzureCosmosDBSqlDatabase()
    mapping: ClassVar[Dict[str, Bender]] = AzureARMResourceProperties.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "sql_throughput_setting": S("properties", "resource") >> Bend(AzureCosmosDBResource.mapping),
    }
    sql_throughput_setting: Optional[AzureCosmosDBResource] = field(default=None, metadata={"description": ""})


@define(eq=False, slots=False)
class AzureCosmosDBAccountUsage(MicrosoftResource, AzureBaseUsage):
    kind: ClassVar[str] = "azure_cosmos_db_account_usage"
    # Collect via AzureCosmosDBAccount()
    mapping: ClassVar[Dict[str, Bender]] = AzureBaseUsage.mapping | {
        "id": K(None),
        "usage_quota_period": S("quotaPeriod"),
    }
    _is_provider_link: ClassVar[bool] = False
    usage_quota_period: Optional[str] = field(default=None, metadata={'description': 'The quota period used to summarize the usage values.'})  # fmt: skip

    @classmethod
    def collect_usages(cls, account_id: str, raw: List[Json], builder: GraphBuilder) -> List[AzureCosmosDBAccountUsage]:
        result = []
        for js in raw:
            # map from api
            if instance := cls.from_api(js, builder):
                # Set account id to resource id
                instance.id = account_id
                if (added := builder.add_node(instance, js)) is not None:
                    result.append(added)
        return result


@define(eq=False, slots=False)
class AzureLocationProperties:
    kind: ClassVar[str] = "azure_location_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "backup_storage_redundancies": S("backupStorageRedundancies"),
        "is_residency_restricted": S("isResidencyRestricted"),
        "is_subscription_region_access_allowed_for_az": S("isSubscriptionRegionAccessAllowedForAz"),
        "is_subscription_region_access_allowed_for_regular": S("isSubscriptionRegionAccessAllowedForRegular"),
        "status": S("status"),
        "supports_availability_zone": S("supportsAvailabilityZone"),
    }
    backup_storage_redundancies: Optional[List[str]] = field(default=None, metadata={'description': 'The properties of available backup storage redundancies.'})  # fmt: skip
    is_residency_restricted: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the location is residency sensitive.'})  # fmt: skip
    is_subscription_region_access_allowed_for_az: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the subscription have access in region for Availability Zones(Az).'})  # fmt: skip
    is_subscription_region_access_allowed_for_regular: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the subscription have access in region for Non-Availability Zones.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate current buildout status of the region.'})  # fmt: skip
    supports_availability_zone: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the location supports availability zones or not.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBLocation(MicrosoftResource, AzureARMProxyResource):
    kind: ClassVar[str] = "azure_cosmos_db_location"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="cosmos-db",
        version="2024-05-15",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/locations",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureARMProxyResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("id"),
        "backup_storage_redundancies": S("properties", "backupStorageRedundancies"),
        "is_residency_restricted": S("properties", "isResidencyRestricted"),
        "is_subscription_region_access_allowed_for_az": S("properties", "isSubscriptionRegionAccessAllowedForAz"),
        "is_subscription_region_access_allowed_for_regular": S(
            "properties", "isSubscriptionRegionAccessAllowedForRegular"
        ),
        "status": S("properties", "status"),
        "supports_availability_zone": S("properties", "supportsAvailabilityZone"),
    }
    backup_storage_redundancies: Optional[List[str]] = field(default=None, metadata={'description': 'The properties of available backup storage redundancies.'})  # fmt: skip
    is_residency_restricted: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the location is residency sensitive.'})  # fmt: skip
    is_subscription_region_access_allowed_for_az: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the subscription have access in region for Availability Zones(Az).'})  # fmt: skip
    is_subscription_region_access_allowed_for_regular: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the subscription have access in region for Non-Availability Zones.'})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate current buildout status of the region.'})  # fmt: skip
    supports_availability_zone: Optional[bool] = field(default=None, metadata={'description': 'Flag indicating whether the location supports availability zones or not.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureMongoClusterRestoreParameters:
    kind: ClassVar[str] = "azure_mongo_cluster_restore_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {
        "point_in_time_utc": S("pointInTimeUTC"),
        "source_resource_id": S("sourceResourceId"),
    }
    point_in_time_utc: Optional[datetime] = field(default=None, metadata={'description': 'UTC point in time to restore a mongo cluster'})  # fmt: skip
    source_resource_id: Optional[str] = field(default=None, metadata={'description': 'Resource ID to locate the source cluster to restore'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNodeGroupProperties:
    kind: ClassVar[str] = "azure_node_group_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disk_size_gb": S("diskSizeGB"),
        "enable_ha": S("enableHa"),
        "sku": S("sku"),
    }
    disk_size_gb: Optional[int] = field(default=None, metadata={'description': 'The disk storage size for the node group in GB. Example values: 128, 256, 512, 1024.'})  # fmt: skip
    enable_ha: Optional[bool] = field(default=None, metadata={'description': 'Whether high availability is enabled on the node group.'})  # fmt: skip
    sku: Optional[str] = field(default=None, metadata={'description': 'The resource sku for the node group. This defines the size of CPU and memory that is provisioned for each node. Example values: M30 , M40 .'})  # fmt: skip


@define(eq=False, slots=False)
class AzureNodeGroupSpec(AzureNodeGroupProperties):
    kind: ClassVar[str] = "azure_node_group_spec"
    mapping: ClassVar[Dict[str, Bender]] = AzureNodeGroupProperties.mapping | {
        "node_kind": S("kind"),
        "node_count": S("nodeCount"),
    }
    node_kind: Optional[str] = field(default=None, metadata={"description": "The kind of a node in the mongo cluster."})
    node_count: Optional[int] = field(default=None, metadata={"description": "The number of nodes in the node group."})


@define(eq=False, slots=False)
class AzureMongoClusterProperties:
    kind: ClassVar[str] = "azure_mongo_cluster_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "administrator_login": S("administratorLogin"),
        "administrator_login_password": S("administratorLoginPassword"),
        "cluster_status": S("clusterStatus"),
        "connection_string": S("connectionString"),
        "create_mode": S("createMode"),
        "earliest_restore_time": S("earliestRestoreTime"),
        "node_group_specs": S("nodeGroupSpecs") >> ForallBend(AzureNodeGroupSpec.mapping),
        "provisioning_state": S("provisioningState"),
        "restore_parameters": S("restoreParameters") >> Bend(AzureMongoClusterRestoreParameters.mapping),
        "server_version": S("serverVersion"),
    }
    administrator_login: Optional[str] = field(default=None, metadata={'description': 'The administrator s login for the mongo cluster.'})  # fmt: skip
    administrator_login_password: Optional[str] = field(default=None, metadata={'description': 'The password of the administrator login.'})  # fmt: skip
    cluster_status: Optional[str] = field(default=None, metadata={'description': 'The status of the resource at the time the operation was called.'})  # fmt: skip
    connection_string: Optional[str] = field(default=None, metadata={'description': 'The default mongo connection string for the cluster.'})  # fmt: skip
    create_mode: Optional[str] = field(default=None, metadata={"description": "The mode to create a mongo cluster."})
    earliest_restore_time: Optional[str] = field(default=None, metadata={'description': 'Earliest restore timestamp in UTC ISO8601 format.'})  # fmt: skip
    node_group_specs: Optional[List[AzureNodeGroupSpec]] = field(default=None, metadata={'description': 'The list of node group specifications for the cluster. Must include one node group spec with kind = Shard .'})  # fmt: skip
    restore_parameters: Optional[AzureMongoClusterRestoreParameters] = field(default=None, metadata={'description': 'Parameters used for restore operations'})  # fmt: skip
    server_version: Optional[str] = field(default=None, metadata={'description': 'The Mongo DB server version. Defaults to the latest available version if not specified.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBMongoDBCluster(MicrosoftResource, AzureTrackedResource):
    kind: ClassVar[str] = "azure_cosmos_db_mongo_db_cluster"
    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec(
        service="cosmos-db",
        version="2024-02-15-preview",
        path="/subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/mongoClusters",
        path_parameters=["subscriptionId"],
        query_parameters=["api-version"],
        access_path="value",
        expect_array=True,
    )
    mapping: ClassVar[Dict[str, Bender]] = AzureTrackedResource.mapping | {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("id"),
        "administrator_login": S("properties", "administratorLogin"),
        "administrator_login_password": S("properties", "administratorLoginPassword"),
        "cluster_status": S("properties", "clusterStatus"),
        "connection_string": S("properties", "connectionString"),
        "create_mode": S("properties", "createMode"),
        "earliest_restore_time": S("properties", "earliestRestoreTime"),
        "node_group_specs": S("properties", "nodeGroupSpecs") >> ForallBend(AzureNodeGroupSpec.mapping),
        "provisioning_state": S("properties", "provisioningState"),
        "cluster_restore_parameters": S("properties", "restoreParameters")
        >> Bend(AzureMongoClusterRestoreParameters.mapping),
        "server_version": S("properties", "serverVersion"),
    }
    administrator_login: Optional[str] = field(default=None, metadata={'description': 'The administrator s login for the mongo cluster.'})  # fmt: skip
    administrator_login_password: Optional[str] = field(default=None, metadata={'description': 'The password of the administrator login.'})  # fmt: skip
    cluster_status: Optional[str] = field(default=None, metadata={'description': 'The status of the resource at the time the operation was called.'})  # fmt: skip
    connection_string: Optional[str] = field(default=None, metadata={'description': 'The default mongo connection string for the cluster.'})  # fmt: skip
    create_mode: Optional[str] = field(default=None, metadata={"description": "The mode to create a mongo cluster."})
    earliest_restore_time: Optional[str] = field(default=None, metadata={'description': 'Earliest restore timestamp in UTC ISO8601 format.'})  # fmt: skip
    node_group_specs: Optional[List[AzureNodeGroupSpec]] = field(default=None, metadata={'description': 'The list of node group specifications for the cluster. Must include one node group spec with kind = Shard .'})  # fmt: skip
    cluster_restore_parameters: Optional[AzureMongoClusterRestoreParameters] = field(default=None, metadata={'description': 'Parameters used for restore operations'})  # fmt: skip
    server_version: Optional[str] = field(default=None, metadata={'description': 'The Mongo DB server version. Defaults to the latest available version if not specified.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorableResourceProperties:
    kind: ClassVar[str] = "azure_restorable_database_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rid": S("_rid"),
        "can_undelete": S("canUndelete"),
        "can_undelete_reason": S("canUndeleteReason"),
        "event_timestamp": S("eventTimestamp"),
        "operation_type": S("operationType"),
        "owner_id": S("ownerId"),
        "owner_resource_id": S("ownerResourceId"),
    }
    rid: Optional[str] = field(default=None, metadata={'description': 'A system generated property. A unique identifier.'})  # fmt: skip
    can_undelete: Optional[str] = field(default=None, metadata={'description': 'A state of this table to identify if this table is restorable in same account.'})  # fmt: skip
    can_undelete_reason: Optional[str] = field(default=None, metadata={'description': 'The reason why this table can not be restored in same account.'})  # fmt: skip
    event_timestamp: Optional[str] = field(default=None, metadata={'description': 'The time when this table event happened.'})  # fmt: skip
    operation_type: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the operation type of the event.'})  # fmt: skip
    owner_id: Optional[str] = field(default=None, metadata={"description": "The name of this Table."})
    owner_resource_id: Optional[str] = field(default=None, metadata={"description": "The resource ID of this Table."})


@define(eq=False, slots=False)
class AzureCosmosDBRestorableGremlinDatabase(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_gremlin_database"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "restorable_gremlin_database": S("properties", "resource") >> Bend(AzureRestorableResourceProperties.mapping),
    }
    restorable_gremlin_database: Optional[AzureRestorableResourceProperties] = field(default=None, metadata={'description': 'The resource of an Azure Cosmos DB Gremlin database event'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableGremlinGraph(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_gremlin_graph"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "restorable_gremlin_graph": S("properties", "resource") >> Bend(AzureRestorableResourceProperties.mapping),
    }
    restorable_gremlin_graph: Optional[AzureRestorableResourceProperties] = field(default=None, metadata={'description': 'The resource of an Azure Cosmos DB Gremlin graph event'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableGremlinResource(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_gremlin_resource"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "database_name": S("databaseName"),
        "graph_names": S("graphNames"),
    }
    database_name: Optional[str] = field(default=None, metadata={'description': 'The name of the gremlin database available for restore.'})  # fmt: skip
    graph_names: Optional[List[str]] = field(default=None, metadata={'description': 'The names of the graphs available for restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableMongoDBCollection(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_mongo_db_collection"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "restorable_mongodb_collection": S("properties", "resource") >> Bend(AzureRestorableResourceProperties.mapping),
    }
    restorable_mongodb_collection: Optional[AzureRestorableResourceProperties] = field(default=None, metadata={'description': 'The resource of an Azure Cosmos DB MongoDB collection event'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableMongoDBDatabase(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_mongo_db_database"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "restorable_mongodb_database": S("properties", "resource") >> Bend(AzureRestorableResourceProperties.mapping),
    }
    restorable_mongodb_database: Optional[AzureRestorableResourceProperties] = field(default=None, metadata={'description': 'The resource of an Azure Cosmos DB MongoDB database event'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableMongoDBResource(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_mongo_db_resource"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "collection_names": S("collectionNames"),
        "database_name": S("databaseName"),
    }
    collection_names: Optional[List[str]] = field(default=None, metadata={'description': 'The names of the collections available for restore.'})  # fmt: skip
    database_name: Optional[str] = field(default=None, metadata={'description': 'The name of the database available for restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorableResourcePropertiesContainer:
    kind: ClassVar[str] = (
        "azure_rid_operationtype_canundelete_canundeletereason_eventtimestamp_ownerid_ownerresourceid_container"
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "rid": S("_rid"),
        "can_undelete": S("canUndelete"),
        "can_undelete_reason": S("canUndeleteReason"),
        "container": S("container", "_self"),
        "event_timestamp": S("eventTimestamp"),
        "operation_type": S("operationType"),
        "owner_id": S("ownerId"),
        "owner_resource_id": S("ownerResourceId"),
    }
    rid: Optional[str] = field(default=None, metadata={'description': 'A system generated property. A unique identifier.'})  # fmt: skip
    can_undelete: Optional[str] = field(default=None, metadata={'description': 'A state of this container to identify if this container is restorable in same account.'})  # fmt: skip
    can_undelete_reason: Optional[str] = field(default=None, metadata={'description': 'The reason why this container can not be restored in same account.'})  # fmt: skip
    container: Optional[str] = field(default=None, metadata={"description": "Cosmos DB SQL container resource object"})
    event_timestamp: Optional[str] = field(default=None, metadata={'description': 'The when this container event happened.'})  # fmt: skip
    operation_type: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the operation type of the event.'})  # fmt: skip
    owner_id: Optional[str] = field(default=None, metadata={"description": "The name of this SQL container."})
    owner_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of this SQL container.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableSqlContainer(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_sql_container"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "restorable_sql_container": S("properties", "resource")
        >> Bend(AzureRestorableResourcePropertiesContainer.mapping),
    }
    restorable_sql_container: Optional[AzureRestorableResourcePropertiesContainer] = field(default=None, metadata={'description': 'The resource of an Azure Cosmos DB SQL container event'})  # fmt: skip


@define(eq=False, slots=False)
class AzureExtendedResourcePropertiesSqlDatabaseResource(AzureSqlDatabaseResource, AzureExtendedResourceProperties):
    kind: ClassVar[str] = "azure_extended_resource_properties_sql_database_resource"
    mapping: ClassVar[Dict[str, Bender]] = (
        AzureSqlDatabaseResource.mapping
        | AzureExtendedResourceProperties.mapping
        | {"colls": S("_colls"), "database_self": S("_self"), "users": S("_users")}
    )
    colls: Optional[str] = field(default=None, metadata={'description': 'A system generated property that specified the addressable path of the collections resource.'})  # fmt: skip
    database_self: Optional[str] = field(default=None, metadata={'description': 'A system generated property that specifies the addressable path of the database resource.'})  # fmt: skip
    users: Optional[str] = field(default=None, metadata={'description': 'A system generated property that specifies the addressable path of the users resource.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureRestorableResourcePropertiesDatabase:
    kind: ClassVar[str] = "azure_restorable_database_database"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rid": S("_rid"),
        "can_undelete": S("canUndelete"),
        "can_undelete_reason": S("canUndeleteReason"),
        "database": S("database") >> Bend(AzureExtendedResourcePropertiesSqlDatabaseResource.mapping),
        "event_timestamp": S("eventTimestamp"),
        "operation_type": S("operationType"),
        "owner_id": S("ownerId"),
        "owner_resource_id": S("ownerResourceId"),
    }
    rid: Optional[str] = field(default=None, metadata={'description': 'A system generated property. A unique identifier.'})  # fmt: skip
    can_undelete: Optional[str] = field(default=None, metadata={'description': 'A state of this database to identify if this database is restorable in same account.'})  # fmt: skip
    can_undelete_reason: Optional[str] = field(default=None, metadata={'description': 'The reason why this database can not be restored in same account.'})  # fmt: skip
    database: Optional[AzureExtendedResourcePropertiesSqlDatabaseResource] = field(default=None, metadata={'description': 'Cosmos DB SQL database resource object'})  # fmt: skip
    event_timestamp: Optional[str] = field(default=None, metadata={'description': 'The time when this database event happened.'})  # fmt: skip
    operation_type: Optional[str] = field(default=None, metadata={'description': 'Enum to indicate the operation type of the event.'})  # fmt: skip
    owner_id: Optional[str] = field(default=None, metadata={"description": "The name of the SQL database."})
    owner_resource_id: Optional[str] = field(default=None, metadata={'description': 'The resource ID of the SQL database.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableSqlDatabase(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_sql_database"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "restorable_sql_database": S("properties", "resource")
        >> Bend(AzureRestorableResourcePropertiesDatabase.mapping),
    }
    restorable_sql_database: Optional[AzureRestorableResourcePropertiesDatabase] = field(default=None, metadata={'description': 'The resource of an Azure Cosmos DB SQL database event'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableSqlResource(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_sql_resource"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "collection_names": S("collectionNames"),
        "database_name": S("databaseName"),
    }
    collection_names: Optional[List[str]] = field(default=None, metadata={'description': 'The names of the collections available for restore.'})  # fmt: skip
    database_name: Optional[str] = field(default=None, metadata={'description': 'The name of the database available for restore.'})  # fmt: skip


@define(eq=False, slots=False)
class AzureCosmosDBRestorableTable(MicrosoftResource):
    kind: ClassVar[str] = "azure_cosmos_db_restorable_table"
    # Collect via AzureCosmosDBRestorableAccount()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "restorable_table_resource": S("properties", "resource") >> Bend(AzureRestorableResourceProperties.mapping),
    }
    restorable_table_resource: Optional[AzureRestorableResourceProperties] = field(default=None, metadata={'description': 'The resource of an Azure Cosmos DB Table event'})  # fmt: skip


resources: List[Type[MicrosoftResource]] = [
    AzureCosmosDBCassandraClusterPublicStatus,
    AzureCosmosDBCassandraKeyspace,
    AzureCosmosDBCassandraTable,
    AzureCosmosDBCassandraCluster,
    AzureCosmosDBCassandraClusterDataCenter,
    AzureCosmosDBAccount,
    AzureCosmosDBAccountReadOnlyKeys,
    AzureCosmosDBGremlinDatabase,
    AzureCosmosDBGremlinGraph,
    AzureCosmosDBMongoDBCollection,
    AzureCosmosDBMongoDBDatabase,
    AzureCosmosDBMongoDBRoleDefinition,
    AzureCosmosDBMongoDBUserDefinition,
    AzureCosmosDBNotebookWorkspace,
    AzureCosmosDBPrivateLinkResource,
    AzureCosmosDBSqlDatabaseClientEncryptionKey,
    AzureCosmosDBSqlDatabaseContainer,
    AzureCosmosDBSqlDatabase,
    AzureCosmosDBSqlRoleAssignment,
    AzureCosmosDBSqlRoleDefinition,
    AzureCosmosDBTable,
    AzureCosmosDBSqlThroughputSetting,
    AzureCosmosDBAccountUsage,
    AzureCosmosDBLocation,
    AzureCosmosDBMongoDBCluster,
    AzureCosmosDBRestorableAccount,
    AzureCosmosDBRestorableGremlinDatabase,
    AzureCosmosDBRestorableGremlinGraph,
    AzureCosmosDBRestorableGremlinResource,
    AzureCosmosDBRestorableMongoDBCollection,
    AzureCosmosDBRestorableMongoDBDatabase,
    AzureCosmosDBRestorableMongoDBResource,
    AzureCosmosDBRestorableSqlContainer,
    AzureCosmosDBRestorableSqlDatabase,
    AzureCosmosDBRestorableSqlResource,
    AzureCosmosDBRestorableTable,
]
