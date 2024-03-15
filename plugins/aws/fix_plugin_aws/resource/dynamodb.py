from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Type, Any
from attrs import define, field
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.kinesis import AwsKinesisStream
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import S, Bend, Bender, ForallBend, bend
from fixlib.types import Json

service_name = "dynamodb"


# noinspection PyUnresolvedReferences
class DynamoDbTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="tag-resource",
                result_name=None,
                ResourceArn=self.arn,
                Tags=[{"Key": key, "Value": value}],
            )
            return True
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="untag-resource",
                result_name=None,
                ResourceArn=self.arn,
                TagKeys=[key],
            )
            return True
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "tag-resource"), AwsApiSpec(service_name, "untag-resource")]


@define(eq=False, slots=False)
class AwsDynamoDbAttributeDefinition:
    kind: ClassVar[str] = "aws_dynamodb_attribute_definition"
    kind_display: ClassVar[str] = "AWS DynamoDB Attribute Definition"
    kind_description: ClassVar[str] = (
        "An attribute definition in AWS DynamoDB describes the data type and name of an attribute for a table."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"attribute_name": S("AttributeName"), "attribute_type": S("AttributeType")}
    attribute_name: Optional[str] = field(default=None)
    attribute_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbKeySchemaElement:
    kind: ClassVar[str] = "aws_dynamodb_key_schema_element"
    kind_display: ClassVar[str] = "AWS DynamoDB Key Schema Element"
    kind_description: ClassVar[str] = (
        "DynamoDB Key Schema Element represents the key attributes used to uniquely"
        " identify an item in a DynamoDB table."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"attribute_name": S("AttributeName"), "key_type": S("KeyType")}
    attribute_name: Optional[str] = field(default=None)
    key_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbProvisionedThroughputDescription:
    kind: ClassVar[str] = "aws_dynamodb_provisioned_throughput_description"
    kind_display: ClassVar[str] = "AWS DynamoDB Provisioned Throughput Description"
    kind_description: ClassVar[str] = (
        "DynamoDB Provisioned Throughput is the measurement of the capacity"
        " provisioned to handle request traffic for a DynamoDB table. It determines"
        " the read and write capacity units available for the table."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_increase_date_time": S("LastIncreaseDateTime"),
        "last_decrease_date_time": S("LastDecreaseDateTime"),
        "number_of_decreases_today": S("NumberOfDecreasesToday"),
        "read_capacity_units": S("ReadCapacityUnits"),
        "write_capacity_units": S("WriteCapacityUnits"),
    }
    last_increase_date_time: Optional[datetime] = field(default=None)
    last_decrease_date_time: Optional[datetime] = field(default=None)
    number_of_decreases_today: Optional[int] = field(default=None)
    read_capacity_units: Optional[int] = field(default=None)
    write_capacity_units: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbBillingModeSummary:
    kind: ClassVar[str] = "aws_dynamodb_billing_mode_summary"
    kind_display: ClassVar[str] = "AWS DynamoDB Billing Mode Summary"
    kind_description: ClassVar[str] = (
        "DynamoDB Billing Mode Summary provides information about the billing mode"
        " configured for DynamoDB tables in AWS. DynamoDB is a NoSQL database service"
        " provided by Amazon."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "billing_mode": S("BillingMode"),
        "last_update_to_pay_per_request_date_time": S("LastUpdateToPayPerRequestDateTime"),
    }
    billing_mode: Optional[str] = field(default=None)
    last_update_to_pay_per_request_date_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbProjection:
    kind: ClassVar[str] = "aws_dynamodb_projection"
    kind_display: ClassVar[str] = "AWS DynamoDB Projection"
    kind_description: ClassVar[str] = (
        "AWS DynamoDB Projection specifies the set of attributes that are projected into a DynamoDB secondary"
        " index, which can be keys only, a selection of attributes, or all attributes from the base table."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "projection_type": S("ProjectionType"),
        "non_key_attributes": S("NonKeyAttributes", default=[]),
    }
    projection_type: Optional[str] = field(default=None)
    non_key_attributes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsDynamoDbLocalSecondaryIndexDescription:
    kind: ClassVar[str] = "aws_dynamodb_local_secondary_index_description"
    kind_display: ClassVar[str] = "AWS DynamoDB Local Secondary Index Description"
    kind_description: ClassVar[str] = (
        "The AWS DynamoDB Local Secondary Index Description provides details about a Local Secondary Index (LSI)"
        " associated with a DynamoDB table. This includes information such as the index name, the key schema, the"
        " projection, and throughput information if provisioned throughput is specified."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "index_name": S("IndexName"),
        "key_schema": S("KeySchema", default=[]) >> ForallBend(AwsDynamoDbKeySchemaElement.mapping),
        "projection": S("Projection") >> Bend(AwsDynamoDbProjection.mapping),
        "index_size_bytes": S("IndexSizeBytes"),
        "item_count": S("ItemCount"),
        "index_arn": S("IndexArn"),
    }
    index_name: Optional[str] = field(default=None)
    key_schema: List[AwsDynamoDbKeySchemaElement] = field(factory=list)
    projection: Optional[AwsDynamoDbProjection] = field(default=None)
    index_size_bytes: Optional[int] = field(default=None)
    item_count: Optional[int] = field(default=None)
    index_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbGlobalSecondaryIndexDescription:
    kind: ClassVar[str] = "aws_dynamodb_global_secondary_index_description"
    kind_display: ClassVar[str] = "AWS DynamoDB Global Secondary Index Description"
    kind_description: ClassVar[str] = (
        "A Global Secondary Index (GSI) in DynamoDB is an additional index that you"
        " can create on your table to support fast and efficient data access patterns."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "index_name": S("IndexName"),
        "key_schema": S("KeySchema", default=[]) >> ForallBend(AwsDynamoDbKeySchemaElement.mapping),
        "projection": S("Projection") >> Bend(AwsDynamoDbProjection.mapping),
        "index_status": S("IndexStatus"),
        "backfilling": S("Backfilling"),
        "provisioned_throughput": S("ProvisionedThroughput")
        >> Bend(AwsDynamoDbProvisionedThroughputDescription.mapping),
        "index_size_bytes": S("IndexSizeBytes"),
        "item_count": S("ItemCount"),
        "index_arn": S("IndexArn"),
    }
    index_name: Optional[str] = field(default=None)
    key_schema: List[AwsDynamoDbKeySchemaElement] = field(factory=list)
    projection: Optional[AwsDynamoDbProjection] = field(default=None)
    index_status: Optional[str] = field(default=None)
    backfilling: Optional[bool] = field(default=None)
    provisioned_throughput: Optional[AwsDynamoDbProvisionedThroughputDescription] = field(default=None)
    index_size_bytes: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    item_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    index_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbStreamSpecification:
    kind: ClassVar[str] = "aws_dynamodb_stream_specification"
    kind_display: ClassVar[str] = "AWS DynamoDB Stream Specification"
    kind_description: ClassVar[str] = (
        "AWS DynamoDB Stream Specification defines whether a stream is enabled on a DynamoDB table and the"
        " type of information that will be written to the stream, such as keys only, new image, old image,"
        " or both new and old images of the item."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "stream_enabled": S("StreamEnabled"),
        "stream_view_type": S("StreamViewType"),
    }
    stream_enabled: Optional[bool] = field(default=None)
    stream_view_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbReplicaGlobalSecondaryIndexDescription:
    kind: ClassVar[str] = "aws_dynamodb_replica_global_secondary_index_description"
    kind_display: ClassVar[str] = "AWS DynamoDB Replica Global Secondary Index Description"
    kind_description: ClassVar[str] = (
        "The AWS DynamoDB Replica Global Secondary Index Description details the properties of a"
        " Global Secondary Index (GSI) on a replica table in a DynamoDB global table configuration."
        " It includes the index name, key schema, attribute projections, provisioned read and write"
        " capacity (if not using on-demand capacity), index status, and other metrics such as"
        " index size and item count. GSIs on replicas enable fast, efficient query performance"
        " across multiple geographically dispersed tables."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "index_name": S("IndexName"),
        "provisioned_throughput_override": S("ProvisionedThroughputOverride", "ReadCapacityUnits"),
    }
    index_name: Optional[str] = field(default=None)
    provisioned_throughput_override: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbTableClassSummary:
    kind: ClassVar[str] = "aws_dynamodb_table_class_summary"
    kind_display: ClassVar[str] = "AWS DynamoDB Table Class Summary"
    kind_description: ClassVar[str] = (
        "The AWS DynamoDB Table Class Summary provides an overview of the table class for"
        " a DynamoDB table, which reflects the cost and performance characteristics of the table."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "table_class": S("TableClass"),
        "last_update_date_time": S("LastUpdateDateTime"),
    }
    table_class: Optional[str] = field(default=None)
    last_update_date_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbReplicaDescription:
    kind: ClassVar[str] = "aws_dynamodb_replica_description"
    kind_display: ClassVar[str] = "AWS DynamoDB Replica Description"
    kind_description: ClassVar[str] = (
        "DynamoDB Replica Description provides detailed information about the replica"
        " configuration and status of an Amazon DynamoDB table in the AWS cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "region_name": S("RegionName"),
        "replica_status": S("ReplicaStatus"),
        "replica_status_description": S("ReplicaStatusDescription"),
        "replica_status_percent_progress": S("ReplicaStatusPercentProgress"),
        "kms_master_key_id": S("KMSMasterKeyId"),
        "provisioned_throughput_override": S("ProvisionedThroughputOverride", "ReadCapacityUnits"),
        "global_secondary_indexes": S("GlobalSecondaryIndexes", default=[])
        >> ForallBend(AwsDynamoDbReplicaGlobalSecondaryIndexDescription.mapping),
        "replica_inaccessible_date_time": S("ReplicaInaccessibleDateTime"),
        "replica_table_class_summary": S("ReplicaTableClassSummary") >> Bend(AwsDynamoDbTableClassSummary.mapping),
    }
    region_name: Optional[str] = field(default=None)
    replica_status: Optional[str] = field(default=None)
    replica_status_description: Optional[str] = field(default=None)
    replica_status_percent_progress: Optional[str] = field(default=None)
    kms_master_key_id: Optional[str] = field(default=None)
    provisioned_throughput_override: Optional[int] = field(default=None)
    global_secondary_indexes: List[AwsDynamoDbReplicaGlobalSecondaryIndexDescription] = field(factory=list)
    replica_inaccessible_date_time: Optional[datetime] = field(default=None)
    replica_table_class_summary: Optional[AwsDynamoDbTableClassSummary] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbRestoreSummary:
    kind: ClassVar[str] = "aws_dynamodb_restore_summary"
    kind_display: ClassVar[str] = "AWS DynamoDB Restore Summary"
    kind_description: ClassVar[str] = (
        "DynamoDB Restore Summary provides an overview of the restore process for"
        " Amazon DynamoDB backups, including information on restore progress,"
        " completion time, and any errors encountered during the restore."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "source_backup_arn": S("SourceBackupArn"),
        "source_table_arn": S("SourceTableArn"),
        "restore_date_time": S("RestoreDateTime"),
        "restore_in_progress": S("RestoreInProgress"),
    }
    source_backup_arn: Optional[str] = field(default=None)
    source_table_arn: Optional[str] = field(default=None)
    restore_date_time: Optional[datetime] = field(default=None)
    restore_in_progress: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbSSEDescription:
    kind: ClassVar[str] = "aws_dynamodb_sse_description"
    kind_display: ClassVar[str] = "AWS DynamoDB SSE Description"
    kind_description: ClassVar[str] = (
        "DynamoDB SSE (Server-Side Encryption) provides automatic encryption at rest"
        " for DynamoDB tables, ensuring data security and compliance with privacy"
        " regulations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("Status"),
        "sse_type": S("SSEType"),
        "kms_master_key_arn": S("KMSMasterKeyArn"),
        "inaccessible_encryption_date_time": S("InaccessibleEncryptionDateTime"),
    }
    status: Optional[str] = field(default=None)
    sse_type: Optional[str] = field(default=None)
    kms_master_key_arn: Optional[str] = field(default=None)
    inaccessible_encryption_date_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbArchivalSummary:
    kind: ClassVar[str] = "aws_dynamodb_archival_summary"
    kind_display: ClassVar[str] = "AWS DynamoDB Archival Summary"
    kind_description: ClassVar[str] = (
        "DynamoDB Archival Summary provides information about the archival status and"
        " details for DynamoDB tables in Amazon's cloud. Archival allows you to"
        " automatically store older data in a cost-effective manner while keeping"
        " active data readily available."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "archival_date_time": S("ArchivalDateTime"),
        "archival_reason": S("ArchivalReason"),
        "archival_backup_arn": S("ArchivalBackupArn"),
    }
    archival_date_time: Optional[datetime] = field(default=None)
    archival_reason: Optional[str] = field(default=None)
    archival_backup_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbTable(DynamoDbTaggable, AwsResource):
    kind: ClassVar[str] = "aws_dynamodb_table"
    kind_display: ClassVar[str] = "AWS DynamoDB Table"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/dynamodbv2/home?region={region}#table?name={name}", "arn_tpl": "arn:{partition}:dynamodb:{region}:{account}:table/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An AWS DynamoDB Table is a collection of data items organized by a primary key in Amazon DynamoDB,"
        " a fully managed NoSQL database service that provides fast and predictable performance with seamless"
        " scalability."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-tables", "TableNames")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_kinesis_stream", "aws_kms_key"]},
        "predecessors": {"delete": ["aws_kinesis_stream", "aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("TableId"),
        "name": S("TableName"),
        "ctime": S("CreationDateTime"),
        "arn": S("TableArn"),
        "dynamodb_attribute_definitions": S("AttributeDefinitions", default=[])
        >> ForallBend(AwsDynamoDbAttributeDefinition.mapping),
        "dynamodb_key_schema": S("KeySchema", default=[]) >> ForallBend(AwsDynamoDbKeySchemaElement.mapping),
        "dynamodb_table_status": S("TableStatus"),
        "dynamodb_provisioned_throughput": S("ProvisionedThroughput")
        >> Bend(AwsDynamoDbProvisionedThroughputDescription.mapping),
        "dynamodb_table_size_bytes": S("TableSizeBytes"),
        "dynamodb_item_count": S("ItemCount"),
        "dynamodb_billing_mode_summary": S("BillingModeSummary") >> Bend(AwsDynamoDbBillingModeSummary.mapping),
        "dynamodb_local_secondary_indexes": S("LocalSecondaryIndexes", default=[])
        >> ForallBend(AwsDynamoDbLocalSecondaryIndexDescription.mapping),
        "dynamodb_global_secondary_indexes": S("GlobalSecondaryIndexes", default=[])
        >> ForallBend(AwsDynamoDbGlobalSecondaryIndexDescription.mapping),
        "dynamodb_stream_specification": S("StreamSpecification") >> Bend(AwsDynamoDbStreamSpecification.mapping),
        "dynamodb_latest_stream_label": S("LatestStreamLabel"),
        "dynamodb_latest_stream_arn": S("LatestStreamArn"),
        "dynamodb_global_table_version": S("GlobalTableVersion"),
        "dynamodb_replicas": S("Replicas", default=[]) >> ForallBend(AwsDynamoDbReplicaDescription.mapping),
        "dynamodb_restore_summary": S("RestoreSummary") >> Bend(AwsDynamoDbRestoreSummary.mapping),
        "dynamodb_sse_description": S("SSEDescription") >> Bend(AwsDynamoDbSSEDescription.mapping),
        "dynamodb_archival_summary": S("ArchivalSummary") >> Bend(AwsDynamoDbArchivalSummary.mapping),
        "dynamodb_table_class_summary": S("TableClassSummary") >> Bend(AwsDynamoDbTableClassSummary.mapping),
    }
    arn: Optional[str] = field(default=None)
    dynamodb_attribute_definitions: List[AwsDynamoDbAttributeDefinition] = field(factory=list)
    dynamodb_key_schema: List[AwsDynamoDbKeySchemaElement] = field(factory=list)
    dynamodb_table_status: Optional[str] = field(default=None)
    dynamodb_provisioned_throughput: Optional[AwsDynamoDbProvisionedThroughputDescription] = field(default=None)
    dynamodb_table_size_bytes: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    dynamodb_item_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    dynamodb_billing_mode_summary: Optional[AwsDynamoDbBillingModeSummary] = field(default=None)
    dynamodb_local_secondary_indexes: List[AwsDynamoDbLocalSecondaryIndexDescription] = field(factory=list)
    dynamodb_global_secondary_indexes: List[AwsDynamoDbGlobalSecondaryIndexDescription] = field(factory=list)
    dynamodb_stream_specification: Optional[AwsDynamoDbStreamSpecification] = field(default=None)
    dynamodb_latest_stream_label: Optional[str] = field(default=None)
    dynamodb_latest_stream_arn: Optional[str] = field(default=None)
    dynamodb_global_table_version: Optional[str] = field(default=None)
    dynamodb_replicas: List[AwsDynamoDbReplicaDescription] = field(factory=list)
    dynamodb_restore_summary: Optional[AwsDynamoDbRestoreSummary] = field(default=None)
    dynamodb_sse_description: Optional[AwsDynamoDbSSEDescription] = field(default=None)
    dynamodb_archival_summary: Optional[AwsDynamoDbArchivalSummary] = field(default=None)
    dynamodb_table_class_summary: Optional[AwsDynamoDbTableClassSummary] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-table"),
            AwsApiSpec(service_name, "list-tags-of-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_instance(table: str) -> None:
            table_description = builder.client.get(service_name, "describe-table", "Table", TableName=table)
            if table_description is not None:
                if instance := cls.from_api(table_description, builder):
                    builder.add_node(instance, table_description)
                    builder.submit_work(service_name, add_tags, instance)

        def add_tags(table: AwsDynamoDbTable) -> None:
            tags = builder.client.list(service_name, "list-tags-of-resource", "Tags", ResourceArn=table.arn)
            if tags:
                table.tags = bend(ToDict(), tags)

        for js in json:
            if isinstance(js, str):
                add_instance(js)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.dynamodb_latest_stream_arn:
            builder.dependant_node(
                self,
                clazz=AwsKinesisStream,
                arn=self.dynamodb_latest_stream_arn,
            )
        for replica in self.dynamodb_replicas:
            if replica.kms_master_key_id:
                builder.dependant_node(
                    self,
                    clazz=AwsKmsKey,
                    id=replica.kms_master_key_id,
                )
        if self.dynamodb_sse_description and self.dynamodb_sse_description.kms_master_key_arn:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                arn=self.dynamodb_sse_description.kms_master_key_arn,
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-table", result_name=None, TableName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-table")]


@define(eq=False, slots=False)
class AwsDynamoDbGlobalTable(DynamoDbTaggable, AwsResource):
    kind: ClassVar[str] = "aws_dynamodb_global_table"
    kind_display: ClassVar[str] = "AWS DynamoDB Global Table"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:dynamodb:{region}:{account}:table/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS DynamoDB Global Tables provide fully managed, multi-region, and globally"
        " distributed replicas of DynamoDB tables, enabling low-latency and high-"
        " performance global access to data."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-global-tables", "GlobalTables")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_kms_key"]},
        "predecessors": {"delete": ["aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("GlobalTableName"),
        "name": S("GlobalTableName"),
        "ctime": S("CreationDateTime"),
        "arn": S("GlobalTableArn"),
        "dynamodb_replication_group": S("ReplicationGroup", default=[])
        >> ForallBend(AwsDynamoDbReplicaDescription.mapping),
        "dynamodb_global_table_status": S("GlobalTableStatus"),
    }
    arn: Optional[str] = field(default=None)
    dynamodb_replication_group: List[AwsDynamoDbReplicaDescription] = field(factory=list)
    dynamodb_global_table_status: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-global-table"),
            AwsApiSpec(service_name, "list-tags-of-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_instance(table: Dict[str, str]) -> None:
            table_description = builder.client.get(
                service_name,
                "describe-global-table",
                "GlobalTableDescription",
                GlobalTableName=table["GlobalTableName"],
            )
            if table_description:
                if instance := cls.from_api(table_description, builder):
                    builder.add_node(instance, table_description)
                    builder.submit_work(service_name, add_tags, instance)

        def add_tags(table: AwsDynamoDbGlobalTable) -> None:
            tags = builder.client.list(service_name, "list-tags-of-resource", "Tags", ResourceArn=table.arn)
            if tags:
                table.tags = bend(ToDict(), tags)

        for js in json:
            add_instance(js)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.dynamodb_replication_group is not []:
            for replica in self.dynamodb_replication_group:
                if replica.kms_master_key_id:
                    builder.dependant_node(
                        self,
                        clazz=AwsKmsKey,
                        id=replica.kms_master_key_id,
                    )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-table", result_name=None, TableName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-table")]


global_resources: List[Type[AwsResource]] = [AwsDynamoDbGlobalTable]
resources: List[Type[AwsResource]] = [AwsDynamoDbTable]
