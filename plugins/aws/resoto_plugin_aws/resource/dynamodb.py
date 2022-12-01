from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Type
from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.kinesis import AwsKinesisStream
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference
from resotolib.json_bender import S, Bend, Bender, ForallBend, bend
from resotolib.types import Json


# noinspection PyUnresolvedReferences
class DynamoDbTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service="dynamodb",
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
                aws_service="dynamodb",
                action="untag-resource",
                result_name=None,
                ResourceArn=self.arn,
                TagKeys=[key],
            )
            return True
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("dynamodb", "tag-resource"), AwsApiSpec("dynamodb", "untag-resource")]


@define(eq=False, slots=False)
class AwsDynamoDbAttributeDefinition:
    kind: ClassVar[str] = "aws_dynamo_db_attribute_definition"
    mapping: ClassVar[Dict[str, Bender]] = {"attribute_name": S("AttributeName"), "attribute_type": S("AttributeType")}
    attribute_name: Optional[str] = field(default=None)
    attribute_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbKeySchemaElement:
    kind: ClassVar[str] = "aws_dynamo_db_key_schema_element"
    mapping: ClassVar[Dict[str, Bender]] = {"attribute_name": S("AttributeName"), "key_type": S("KeyType")}
    attribute_name: Optional[str] = field(default=None)
    key_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbProvisionedThroughputDescription:
    kind: ClassVar[str] = "aws_dynamo_db_provisioned_throughput_description"
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
    kind: ClassVar[str] = "aws_dynamo_db_billing_mode_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "billing_mode": S("BillingMode"),
        "last_update_to_pay_per_request_date_time": S("LastUpdateToPayPerRequestDateTime"),
    }
    billing_mode: Optional[str] = field(default=None)
    last_update_to_pay_per_request_date_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbProjection:
    kind: ClassVar[str] = "aws_dynamo_db_projection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "projection_type": S("ProjectionType"),
        "non_key_attributes": S("NonKeyAttributes", default=[]),
    }
    projection_type: Optional[str] = field(default=None)
    non_key_attributes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsDynamoDbLocalSecondaryIndexDescription:
    kind: ClassVar[str] = "aws_dynamo_db_local_secondary_index_description"
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
    kind: ClassVar[str] = "aws_dynamo_db_global_secondary_index_description"
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
    index_size_bytes: Optional[int] = field(default=None)
    item_count: Optional[int] = field(default=None)
    index_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbStreamSpecification:
    kind: ClassVar[str] = "aws_dynamo_db_stream_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "stream_enabled": S("StreamEnabled"),
        "stream_view_type": S("StreamViewType"),
    }
    stream_enabled: Optional[bool] = field(default=None)
    stream_view_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbReplicaGlobalSecondaryIndexDescription:
    kind: ClassVar[str] = "aws_dynamo_db_replica_global_secondary_index_description"
    mapping: ClassVar[Dict[str, Bender]] = {
        "index_name": S("IndexName"),
        "provisioned_throughput_override": S("ProvisionedThroughputOverride", "ReadCapacityUnits"),
    }
    index_name: Optional[str] = field(default=None)
    provisioned_throughput_override: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbTableClassSummary:
    kind: ClassVar[str] = "aws_dynamo_db_table_class_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "table_class": S("TableClass"),
        "last_update_date_time": S("LastUpdateDateTime"),
    }
    table_class: Optional[str] = field(default=None)
    last_update_date_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsDynamoDbReplicaDescription:
    kind: ClassVar[str] = "aws_dynamo_db_replica_description"
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
    kind: ClassVar[str] = "aws_dynamo_db_restore_summary"
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
    kind: ClassVar[str] = "aws_dynamo_db_sse_description"
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
    kind: ClassVar[str] = "aws_dynamo_db_archival_summary"
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
    kind: ClassVar[str] = "aws_dynamo_db_table"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("dynamodb", "list-tables", "TableNames")
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
    dynamodb_table_size_bytes: Optional[int] = field(default=None)
    dynamodb_item_count: Optional[int] = field(default=None)
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
        return [cls.api_spec, AwsApiSpec("dynamodb", "describe-table"), AwsApiSpec("dynamodb", "list-tags-of-resource")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_instance(table: str) -> None:
            table_description = builder.client.get("dynamodb", "describe-table", "Table", TableName=table)
            if table_description is not None:
                instance = cls.from_api(table_description)
                builder.add_node(instance, table_description)
                builder.submit_work(add_tags, instance)

        def add_tags(table: AwsDynamoDbTable) -> None:
            tags = builder.client.list("dynamodb", "list-tags-of-resource", "Tags", ResourceArn=table.arn)
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-table", result_name=None, TableName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec("dynamodb", "delete-table")]


@define(eq=False, slots=False)
class AwsDynamoDbGlobalTable(DynamoDbTaggable, AwsResource):
    kind: ClassVar[str] = "aws_dynamo_db_global_table"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("dynamodb", "list-global-tables", "GlobalTables")
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
            AwsApiSpec("dynamodb", "describe-global-table"),
            AwsApiSpec("dynamodb", "list-tags-of-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_instance(table: Dict[str, str]) -> None:
            table_description = builder.client.get(
                "dynamodb", "describe-global-table", "GlobalTableDescription", GlobalTableName=table["GlobalTableName"]
            )
            if table_description:
                instance = cls.from_api(table_description)
                builder.add_node(instance, table_description)
                builder.submit_work(add_tags, instance)

        def add_tags(table: AwsDynamoDbGlobalTable) -> None:
            tags = builder.client.list("dynamodb", "list-tags-of-resource", "Tags", ResourceArn=table.arn)
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-table", result_name=None, TableName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec("dynamodb", "delete-table")]


global_resources: List[Type[AwsResource]] = [AwsDynamoDbGlobalTable]
resources: List[Type[AwsResource]] = [AwsDynamoDbTable]
