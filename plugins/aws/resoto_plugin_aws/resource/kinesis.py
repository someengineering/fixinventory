from typing import ClassVar, Dict, Optional, List

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resotolib.baseresources import ModelReference
from resotolib.graph import Graph
from resotolib.json_bender import Bender, S, Bend, bend, ForallBend
from resotolib.types import Json
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.utils import ToDict
from typing import Type

service_name = "kinesis"


@define(eq=False, slots=False)
class AwsKinesisHashKeyRange:
    kind: ClassVar[str] = "aws_kinesis_hash_key_range"
    mapping: ClassVar[Dict[str, Bender]] = {
        "starting_hash_key": S("StartingHashKey"),
        "ending_hash_key": S("EndingHashKey"),
    }
    starting_hash_key: Optional[str] = field(default=None)
    ending_hash_key: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsKinesisSequenceNumberRange:
    kind: ClassVar[str] = "aws_kinesis_sequence_number_range"
    mapping: ClassVar[Dict[str, Bender]] = {
        "starting_sequence_number": S("StartingSequenceNumber"),
        "ending_sequence_number": S("EndingSequenceNumber"),
    }
    starting_sequence_number: Optional[str] = field(default=None)
    ending_sequence_number: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsKinesisShard:
    kind: ClassVar[str] = "aws_kinesis_shard"
    mapping: ClassVar[Dict[str, Bender]] = {
        "shard_id": S("ShardId"),
        "parent_shard_id": S("ParentShardId"),
        "adjacent_parent_shard_id": S("AdjacentParentShardId"),
        "hash_key_range": S("HashKeyRange") >> Bend(AwsKinesisHashKeyRange.mapping),
        "sequence_number_range": S("SequenceNumberRange") >> Bend(AwsKinesisSequenceNumberRange.mapping),
    }
    shard_id: Optional[str] = field(default=None)
    parent_shard_id: Optional[str] = field(default=None)
    adjacent_parent_shard_id: Optional[str] = field(default=None)
    hash_key_range: Optional[AwsKinesisHashKeyRange] = field(default=None)
    sequence_number_range: Optional[AwsKinesisSequenceNumberRange] = field(default=None)


@define(eq=False, slots=False)
class AwsKinesisEnhancedMetrics:
    kind: ClassVar[str] = "aws_kinesis_enhanced_metrics"
    mapping: ClassVar[Dict[str, Bender]] = {"shard_level_metrics": S("ShardLevelMetrics", default=[])}
    shard_level_metrics: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsKinesisStream(AwsResource):
    kind: ClassVar[str] = "aws_kinesis_stream"
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "delete": ["aws_kms_key"],
        },
        "successors": {"default": ["aws_kms_key"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-streams", "StreamNames")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("StreamName"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("StreamName"),
        "ctime": S("StreamCreationTimestamp"),
        "mtime": S("StreamCreationTimestamp"),
        "atime": S("StreamCreationTimestamp"),
        "arn": S("StreamARN"),
        "kinesis_stream_name": S("StreamName"),
        "kinesis_stream_status": S("StreamStatus"),
        "kinesis_stream_mode_details": S("StreamModeDetails", "StreamMode"),
        "kinesis_shards": S("Shards", default=[]) >> ForallBend(AwsKinesisShard.mapping),
        "kinesis_has_more_shards": S("HasMoreShards"),
        "kinesis_retention_period_hours": S("RetentionPeriodHours"),
        "kinesis_enhanced_monitoring": S("EnhancedMonitoring", default=[])
        >> ForallBend(AwsKinesisEnhancedMetrics.mapping),
        "kinesis_encryption_type": S("EncryptionType"),
        "kinesis_key_id": S("KeyId"),
    }
    kinesis_stream_status: Optional[str] = field(default=None)
    kinesis_stream_mode_details: Optional[str] = field(default=None)
    kinesis_shards: List[AwsKinesisShard] = field(factory=list)
    kinesis_has_more_shards: Optional[bool] = field(default=None)
    kinesis_retention_period_hours: Optional[int] = field(default=None)
    kinesis_enhanced_monitoring: List[AwsKinesisEnhancedMetrics] = field(factory=list)
    kinesis_encryption_type: Optional[str] = field(default=None)
    kinesis_key_id: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-stream"),
            AwsApiSpec(service_name, "list-tags-for-stream"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(stream: AwsKinesisStream) -> None:
            tags = builder.client.list(stream.api_spec.service, "list-tags-for-stream", "Tags", StreamName=stream.name)
            if tags:
                stream.tags = bend(ToDict(), tags)

        for stream_name in json:
            # this call is paginated and will return a list
            stream_descriptions = builder.client.list(
                aws_service=service_name,
                action="describe-stream",
                result_name="StreamDescription",
                StreamName=stream_name,
            )
            if len(stream_descriptions) == 1:
                stream = AwsKinesisStream.from_api(stream_descriptions[0])
                builder.add_node(stream)
                builder.submit_work(service_name, add_tags, stream)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.kinesis_key_id:
            builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(self.kinesis_key_id))

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="add-tags-to-stream",
            result_name=None,
            StreamName=self.name,
            Tags={key: value},
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="remove-tags-from-stream",
            result_name=None,
            StreamName=self.name,
            TagKeys=[key],
        )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-stream",
            result_name=None,
            StreamName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "add-tags-to-stream"),
            AwsApiSpec(service_name, "remove-tags-from-stream"),
            AwsApiSpec(service_name, "delete-stream"),
        ]


resources: List[Type[AwsResource]] = [AwsKinesisStream]
