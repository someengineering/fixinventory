from typing import ClassVar, Dict, Optional, List, Any, Tuple
from json import loads as json_loads

from attrs import define, field

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from fix_plugin_aws.resource.cloudwatch import AwsCloudwatchQuery, normalizer_factory
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import HasResourcePolicy, MetricName, ModelReference, PolicySource, PolicySourceKind
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, bend, ForallBend
from fixlib.types import Json
from fixlib.json import sort_json
from typing import Type

service_name = "kinesis"


@define(eq=False, slots=False)
class AwsKinesisHashKeyRange:
    kind: ClassVar[str] = "aws_kinesis_hash_key_range"
    kind_display: ClassVar[str] = "AWS Kinesis Hash Key Range"
    kind_description: ClassVar[str] = (
        "AWS Kinesis Hash Key Range is a range of hash keys used for partitioning"
        " data in Amazon Kinesis streams, allowing for efficient and scalable data"
        " processing and analysis."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "starting_hash_key": S("StartingHashKey"),
        "ending_hash_key": S("EndingHashKey"),
    }
    starting_hash_key: Optional[str] = field(default=None)
    ending_hash_key: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsKinesisSequenceNumberRange:
    kind: ClassVar[str] = "aws_kinesis_sequence_number_range"
    kind_display: ClassVar[str] = "AWS Kinesis Sequence Number Range"
    kind_description: ClassVar[str] = (
        "Kinesis Sequence Number Range represents a range of sequence numbers"
        " associated with data records in an Amazon Kinesis data stream. It is used to"
        " specify a starting and ending sequence number when retrieving records from"
        " the stream."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "starting_sequence_number": S("StartingSequenceNumber"),
        "ending_sequence_number": S("EndingSequenceNumber"),
    }
    starting_sequence_number: Optional[str] = field(default=None)
    ending_sequence_number: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsKinesisShard:
    kind: ClassVar[str] = "aws_kinesis_shard"
    kind_display: ClassVar[str] = "AWS Kinesis Shard"
    kind_description: ClassVar[str] = (
        "An AWS Kinesis Shard is a sequence of data records in an Amazon Kinesis"
        " stream, used for storing and processing real-time streaming data."
    )
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
    kind_display: ClassVar[str] = "AWS Kinesis Enhanced Metrics"
    kind_description: ClassVar[str] = (
        "Kinesis Enhanced Metrics is a feature provided by AWS Kinesis that enables"
        " enhanced monitoring and analysis of data streams with additional metrics and"
        " statistics."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"shard_level_metrics": S("ShardLevelMetrics", default=[])}
    shard_level_metrics: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsKinesisStream(AwsResource, HasResourcePolicy):
    kind: ClassVar[str] = "aws_kinesis_stream"
    _kind_display: ClassVar[str] = "AWS Kinesis Stream"
    _kind_description: ClassVar[str] = "AWS Kinesis Stream is a data streaming service that collects, processes, and analyzes real-time data at scale. It ingests data from multiple sources, stores it in shards, and makes it available for consumption by applications. Kinesis Stream supports various data types and can handle high-throughput data flows for analytics, monitoring, and machine learning purposes."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/streams/latest/dev/introduction.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "queue", "group": "compute"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/kinesis/home?region={region}#/streams/details/{name}", "arn_tpl": "arn:{partition}:kinesis:{region}:{account}:stream/{name}"}  # fmt: skip
    _reference_kinds: ClassVar[ModelReference] = {
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
    kinesis_policy: Optional[Json] = field(default=None)

    def resource_policy(self, builder: Any) -> List[Tuple[PolicySource, Dict[str, Any]]]:
        if not self.kinesis_policy or not self.arn:
            return []

        return [(PolicySource(PolicySourceKind.resource, self.arn), self.kinesis_policy)]

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-stream"),
            AwsApiSpec(service_name, "list-tags-for-stream"),
            AwsApiSpec(service_name, "get-resource-policy"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_kinesis_policy(kinesis: AwsKinesisStream) -> None:
            with builder.suppress(f"{service_name}.get-resource-policy"):
                if raw_policy := builder.client.get(
                    service_name,
                    "get-resource-policy",
                    "Policy",
                    ResourceARN=kinesis.arn,
                    expected_errors=["AccessDeniedException"],
                ):
                    kinesis.kinesis_policy = sort_json(json_loads(raw_policy), sort_list=True)  # type: ignore

        def add_instance(stream_name: str) -> None:
            # this call is paginated and will return a list
            stream_descriptions = builder.client.list(
                aws_service=service_name,
                action="describe-stream",
                result_name="StreamDescription",
                StreamName=stream_name,
            )
            if len(stream_descriptions) == 1:
                js = stream_descriptions[0]
                if stream := AwsKinesisStream.from_api(js, builder):
                    builder.add_node(stream, js)
                    builder.submit_work(service_name, add_tags, stream)
                    builder.submit_work(service_name, add_kinesis_policy, stream)

        def add_tags(stream: AwsKinesisStream) -> None:
            tags = builder.client.list(stream.api_spec.service, "list-tags-for-stream", "Tags", StreamName=stream.name)
            if tags:
                stream.tags = bend(ToDict(), tags)

        for stream_name in json:
            builder.submit_work(service_name, add_instance, stream_name)

    def collect_usage_metrics(self, builder: GraphBuilder) -> List[AwsCloudwatchQuery]:
        # Filter out metrics with the 'aws-controltower' dimension value
        if "aws-controltower" in self.safe_name:
            return []
        queries: List[AwsCloudwatchQuery] = []
        delta = builder.metrics_delta

        queries.extend(
            [
                AwsCloudwatchQuery.create(
                    query_name="GetRecords.Bytes",
                    namespace="AWS/Kinesis",
                    period=delta,
                    ref_id=self.id,
                    metric_name=MetricName.RecordsBytes,
                    normalization=normalizer_factory.bytes,
                    stat=stat,
                    unit="Bytes",
                    StreamName=self.safe_name,
                )
                for stat in ["Minimum", "Average", "Maximum"]
            ]
        )
        queries.extend(
            [
                AwsCloudwatchQuery.create(
                    query_name="GetRecords.IteratorAgeMilliseconds",
                    namespace="AWS/Kinesis",
                    period=delta,
                    ref_id=self.id,
                    metric_name=MetricName.RecordsIteratorAgeMilliseconds,
                    normalization=normalizer_factory.milliseconds,
                    stat=stat,
                    unit="Milliseconds",
                    StreamName=self.safe_name,
                )
                for stat in ["Minimum", "Average", "Maximum"]
            ]
        )
        return queries

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
