from datetime import datetime, timezone
from typing import ClassVar, Dict, List, Optional, Tuple, Type, Any


from attrs import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.cloudwatch import AwsCloudwatchQuery, normalizer_factory
from fix_plugin_aws.resource.kms import AwsKmsKey
from fixlib.baseresources import (
    BaseQueue,
    HasResourcePolicy,
    MetricName,
    ModelReference,
    PolicySource,
    PolicySourceKind,
    QueueType,
)
from fixlib.graph import Graph
from fixlib.json_bender import F, Bender, S, AsInt, AsBool, Bend, ParseJson, Sorted
from fixlib.types import Json
from fixlib.utils import utc_str

service_name = "sqs"


@define(eq=False, slots=False)
class AwsSqsRedrivePolicy:
    kind: ClassVar[str] = "aws_sqs_redrive_policy"
    kind_display: ClassVar[str] = "AWS SQS Redrive Policy"
    kind_description: ClassVar[str] = (
        "The AWS SQS Redrive Policy enables you to configure dead-letter queues for"
        " your Amazon Simple Queue Service (SQS) queues. Dead-letter queues are used"
        " to store messages that cannot be processed successfully by the main queue."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "dead_letter_target_arn": S("deadLetterTargetArn"),
        "max_receive_count": S("maxReceiveCount"),
    }
    dead_letter_target_arn: Optional[str] = None
    max_receive_count: Optional[int] = None


@define(eq=False, slots=False)
class AwsSqsQueue(AwsResource, BaseQueue, HasResourcePolicy):
    kind: ClassVar[str] = "aws_sqs_queue"
    _kind_display: ClassVar[str] = "AWS SQS Queue"
    _kind_description: ClassVar[str] = "AWS SQS Queue is a managed message queuing service that facilitates communication between distributed system components. It stores messages from producers and delivers them to consumers, ensuring reliable data transfer. SQS supports multiple messaging patterns, including point-to-point and publish-subscribe, and handles message retention, delivery, and deletion. It integrates with other AWS services for building decoupled applications."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/welcome.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "queue", "group": "compute"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/sqs/v3/home?region={region}#/queues/{QueueUrl}", "arn_tpl": "arn:{partition}:sqs:{region}:{account}:{id}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-queues", "QueueUrls")
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_kms_key"]},
        "predecessors": {"delete": ["aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("QueueName"),
        "name": S("QueueName"),
        "ctime": S("CreatedTimestamp") >> AsInt() >> F(lambda x: utc_str(datetime.fromtimestamp(x, timezone.utc))),
        "mtime": S("LastModifiedTimestamp") >> AsInt() >> F(lambda x: utc_str(datetime.fromtimestamp(x, timezone.utc))),
        "arn": S("QueueArn"),
        "sqs_queue_url": S("QueueUrl"),
        "sqs_approximate_number_of_messages": S("ApproximateNumberOfMessages") >> AsInt(),
        "sqs_approximate_number_of_messages_not_visible": S("ApproximateNumberOfMessagesNotVisible") >> AsInt(),
        "sqs_approximate_number_of_messages_delayed": S("ApproximateNumberOfMessagesDelayed") >> AsInt(),
        "sqs_policy": S("Policy") >> ParseJson() >> Sorted(sort_list=True),
        "sqs_redrive_policy": S("RedrivePolicy") >> ParseJson() >> Bend(AwsSqsRedrivePolicy.mapping),
        "sqs_fifo_queue": S("FifoQueue") >> AsBool(),
        "sqs_content_based_deduplication": S("ContentBasedDeduplication") >> AsBool(),
        "sqs_kms_master_key_id": S("KmsMasterKeyId"),
        "sqs_kms_data_key_reuse_period_seconds": S("KmsDataKeyReusePeriodSeconds") >> AsInt(),
        "sqs_deduplication_scope": S("DeduplicationScope"),
        "sqs_fifo_throughput_limit": S("FifoThroughputLimit"),
        "sqs_redrive_allow_policy": S("RedriveAllowPolicy") >> ParseJson() >> S("redrivePermission"),
        "sqs_visibility_timeout": S("VisibilityTimeout") >> AsInt(),
        "sqs_maximum_message_size": S("MaximumMessageSize") >> AsInt(),
        "sqs_message_retention_period": S("MessageRetentionPeriod") >> AsInt(),
        "sqs_delay_seconds": S("DelaySeconds") >> AsInt(),
        "sqs_receive_message_wait_time_seconds": S("ReceiveMessageWaitTimeSeconds") >> AsInt(),
        "sqs_managed_sse_enabled": S("SqsManagedSseEnabled") >> AsBool(),
        "message_retention_period_days": S("MessageRetentionPeriod") >> AsInt(),
        "approximate_message_count": S("ApproximateNumberOfMessages") >> AsInt(),
    }
    sqs_queue_url: Optional[str] = field(default=None)
    sqs_approximate_number_of_messages: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    sqs_approximate_number_of_messages_not_visible: Optional[int] = field(
        default=None, metadata=dict(ignore_history=True)
    )
    sqs_approximate_number_of_messages_delayed: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    sqs_policy: Optional[Json] = field(default=None)
    sqs_redrive_policy: Optional[AwsSqsRedrivePolicy] = field(default=None)
    sqs_fifo_queue: Optional[bool] = field(default=None)
    sqs_content_based_deduplication: Optional[bool] = field(default=None)
    sqs_kms_master_key_id: Optional[str] = field(default=None)
    sqs_kms_data_key_reuse_period_seconds: Optional[int] = field(default=None)
    sqs_deduplication_scope: Optional[str] = field(default=None)
    sqs_fifo_throughput_limit: Optional[str] = field(default=None)
    sqs_redrive_allow_policy: Optional[str] = field(default=None)
    sqs_visibility_timeout: Optional[int] = field(default=None)
    sqs_maximum_message_size: Optional[int] = field(default=None)
    sqs_message_retention_period: Optional[int] = field(default=None)
    sqs_delay_seconds: Optional[int] = field(default=None)
    sqs_receive_message_wait_time_seconds: Optional[int] = field(default=None)
    sqs_managed_sse_enabled: Optional[bool] = field(default=None)

    def resource_policy(self, builder: Any) -> List[Tuple[PolicySource, Dict[str, Any]]]:
        if not self.sqs_policy or not self.arn:
            return []

        return [(PolicySource(PolicySourceKind.resource, self.arn), self.sqs_policy)]

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "get-queue-attributes"),
            AwsApiSpec(service_name, "list-queue-tags"),
        ]

    @classmethod
    def collect(cls, json: List[Json], builder: GraphBuilder) -> None:
        def add_instance(queue_url: str) -> None:
            queue_attributes = builder.client.get(
                service_name, "get-queue-attributes", "Attributes", QueueUrl=queue_url, AttributeNames=["All"]
            )
            if queue_attributes is not None:
                queue_attributes["QueueUrl"] = queue_url
                queue_attributes["QueueName"] = queue_url.rsplit("/", 1)[-1]
                if instance := AwsSqsQueue.from_api(queue_attributes, builder):
                    builder.add_node(instance, queue_attributes)
                    instance.queue_type = QueueType.FIFO if instance.sqs_fifo_queue else QueueType.STANDARD
                    builder.submit_work(service_name, add_tags, instance)

        def add_tags(queue: AwsSqsQueue) -> None:
            tags = builder.client.get(service_name, "list-queue-tags", result_name="Tags", QueueUrl=queue.sqs_queue_url)
            if tags:
                queue.tags = tags

        for queue_url in json:
            if isinstance(queue_url, str):
                builder.submit_work(service_name, add_instance, queue_url)

    def collect_usage_metrics(self, builder: GraphBuilder) -> List[AwsCloudwatchQuery]:
        # Filter out metrics with the 'aws-controltower' dimension value
        if "aws-controltower" in self.safe_name:
            return []
        queries: List[AwsCloudwatchQuery] = []
        delta = builder.metrics_delta

        queries.extend(
            [
                AwsCloudwatchQuery.create(
                    query_name="ApproximateAgeOfOldestMessage",
                    namespace="AWS/SQS",
                    period=delta,
                    ref_id=self.id,
                    metric_name=MetricName.ApproximateAgeOfOldestMessage,
                    normalization=normalizer_factory.seconds,
                    stat=stat,
                    unit="Seconds",
                    QueueName=self.safe_name,
                )
                for stat in ["Minimum", "Average", "Maximum"]
            ]
        )
        queries.extend(
            [
                AwsCloudwatchQuery.create(
                    query_name=name,
                    namespace="AWS/SQS",
                    period=delta,
                    ref_id=self.id,
                    metric_name=metric_name,
                    normalization=normalizer_factory.count,
                    stat=stat,
                    unit="Count",
                    QueueName=self.safe_name,
                )
                for stat in ["Minimum", "Average", "Maximum"]
                for name, metric_name in [
                    ("ApproximateNumberOfMessagesDelayed", MetricName.ApproximateNumberOfMessagesDelayed),
                    ("ApproximateNumberOfMessagesNotVisible", MetricName.ApproximateNumberOfMessagesNotVisible),
                    ("ApproximateNumberOfMessagesVisible", MetricName.ApproximateNumberOfMessagesVisible),
                    ("NumberOfMessagesReceived", MetricName.NumberOfMessagesReceived),
                    ("NumberOfMessagesSent", MetricName.NumberOfMessagesSent),
                ]
            ]
        )
        return queries

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.sqs_kms_master_key_id:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                id=self.sqs_kms_master_key_id,
            )

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name,
            action="tag-queue",
            result_name=None,
            QueueUrl=self.sqs_queue_url,
            Tags={key: value},
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=service_name, action="untag-queue", result_name=None, QueueUrl=self.sqs_queue_url, TagKeys=[key]
        )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="delete-queue", result_name=None, QueueUrl=self.sqs_queue_url)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-queue"),
            AwsApiSpec(service_name, "untag-queue"),
            AwsApiSpec(service_name, "delete-queue"),
        ]


resources: List[Type[AwsResource]] = [AwsSqsQueue]
