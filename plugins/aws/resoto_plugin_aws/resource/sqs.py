from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Type

from attrs import define, field

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resotolib.baseresources import ModelReference
from resotolib.json_bender import F, Bender, S
from resotolib.types import Json
from resotolib.utils import utc_str


@define(eq=False, slots=False)
class AwsSqsQueue(AwsResource):
    kind: ClassVar[str] = "aws_sqs_queue"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sqs", "list-queues", "QueueUrls")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_kms_key"]},
        "predecessors": {"delete": ["aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("QueueName"),
        "name": S("QueueName"),
        "ctime": S("CreatedTimestamp") >> F(lambda x: utc_str(datetime.utcfromtimestamp(x))),
        "mtime": S("LastModifiedTimestamp") >> F(lambda x: utc_str(datetime.utcfromtimestamp(x))),
        "arn": S("QueueArn"),
        "sqs_queue_url": S("QueueUrl"),
        "sqs_approximate_number_of_messages": S("ApproximateNumberOfMessages"),
        "sqs_approximate_number_of_messages_not_visible": S("ApproximateNumberOfMessagesNotVisible"),
        "sqs_approximate_number_of_messages_delayed": S("ApproximateNumberOfMessagesDelayed"),
        "sqs_policy": S("Policy"),
        "sqs_redrive_policy": S("RedrivePolicy"),
        "sqs_fifo_queue": S("FifoQueue"),
        "sqs_content_based_deduplication": S("ContentBasedDeduplication"),
        "sqs_kms_master_key_id": S("KmsMasterKeyId"),
        "sqs_kms_data_key_reuse_period_seconds": S("KmsDataKeyReusePeriodSeconds"),
        "sqs_deduplication_scope": S("DeduplicationScope"),
        "sqs_fifo_throughput_limit": S("FifoThroughputLimit"),
        "sqs_redrive_allow_policy": S("RedriveAllowPolicy"),
        "sqs_visibility_timeout": S("VisibilityTimeout"),
        "sqs_maximum_message_size": S("MaximumMessageSize"),
        "sqs_message_retention_period": S("MessageRetentionPeriod"),
        "sqs_delay_seconds": S("DelaySeconds"),
        "sqs_receive_message_wait_time_seconds": S("ReceiveMessageWaitTimeSeconds"),
        "sqs_managed_sse_enabled": S("SqsManagedSseEnabled"),
    }
    sqs_queue_url: str = field(default=None)
    sqs_approximate_number_of_messages: Optional[int] = field(default=None)
    sqs_approximate_number_of_messages_not_visible: Optional[int] = field(default=None)
    sqs_approximate_number_of_messages_delayed: Optional[int] = field(default=None)
    sqs_policy: Optional[str] = field(default=None)
    sqs_redrive_policy: Optional[str] = field(default=None)
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

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec("sqs", "get-queue-attributes"), AwsApiSpec("sqs", "list-queue-tags")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_instance(queue_url: str) -> None:
            queue_attributes = builder.client.get(
                "sqs", "get-queue-attributes", "Attributes", QueueUrl=queue_url, AttributeNames=["All"]
            )
            if queue_attributes is not None:
                queue_attributes["QueueUrl"] = queue_url
                queue_attributes["QueueName"] = queue_url.rsplit("/", 1)[-1]
                instance = cls.from_api(queue_attributes)
                builder.add_node(instance)
                builder.submit_work(add_tags, instance)

        def add_tags(queue: AwsSqsQueue) -> None:
            tags = builder.client.get("sqs", "list-queue-tags", result_name="Tags", QueueUrl=[queue.sqs_queue_url])
            if tags:
                queue.tags = tags

        for queue_url in json:
            if isinstance(queue_url, str):
                add_instance(queue_url)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.sqs_kms_master_key_id:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                id=self.sqs_kms_master_key_id,
            )

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service="sqs", action="tag-queue", result_name=None, QueueUrl=self.sqs_queue_url, Tags={key: value}
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service="sqs", action="untag-queue", result_name=None, QueueUrl=self.sqs_queue_url, TagKeys=[key]
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="sqs", action="delete-queue", result_name=None, QueueUrl=self.sqs_queue_url)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("sqs", "tag-queue"),
            AwsApiSpec("sqs", "untag-queue"),
            AwsApiSpec("sqs", "delete-queue"),
        ]


resources: List[Type[AwsResource]] = [AwsSqsQueue]
