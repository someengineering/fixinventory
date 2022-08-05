from typing import ClassVar, Dict, List, Optional, Type
from attrs import define, field
from datetime import datetime
from resoto_plugin_aws.utils import ToDict
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resotolib.json_bender import AsDate, Bender, S, bend
from resotolib.types import Json

# @define(eq=False, slots=False)
# class AwsSqsQueueList():
#     kind: ClassVar[str] = "aws_sqs_queue"
#     api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sqs", "list-queues", result_name=None)
#     mapping: ClassVar[Dict[str, Bender]] = {
#         "sqs_queue_urls": S("QueueUrls")
#     }
#     sqs_queue_urls: List[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSqsQueue(AwsResource):
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sqs", "list-queues", "QueueUrls")
    kind: ClassVar[str] = "aws_sqs_queue"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("QueueName"),
        "name": S("QueueName"),
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
        "sqs_managed_sse_enabled": S("SqsManagedSseEnabled")
    }
    sqs_queue_url: str = field(default=None)
    sqs_approximate_number_of_messages: Optional[int] = field(default=None)
    sqs_approximate_number_of_messages_not_visible: Optional[int] = field(default=None)
    sqs_approximate_number_of_messages_delayed: Optional[int] = field(default=None)
    sqs_policy: Optional[str] = field(default=None)
    sqs_redrive_policy: Optional[str] = field(default=None)
    sqs_fifo_queue: Optional[bool] = field(default=None)
    sqs_content_based_deduplication: Optional[bool] = field(default=None)
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
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(queue: AwsSqsQueue) -> None:
            tags = builder.client.list("sqs", "list-queue-tags", result_name="Tags", QueueUrl=[queue.sqs_queue_url])
            if tags:
                queue.tags = tags

        for queue_url in json:
            queue_attributes = builder.client.call("sqs", "get-queue-attributes", "Attributes", QueueUrl=queue_url, AttributeNames=["All"])
            queue_attributes["QueueUrl"] = queue_url
            queue_attributes["QueueName"] = queue_url.rsplit('/',1)[-1]
            instance = cls.from_api(queue_attributes)
            instance.ctime = datetime.fromtimestamp(queue_attributes["CreatedTimestamp"])
            instance.mtime = datetime.fromtimestamp(queue_attributes["LastModifiedTimestamp"])
            builder.add_node(instance, queue_attributes)
            builder.submit_work(add_tags, instance)

resources: List[Type[AwsResource]] = [AwsSqsQueue]
