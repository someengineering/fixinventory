from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder
from fixlib.baseresources import BaseQueue, ModelReference, QueueType
from fixlib.json_bender import Bender, S, Bend, K, F
from fixlib.types import Json

service_name = "pubsub"


@define(eq=False, slots=False)
class GcpPubSubSnapshot(GcpResource):
    kind: ClassVar[str] = "gcp_pubsub_snapshot"
    _kind_display: ClassVar[str] = "GCP Pub/Sub Snapshot"
    _kind_description: ClassVar[str] = (
        "GCP Pub/Sub Snapshot provides a point-in-time view of a Pub/Sub subscription. "
        "Snapshots enable developers to reprocess or replay messages from a specified point, allowing for data recovery and debugging. "
        "They are useful for scenarios requiring auditability or backtracking in message processing workflows."
    )  # fmt: skip
    _kind_service: ClassVar[Optional[str]] = service_name
    _docs_url: ClassVar[str] = "https://cloud.google.com/pubsub/docs/replay-overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "snapshot", "group": "compute"}
    _reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_pubsub_topic"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="pubsub",
        version="v1",
        accessors=["projects", "snapshots"],
        action="list",
        request_parameter={"project": "projects/{project}"},
        request_parameter_in={"project"},
        response_path="snapshots",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "expire_time": S("expireTime"),
        "subscription_topic": S("topic"),
    }
    expire_time: Optional[datetime] = field(default=None)
    subscription_topic: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if topic := self.subscription_topic:
            builder.add_edge(self, clazz=GcpPubSubTopic, reverse=True, name=topic)


@define(eq=False, slots=False)
class GcpAnalyticsHubSubscriptionInfo:
    kind: ClassVar[str] = "gcp_analytics_hub_subscription_info"
    mapping: ClassVar[Dict[str, Bender]] = {"listing": S("listing"), "subscription": S("subscription")}
    listing: Optional[str] = field(default=None)
    subscription: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpBigQueryConfig:
    kind: ClassVar[str] = "gcp_big_query_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "drop_unknown_fields": S("dropUnknownFields"),
        "service_account_email": S("serviceAccountEmail"),
        "state": S("state"),
        "table": S("table"),
        "use_table_schema": S("useTableSchema"),
        "use_topic_schema": S("useTopicSchema"),
        "write_metadata": S("writeMetadata"),
    }
    drop_unknown_fields: Optional[bool] = field(default=None)
    service_account_email: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    table: Optional[str] = field(default=None)
    use_table_schema: Optional[bool] = field(default=None)
    use_topic_schema: Optional[bool] = field(default=None)
    write_metadata: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpAvroConfig:
    kind: ClassVar[str] = "gcp_avro_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "use_topic_schema": S("useTopicSchema"),
        "write_metadata": S("writeMetadata"),
    }
    use_topic_schema: Optional[bool] = field(default=None)
    write_metadata: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpTextConfig:
    kind: ClassVar[str] = "gcp_text_config"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpCloudStorageConfig:
    kind: ClassVar[str] = "gcp_cloud_storage_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "avro_config": S("avroConfig", default={}) >> Bend(GcpAvroConfig.mapping),
        "bucket": S("bucket"),
        "filename_datetime_format": S("filenameDatetimeFormat"),
        "filename_prefix": S("filenamePrefix"),
        "filename_suffix": S("filenameSuffix"),
        "max_bytes": S("maxBytes"),
        "max_duration": S("maxDuration"),
        "max_messages": S("maxMessages"),
        "service_account_email": S("serviceAccountEmail"),
        "state": S("state"),
        "text_config": S("textConfig", default={}) >> Bend(GcpTextConfig.mapping),
    }
    avro_config: Optional[GcpAvroConfig] = field(default=None)
    bucket: Optional[str] = field(default=None)
    filename_datetime_format: Optional[str] = field(default=None)
    filename_prefix: Optional[str] = field(default=None)
    filename_suffix: Optional[str] = field(default=None)
    max_bytes: Optional[str] = field(default=None)
    max_duration: Optional[str] = field(default=None)
    max_messages: Optional[str] = field(default=None)
    service_account_email: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    text_config: Optional[GcpTextConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpDeadLetterPolicy:
    kind: ClassVar[str] = "gcp_dead_letter_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "dead_letter_topic": S("deadLetterTopic"),
        "max_delivery_attempts": S("maxDeliveryAttempts"),
    }
    dead_letter_topic: Optional[str] = field(default=None)
    max_delivery_attempts: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpOidcToken:
    kind: ClassVar[str] = "gcp_oidc_token"
    mapping: ClassVar[Dict[str, Bender]] = {
        "audience": S("audience"),
        "service_account_email": S("serviceAccountEmail"),
    }
    audience: Optional[str] = field(default=None)
    service_account_email: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPubsubWrapper:
    kind: ClassVar[str] = "gcp_pubsub_wrapper"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpPushConfig:
    kind: ClassVar[str] = "gcp_push_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attributes": S("attributes"),
        "no_wrapper": S("noWrapper", "writeMetadata"),
        "oidc_token": S("oidcToken", default={}) >> Bend(GcpOidcToken.mapping),
        "pubsub_wrapper": S("pubsubWrapper", default={}) >> Bend(GcpPubsubWrapper.mapping),
        "push_endpoint": S("pushEndpoint"),
    }
    attributes: Optional[Dict[str, str]] = field(default=None)
    no_wrapper: Optional[bool] = field(default=None)
    oidc_token: Optional[GcpOidcToken] = field(default=None)
    pubsub_wrapper: Optional[GcpPubsubWrapper] = field(default=None)
    push_endpoint: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpRetryPolicy:
    kind: ClassVar[str] = "gcp_retry_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "maximum_backoff": S("maximumBackoff"),
        "minimum_backoff": S("minimumBackoff"),
    }
    maximum_backoff: Optional[str] = field(default=None)
    minimum_backoff: Optional[str] = field(default=None)


def seconds_to_days(time_str: str) -> int:
    seconds = int(time_str.rstrip("s"))
    # Convert seconds to days
    days = seconds // 86400
    return days


@define(eq=False, slots=False)
class GcpPubSubSubscription(GcpResource, BaseQueue):
    kind: ClassVar[str] = "gcp_pubsub_subscription"
    _kind_display: ClassVar[str] = "GCP Pub/Sub Subscription"
    _kind_description: ClassVar[str] = (
        "GCP Pub/Sub Subscription represents a connection to a Pub/Sub Topic, enabling applications to consume messages. "
        "Subscriptions can pull or push messages from the associated topic and ensure message delivery based on acknowledgment and retry policies. "
        "This allows for flexible, reliable messaging and integration with various systems."
    )  # fmt: skip
    _kind_service: ClassVar[Optional[str]] = service_name
    _docs_url: ClassVar[str] = "https://cloud.google.com/pubsub/docs/subscriber"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "queue", "group": "compute"}
    _reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["gcp_pubsub_topic"]}}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="pubsub",
        version="v1",
        accessors=["projects", "subscriptions"],
        action="list",
        request_parameter={"project": "projects/{project}"},
        request_parameter_in={"project"},
        response_path="subscriptions",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "ack_deadline_seconds": S("ackDeadlineSeconds"),
        "analytics_hub_subscription_info": S("analyticsHubSubscriptionInfo", default={})
        >> Bend(GcpAnalyticsHubSubscriptionInfo.mapping),
        "bigquery_config": S("bigqueryConfig", default={}) >> Bend(GcpBigQueryConfig.mapping),
        "cloud_storage_config": S("cloudStorageConfig", default={}) >> Bend(GcpCloudStorageConfig.mapping),
        "dead_letter_policy": S("deadLetterPolicy", default={}) >> Bend(GcpDeadLetterPolicy.mapping),
        "detached": S("detached"),
        "enable_exactly_once_delivery": S("enableExactlyOnceDelivery"),
        "enable_message_ordering": S("enableMessageOrdering"),
        "expiration_policy": S("expirationPolicy", "ttl"),
        "subscription_filter": S("filter"),
        "message_retention_duration": S("messageRetentionDuration"),
        "push_config": S("pushConfig", default={}) >> Bend(GcpPushConfig.mapping),
        "retain_acked_messages": S("retainAckedMessages"),
        "retry_policy": S("retryPolicy", default={}) >> Bend(GcpRetryPolicy.mapping),
        "state": S("state"),
        "subscription_topic": S("topic"),
        "topic_message_retention_duration": S("topicMessageRetentionDuration"),
        "queue_type": K(QueueType.STANDARD),
        "message_retention_period_days": S("messageRetentionDuration") >> F(seconds_to_days),
    }
    ack_deadline_seconds: Optional[int] = field(default=None)
    analytics_hub_subscription_info: Optional[GcpAnalyticsHubSubscriptionInfo] = field(default=None)
    bigquery_config: Optional[GcpBigQueryConfig] = field(default=None)
    cloud_storage_config: Optional[GcpCloudStorageConfig] = field(default=None)
    dead_letter_policy: Optional[GcpDeadLetterPolicy] = field(default=None)
    detached: Optional[bool] = field(default=None)
    enable_exactly_once_delivery: Optional[bool] = field(default=None)
    enable_message_ordering: Optional[bool] = field(default=None)
    expiration_policy: Optional[str] = field(default=None)
    subscription_filter: Optional[str] = field(default=None)
    message_retention_duration: Optional[str] = field(default=None)
    push_config: Optional[GcpPushConfig] = field(default=None)
    retain_acked_messages: Optional[bool] = field(default=None)
    retry_policy: Optional[GcpRetryPolicy] = field(default=None)
    state: Optional[str] = field(default=None)
    subscription_topic: Optional[str] = field(default=None)
    topic_message_retention_duration: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if topic := self.subscription_topic:
            builder.add_edge(self, clazz=GcpPubSubTopic, reverse=True, name=topic)


@define(eq=False, slots=False)
class GcpAwsKinesis:
    kind: ClassVar[str] = "gcp_aws_kinesis"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_role_arn": S("awsRoleArn"),
        "consumer_arn": S("consumerArn"),
        "gcp_service_account": S("gcpServiceAccount"),
        "state": S("state"),
        "stream_arn": S("streamArn"),
    }
    aws_role_arn: Optional[str] = field(default=None)
    consumer_arn: Optional[str] = field(default=None)
    gcp_service_account: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    stream_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAvroFormat:
    kind: ClassVar[str] = "gcp_avro_format"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpPubSubAvroFormat:
    kind: ClassVar[str] = "gcp_pub_sub_avro_format"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpCloudStorage:
    kind: ClassVar[str] = "gcp_cloud_storage"
    mapping: ClassVar[Dict[str, Bender]] = {
        "avro_format": S("avroFormat", default={}) >> Bend(GcpAvroFormat.mapping),
        "bucket": S("bucket"),
        "match_glob": S("matchGlob"),
        "minimum_object_create_time": S("minimumObjectCreateTime"),
        "pubsub_avro_format": S("pubsubAvroFormat", default={}) >> Bend(GcpPubSubAvroFormat.mapping),
        "state": S("state"),
        "text_format": S("textFormat", "delimiter"),
    }
    avro_format: Optional[GcpAvroFormat] = field(default=None)
    bucket: Optional[str] = field(default=None)
    match_glob: Optional[str] = field(default=None)
    minimum_object_create_time: Optional[datetime] = field(default=None)
    pubsub_avro_format: Optional[GcpPubSubAvroFormat] = field(default=None)
    state: Optional[str] = field(default=None)
    text_format: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpIngestionDataSourceSettings:
    kind: ClassVar[str] = "gcp_ingestion_data_source_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "aws_kinesis": S("awsKinesis", default={}) >> Bend(GcpAwsKinesis.mapping),
        "cloud_storage": S("cloudStorage", default={}) >> Bend(GcpCloudStorage.mapping),
        "platform_logs_settings": S("platformLogsSettings", "severity"),
    }
    aws_kinesis: Optional[GcpAwsKinesis] = field(default=None)
    cloud_storage: Optional[GcpCloudStorage] = field(default=None)
    platform_logs_settings: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpMessageStoragePolicy:
    kind: ClassVar[str] = "gcp_message_storage_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allowed_persistence_regions": S("allowedPersistenceRegions", default=[]),
        "enforce_in_transit": S("enforceInTransit"),
    }
    allowed_persistence_regions: Optional[List[str]] = field(default=None)
    enforce_in_transit: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpSchemaSettings:
    kind: ClassVar[str] = "gcp_schema_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "encoding": S("encoding"),
        "first_revision_id": S("firstRevisionId"),
        "last_revision_id": S("lastRevisionId"),
        "schema": S("schema"),
    }
    encoding: Optional[str] = field(default=None)
    first_revision_id: Optional[str] = field(default=None)
    last_revision_id: Optional[str] = field(default=None)
    schema: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPubSubTopic(GcpResource):
    kind: ClassVar[str] = "gcp_pubsub_topic"
    _kind_display: ClassVar[str] = "GCP Pub/Sub Topic"
    _kind_description: ClassVar[str] = (
        "GCP Pub/Sub Topic is a messaging entity within the Google Cloud Pub/Sub service that acts as a conduit for messages sent by publishers. "
        "It allows applications to send messages to a centralized topic, which are then delivered to one or more subscribing applications. "
        "Pub/Sub Topics facilitate decoupled communication, enabling scalable and reliable messaging patterns for distributed systems."
    )  # fmt: skip
    _kind_service: ClassVar[Optional[str]] = service_name
    _docs_url: ClassVar[str] = "https://cloud.google.com/pubsub/docs/overview"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "queue", "group": "compute"}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="pubsub",
        version="v1",
        accessors=["projects", "topics"],
        action="list",
        request_parameter={"project": "projects/{project}"},
        request_parameter_in={"project"},
        response_path="topics",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "ingestion_data_source_settings": S("ingestionDataSourceSettings", default={})
        >> Bend(GcpIngestionDataSourceSettings.mapping),
        "kms_key_name": S("kmsKeyName"),
        "message_retention_duration": S("messageRetentionDuration"),
        "message_storage_policy": S("messageStoragePolicy", default={}) >> Bend(GcpMessageStoragePolicy.mapping),
        "satisfies_pzs": S("satisfiesPzs"),
        "schema_settings": S("schemaSettings", default={}) >> Bend(GcpSchemaSettings.mapping),
        "state": S("state"),
    }
    ingestion_data_source_settings: Optional[GcpIngestionDataSourceSettings] = field(default=None)
    kms_key_name: Optional[str] = field(default=None)
    message_retention_duration: Optional[str] = field(default=None)
    message_storage_policy: Optional[GcpMessageStoragePolicy] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    schema_settings: Optional[GcpSchemaSettings] = field(default=None)
    state: Optional[str] = field(default=None)


resources: List[Type[GcpResource]] = [GcpPubSubSnapshot, GcpPubSubSubscription, GcpPubSubTopic]
