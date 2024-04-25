from datetime import timedelta
from typing import ClassVar, Dict, List, Optional, Type, Any
from attrs import define, field
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchMetricData,
    AwsCloudwatchQuery,
    calculate_min_max_avg,
    update_resource_metrics,
)
from fix_plugin_aws.resource.iam import AwsIamRole
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.utils import MetricNormalization, ToDict
from fixlib.baseresources import EdgeType, MetricName, MetricUnit, ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import F, Bender, S, bend, ParseJson, Sorted
from fixlib.types import Json

service_name = "sns"


@define(eq=False, slots=False)
class AwsSnsTopic(AwsResource):
    kind: ClassVar[str] = "aws_sns_topic"
    kind_display: ClassVar[str] = "AWS SNS Topic"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/sns/v3/home?region={region}#/topic/{arn}", "arn_tpl": "arn:{partition}:sns:{region}:{account}:{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS SNS (Simple Notification Service) Topic is a publish-subscribe messaging"
        " service provided by Amazon Web Services. It allows applications, services,"
        " and devices to send and receive notifications via email, SMS, push"
        " notifications, and more."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-topics", "Topics")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "delete": ["aws_kms_key"],
        },
        "successors": {"default": ["aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("TopicArn"),
        "name": S("DisplayName"),
        "arn": S("TopicArn"),
        "topic_subscriptions_confirmed": S("SubscriptionsConfirmed") >> F(lambda x: int(x)),
        "topic_subscriptions_deleted": S("SubscriptionsDeleted") >> F(lambda x: int(x)),
        "topic_subscriptions_pending": S("SubscriptionsPending") >> F(lambda x: int(x)),
        "topic_policy": S("Policy") >> ParseJson() >> Sorted(sort_list=True),
        "topic_delivery_policy": S("DeliveryPolicy"),
        "topic_effective_delivery_policy": S("EffectiveDeliveryPolicy"),
        "topic_owner": S("Owner"),
        "topic_kms_master_key_id": S("KmsMasterKeyId"),
        "topic_fifo_topic": S("FifoTopic") >> F(lambda x: x == "true"),
        "topic_content_based_deduplication": S("ContentBasedDeduplication") >> F(lambda x: x == "true"),
    }
    topic_subscriptions_confirmed: Optional[int] = field(default=None)
    topic_subscriptions_deleted: Optional[int] = field(default=None)
    topic_subscriptions_pending: Optional[int] = field(default=None)
    topic_policy: Optional[Json] = field(default=None)
    topic_delivery_policy: Optional[str] = field(default=None)
    topic_effective_delivery_policy: Optional[str] = field(default=None)
    topic_owner: Optional[str] = field(default=None)
    topic_kms_master_key_id: Optional[str] = field(default=None)
    topic_fifo_topic: Optional[bool] = field(default=None)
    topic_content_based_deduplication: Optional[bool] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "get-topic-attributes"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(topic: AwsSnsTopic) -> None:
            tags = builder.client.list(
                service_name, "list-tags-for-resource", result_name="Tags", ResourceArn=topic.arn
            )
            if tags:
                topic.tags = bend(ToDict(), tags)

        for entry in json:
            topic = builder.client.get(
                service_name, "get-topic-attributes", TopicArn=entry["TopicArn"], result_name="Attributes"
            )
            if topic:
                if topic_instance := cls.from_api(topic, builder):
                    builder.add_node(topic_instance, topic)
                    builder.submit_work(service_name, add_tags, topic_instance)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        sns_topics = {sns.id: sns for sns in builder.nodes(clazz=AwsSnsTopic) if sns.region().id == builder.region.id}
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at
        period = min(timedelta(minutes=5), delta)

        for sns_id, sns_topic in sns_topics.items():
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric_name,
                        namespace="AWS/SNS",
                        period=period,
                        ref_id=sns_id,
                        stat="Sum",
                        unit="Count",
                        TopicName=sns_topic.name or sns_topic.safe_name,
                    )
                    for metric_name in [
                        "NumberOfMessagesPublished",
                        "NumberOfNotificationsDelivered",
                        "NumberOfNotificationsFailed",
                    ]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="PublishSize",
                        namespace="AWS/SNS",
                        period=delta,
                        ref_id=sns_id,
                        stat=stat,
                        unit="Bytes",
                        TopicName=sns_topic.name or sns_topic.safe_name,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )
        metric_normalizers = {
            "NumberOfMessagesPublished": MetricNormalization(
                metric_name=MetricName.NumberOfMessagesPublished,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "NumberOfNotificationsDelivered": MetricNormalization(
                metric_name=MetricName.NumberOfNotificationsDelivered,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "NumberOfNotificationsFailed": MetricNormalization(
                metric_name=MetricName.NumberOfNotificationsFailed,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "PublishSize": MetricNormalization(
                metric_name=MetricName.PublishSize,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(sns_topics, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.topic_kms_master_key_id:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                id=AwsKmsKey.normalise_id(self.topic_kms_master_key_id),
            )

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name,
            action="tag-resource",
            result_name=None,
            ResourceArn=self.arn,
            Tags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=service_name, action="untag-resource", result_name=None, ResourceArn=self.arn, TagKeys=[key]
        )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="delete-topic", result_name=None, TopicArn=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-topic"),
        ]


@define(eq=False, slots=False)
class AwsSnsSubscription(AwsResource):
    kind: ClassVar[str] = "aws_sns_subscription"
    kind_display: ClassVar[str] = "AWS SNS Subscription"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/sns/v3/home?region={region}#/topic/{arn}", "arn_tpl": "arn:{partition}:sns:{region}:{account}:{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SNS Subscriptions in AWS allow applications to receive messages from topics"
        " of interest using different protocols such as HTTP, email, SMS, or Lambda"
        " function invocation."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-subscriptions", "Subscriptions")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_sns_topic", "aws_iam_role"], "delete": ["aws_iam_role"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("SubscriptionArn"),
        "name": S("SubscriptionArn"),
        "arn": S("SubscriptionArn"),
        "subscription_confirmation_was_authenticated": S("ConfirmationWasAuthenticated") >> F(lambda x: x == "true"),
        "subscription_delivery_policy": S("DeliveryPolicy"),
        "subscription_effective_delivery_policy": S("EffectiveDeliveryPolicy"),
        "subscription_filter_policy": S("FilterPolicy"),
        "subscription_owner": S("Owner"),
        "subscription_pending_confirmation": S("PendingConfirmation") >> F(lambda x: x == "true"),
        "subscription_raw_message_delivery": S("RawMessageDelivery") >> F(lambda x: x == "true"),
        "subscription_redrive_policy": S("RedrivePolicy"),
        "subscription_topic_arn": S("TopicArn"),
        "subscription_role_arn": S("SubscriptionRoleArn"),
    }
    subscription_confirmation_was_authenticated: Optional[bool] = field(default=None)
    subscription_delivery_policy: Optional[str] = field(default=None)
    subscription_effective_delivery_policy: Optional[str] = field(default=None)
    subscription_filter_policy: Optional[str] = field(default=None)
    subscription_owner: Optional[str] = field(default=None)
    subscription_pending_confirmation: Optional[bool] = field(default=None)
    subscription_raw_message_delivery: Optional[bool] = field(default=None)
    subscription_redrive_policy: Optional[str] = field(default=None)
    subscription_topic_arn: Optional[str] = field(default=None)
    subscription_role_arn: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "get-subscription-attributes"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for entry in json:
            subscription = builder.client.get(
                service_name,
                "get-subscription-attributes",
                SubscriptionArn=entry["SubscriptionArn"],
                result_name="Attributes",
                expected_errors=["InvalidParameter", "NotFound"],
            )
            if subscription:
                if subscription_instance := cls.from_api(subscription, builder):
                    builder.add_node(subscription_instance, subscription)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.subscription_topic_arn:
            builder.add_edge(
                self,
                reverse=True,
                clazz=AwsSnsTopic,
                arn=self.subscription_topic_arn,
            )
        if self.subscription_role_arn:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=self.subscription_role_arn
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="unsubscribe", result_name=None, SubscriptionArn=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "unsubscribe")]


@define(eq=False, slots=False)
class AwsSnsEndpoint(AwsResource):
    # collection of endpoint resources happens in AwsSnsPlatformApplication.collect()
    kind: ClassVar[str] = "aws_sns_endpoint"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sns:{region}:{account}:endpoint/{id}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS SNS Endpoint"
    kind_description: ClassVar[str] = (
        "An endpoint in the AWS Simple Notification Service (SNS), which is used to"
        " send push notifications or SMS messages to mobile devices or other"
        " applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Arn"),
        "arn": S("Arn"),
        "endpoint_enabled": S("Enabled") >> F(lambda x: x == "true"),
        "endpoint_token": S("Token"),
    }
    endpoint_enabled: Optional[bool] = field(default=None)
    endpoint_token: Optional[str] = field(default=None)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="delete-endpoint", result_name=None, EndpointArn=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "delete-endpoint")]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsSnsPlatformApplication(AwsResource):
    kind: ClassVar[str] = "aws_sns_platform_application"
    kind_display: ClassVar[str] = "AWS SNS Platform Application"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sns:{region}:{account}:platform-application/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS SNS Platform Application is a service that allows you to create a"
        " platform application and register it with Amazon SNS so that your"
        " application can receive push notifications."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-platform-applications", "PlatformApplications", expected_errors=["InvalidAction"]
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_sns_topic", "aws_sns_endpoint"],
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Arn"),
        "arn": S("Arn"),
        "application_apple_certificate_expiry_date": S("AppleCertificateExpiryDate"),
        "application_apple_platform_team_id": S("ApplePlatformTeamID"),
        "application_apple_platform_bundle_id": S("ApplePlatformBundleID"),
        "application_event_endpoint_created": S("EventEndpointCreated"),
        "application_event_endpoint_deleted": S("EventEndpointDeleted"),
        "application_event_endpoint_updated": S("EventEndpointUpdated"),
        "application_event_endpoint_failure": S("EventDeliveryFailure"),
    }
    application_apple_certificate_expiry_date: Optional[str] = field(default=None)
    application_apple_platform_team_id: Optional[str] = field(default=None)
    application_apple_platform_bundle_id: Optional[str] = field(default=None)
    application_event_endpoint_created: Optional[str] = field(default=None)
    application_event_endpoint_deleted: Optional[str] = field(default=None)
    application_event_endpoint_updated: Optional[str] = field(default=None)
    application_event_endpoint_failure: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "get-platform-application-attributes"),
            AwsApiSpec(service_name, "list-endpoints-by-platform-application"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for entry in json:
            app_arn = entry["PlatformApplicationArn"]
            app = builder.client.get(
                service_name,
                "get-platform-application-attributes",
                PlatformApplicationArn=app_arn,
                result_name="Attributes",
            )
            if app:
                app["Arn"] = app_arn
                if app_instance := cls.from_api(app, builder):
                    builder.add_node(app_instance, app)

                    endpoints = builder.client.list(
                        service_name,
                        "list-endpoints-by-platform-application",
                        PlatformApplicationArn=app_arn,
                        result_name="Endpoints",
                    )
                    for endpoint in endpoints:
                        attributes = endpoint["Attributes"]
                        attributes["Arn"] = endpoint["EndpointArn"]
                        if endpoint_instance := AwsSnsEndpoint.from_api(attributes, builder):
                            builder.add_node(endpoint_instance, attributes)
                            builder.add_edge(app_instance, edge_type=EdgeType.default, node=endpoint_instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for topic in [
            self.application_event_endpoint_created,
            self.application_event_endpoint_deleted,
            self.application_event_endpoint_updated,
            self.application_event_endpoint_failure,
        ]:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AwsSnsTopic, arn=topic)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-platform-application",
            result_name=None,
            PlatformApplicationArn=self.arn,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "delete-platform-application")]


resources: List[Type[AwsResource]] = [AwsSnsTopic, AwsSnsSubscription, AwsSnsPlatformApplication, AwsSnsEndpoint]
