from typing import ClassVar, Dict, List, Optional, Type
from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.iam import AwsIamRole
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import EdgeType, ModelReference
from resotolib.json_bender import F, Bender, S, bend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsSnsTopic(AwsResource):
    kind: ClassVar[str] = "aws_sns_topic"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sns", "list-topics", "Topics")
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
        "topic_policy": S("Policy"),
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
    topic_policy: Optional[str] = field(default=None)
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
            AwsApiSpec("sns", "get-topic-attributes"),
            AwsApiSpec("sns", "list-tags-for-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(topic: AwsSnsTopic) -> None:
            tags = builder.client.list("sns", "list-tags-for-resource", result_name=None, ResourceArn=topic.arn)
            if tags:
                topic.tags = bend(S("Tags", default=[]) >> ToDict(), tags[0])

        for entry in json:
            topic = builder.client.get(
                "sns", "get-topic-attributes", TopicArn=entry["TopicArn"], result_name="Attributes"
            )
            if topic:
                topic_instance = cls.from_api(topic)
                builder.add_node(topic_instance, topic)
                builder.submit_work(add_tags, topic_instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.topic_kms_master_key_id:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                id=AwsKmsKey.normalise_id(self.topic_kms_master_key_id),
            )

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service="sns",
            action="tag-resource",
            result_name=None,
            ResourceArn=self.arn,
            Tags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(aws_service="sns", action="untag-resource", result_name=None, ResourceArn=self.arn, TagKeys=[key])
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="sns", action="delete-topic", result_name=None, TopicArn=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("sns", "tag-resource"),
            AwsApiSpec("sns", "untag-resource"),
            AwsApiSpec("sns", "delete-topic"),
        ]


@define(eq=False, slots=False)
class AwsSnsSubscription(AwsResource):
    kind: ClassVar[str] = "aws_sns_subscription"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sns", "list-subscriptions", "Subscriptions")
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
            AwsApiSpec("sns", "get-subscription-attributes"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for entry in json:
            subscription = builder.client.get(
                "sns", "get-subscription-attributes", SubscriptionArn=entry["SubscriptionArn"], result_name="Attributes"
            )
            if subscription:
                subscription_instance = cls.from_api(subscription)
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="sns", action="unsubscribe", result_name=None, SubscriptionArn=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("sns", "unsubscribe")]


@define(eq=False, slots=False)
class AwsSnsEndpoint(AwsResource):
    # collection of endpoint resources happens in AwsSnsPlatformApplication.collect()
    kind: ClassVar[str] = "aws_sns_endpoint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Arn"),
        "arn": S("Arn"),
        "endpoint_enabled": S("Enabled") >> F(lambda x: x == "true"),
        "endpoint_token": S("Token"),
    }
    endpoint_enabled: Optional[bool] = field(default=None)
    endpoint_token: Optional[str] = field(default=None)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="sns", action="delete-endpoint", result_name=None, EndpointArn=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("sns", "delete-endpoint")]


@define(eq=False, slots=False)
class AwsSnsPlatformApplication(AwsResource):
    kind: ClassVar[str] = "aws_sns_platform_application"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "sns", "list-platform-applications", "PlatformApplications", expected_errors=["InvalidAction"]
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
            AwsApiSpec("sns", "get-platform-application-attributes"),
            AwsApiSpec("sns", "list-endpoints-by-platform-application"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for entry in json:
            app_arn = entry["PlatformApplicationArn"]
            app = builder.client.get(
                "sns",
                "get-platform-application-attributes",
                PlatformApplicationArn=app_arn,
                result_name="Attributes",
            )
            if app:
                app["Arn"] = app_arn
                app_instance = cls.from_api(app)
                builder.add_node(app_instance, app)

                endpoints = builder.client.list(
                    "sns",
                    "list-endpoints-by-platform-application",
                    PlatformApplicationArn=app_arn,
                    result_name="Endpoints",
                )
                for endpoint in endpoints:
                    attributes = endpoint["Attributes"]
                    attributes["Arn"] = endpoint["EndpointArn"]
                    endpoint_instance = AwsSnsEndpoint.from_api(attributes)
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="sns", action="delete-platform-application", result_name=None, PlatformApplicationArn=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("sns", "delete-platform-application")]


resources: List[Type[AwsResource]] = [AwsSnsTopic, AwsSnsSubscription, AwsSnsPlatformApplication, AwsSnsEndpoint]
