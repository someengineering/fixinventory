from datetime import datetime
from typing import ClassVar, Dict, Optional, Type, List, Any

from attr import define, field as attrs_field, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, GraphBuilder, AwsResource, parse_json
from fix_plugin_aws.resource.cloudwatch import AwsCloudwatchLogGroup
from fix_plugin_aws.resource.iam import AwsIamRole
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.s3 import AwsS3Bucket
from fix_plugin_aws.resource.sns import AwsSnsTopic
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import ModelReference, EdgeType
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, bend, ForallBend, EmptyToNone
from fixlib.types import Json

service_name = "cloudtrail"


@define(eq=False, slots=False)
class AwsCloudTrailDataResource:
    kind: ClassVar[str] = "aws_cloud_trail_data_resource"
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("Type"), "values": S("Values", default=[])}
    type: Optional[str] = field(default=None, metadata={"description": "The resource type in which you want to log data events."})  # fmt: skip
    values: Optional[List[str]] = field(factory=list, metadata={"description": "An array of Amazon Resource Name (ARN) strings or partial ARN strings for the specified objects."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudTrailEventSelector:
    kind: ClassVar[str] = "aws_cloud_trail_event_selector"
    mapping: ClassVar[Dict[str, Bender]] = {
        "read_write_type": S("ReadWriteType"),
        "include_management_events": S("IncludeManagementEvents"),
        "data_resources": S("DataResources", default=[]) >> ForallBend(AwsCloudTrailDataResource.mapping),
        "exclude_management_event_sources": S("ExcludeManagementEventSources", default=[]),
    }
    read_write_type: Optional[str] = field(default=None, metadata={"description": "Specify if you want your trail to log read-only events, write-only events, or all."})  # fmt: skip
    include_management_events: Optional[bool] = field(default=None, metadata={"description": "Specify if you want your event selector to include management events for your trail."})  # fmt: skip
    data_resources: Optional[List[AwsCloudTrailDataResource]] = field(factory=list, metadata={"description": "CloudTrail supports data event logging for Amazon S3 objects, Lambda functions, and Amazon DynamoDB tables with basic event selectors."})  # fmt: skip
    exclude_management_event_sources: Optional[List[str]] = field(factory=list, metadata={"description": "An optional list of service event sources from which you do not want management events to be logged on your trail."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudTrailAdvancedFieldSelector:
    kind: ClassVar[str] = "aws_cloud_trail_advanced_field_selector"
    mapping: ClassVar[Dict[str, Bender]] = {
        "selector_field": S("Field"),
        "equals": S("Equals", default=[]),
        "starts_with": S("StartsWith", default=[]),
        "ends_with": S("EndsWith", default=[]),
        "not_equals": S("NotEquals", default=[]),
        "not_starts_with": S("NotStartsWith", default=[]),
        "not_ends_with": S("NotEndsWith", default=[]),
    }
    selector_field: Optional[str] = field(default=None, metadata={"description": "A field in a CloudTrail event record on which to filter events to be logged."})  # fmt: skip
    equals: Optional[List[str]] = field(factory=list, metadata={"description": "An operator that includes events that match the exact value of the event record field specified as the value of Field. This is the only valid operator that you can use with the readOnly, eventCategory, and resources.type fields."})  # fmt: skip
    starts_with: Optional[List[str]] = field(factory=list, metadata={"description": "An operator that includes events that match the first few characters of the event record field specified as the value of Field."})  # fmt: skip
    ends_with: Optional[List[str]] = field(factory=list, metadata={"description": "An operator that includes events that match the last few characters of the event record field specified as the value of Field."})  # fmt: skip
    not_equals: Optional[List[str]] = field(factory=list, metadata={"description": "An operator that excludes events that match the exact value of the event record field specified as the value of Field."})  # fmt: skip
    not_starts_with: Optional[List[str]] = field(factory=list, metadata={"description": "An operator that excludes events that match the first few characters of the event record field specified as the value of Field."})  # fmt: skip
    not_ends_with: Optional[List[str]] = field(factory=list, metadata={"description": "An operator that excludes events that match the last few characters of the event record field specified as the value of Field."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudTrailAdvancedEventSelector:
    kind: ClassVar[str] = "aws_cloud_trail_advanced_event_selector"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "field_selectors": S("FieldSelectors", default=[]) >> ForallBend(AwsCloudTrailAdvancedFieldSelector.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "An optional, descriptive name for an advanced event selector, such as Log data events for only two S3 buckets."})  # fmt: skip
    field_selectors: Optional[List[AwsCloudTrailAdvancedFieldSelector]] = field(factory=list, metadata={"description": "Contains all selector statements in an advanced event selector."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudTrailEventSelectors:
    kind: ClassVar[str] = "aws_cloud_trail_event_selectors"
    mapping: ClassVar[Dict[str, Bender]] = {
        "event_selectors": S("EventSelectors", default=[]) >> ForallBend(AwsCloudTrailEventSelector.mapping),
        "advanced_event_selectors": S("AdvancedEventSelectors", default=[])
        >> ForallBend(AwsCloudTrailAdvancedEventSelector.mapping),
    }
    event_selectors: Optional[List[AwsCloudTrailEventSelector]] = field(factory=list, metadata={"description": "The event selectors that are configured for the trail."})  # fmt: skip
    advanced_event_selectors: Optional[List[AwsCloudTrailAdvancedEventSelector]] = field(factory=list, metadata={"description": "The advanced event selectors that are configured for the trail."})  # fmt: skip


@define(eq=False, slots=False)
class AwsCloudTrailStatus:
    kind: ClassVar[str] = "aws_cloud_trail_status"
    kind_display: ClassVar[str] = "AWS CloudTrail Status"
    kind_description: ClassVar[str] = (
        "CloudTrail Status reflects the current operational status, including logging activities"
        " and any errors, of a specified CloudTrail trail."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "is_logging": S("IsLogging"),
        "latest_delivery_error": S("LatestDeliveryError"),
        "latest_notification_error": S("LatestNotificationError"),
        "latest_delivery_time": S("LatestDeliveryTime") >> EmptyToNone,
        "latest_notification_time": S("LatestNotificationTime") >> EmptyToNone,
        "start_logging_time": S("StartLoggingTime") >> EmptyToNone,
        "stop_logging_time": S("StopLoggingTime") >> EmptyToNone,
        "latest_cloud_watch_logs_delivery_error": S("LatestCloudWatchLogsDeliveryError"),
        "latest_cloud_watch_logs_delivery_time": S("LatestCloudWatchLogsDeliveryTime"),
        "latest_digest_delivery_time": S("LatestDigestDeliveryTime") >> EmptyToNone,
        "latest_digest_delivery_error": S("LatestDigestDeliveryError"),
        "latest_delivery_attempt_time": S("LatestDeliveryAttemptTime") >> EmptyToNone,
        "latest_notification_attempt_time": S("LatestNotificationAttemptTime") >> EmptyToNone,
        "latest_notification_attempt_succeeded": S("LatestNotificationAttemptSucceeded") >> EmptyToNone,
        "latest_delivery_attempt_succeeded": S("LatestDeliveryAttemptSucceeded") >> EmptyToNone,
        "time_logging_started": S("TimeLoggingStarted") >> EmptyToNone,
        "time_logging_stopped": S("TimeLoggingStopped") >> EmptyToNone,
    }
    is_logging: Optional[bool] = attrs_field(default=None)
    latest_delivery_error: Optional[str] = attrs_field(default=None)
    latest_notification_error: Optional[str] = attrs_field(default=None)
    latest_delivery_time: Optional[datetime] = attrs_field(default=None)
    latest_notification_time: Optional[datetime] = attrs_field(default=None)
    start_logging_time: Optional[datetime] = attrs_field(default=None)
    stop_logging_time: Optional[datetime] = attrs_field(default=None)
    latest_cloud_watch_logs_delivery_error: Optional[str] = attrs_field(default=None)
    latest_cloud_watch_logs_delivery_time: Optional[datetime] = attrs_field(default=None)
    latest_digest_delivery_time: Optional[datetime] = attrs_field(default=None)
    latest_digest_delivery_error: Optional[str] = attrs_field(default=None)
    latest_delivery_attempt_time: Optional[datetime] = attrs_field(default=None)
    latest_notification_attempt_time: Optional[datetime] = attrs_field(default=None)
    latest_notification_attempt_succeeded: Optional[datetime] = attrs_field(default=None)
    latest_delivery_attempt_succeeded: Optional[datetime] = attrs_field(default=None)
    time_logging_started: Optional[datetime] = attrs_field(default=None)
    time_logging_stopped: Optional[datetime] = attrs_field(default=None)


@define(eq=False, slots=False)
class AwsCloudTrail(AwsResource):
    kind: ClassVar[str] = "aws_cloud_trail"
    kind_display: ClassVar[str] = "AWS CloudTrail"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudtrail/home?region={region}#/trails/{arn}:trail/{name}", "arn_tpl": "arn:{partition}:cloudtrail:{region}:{account}:trail/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudTrail is a service that enables governance, compliance, operational"
        " auditing, and risk auditing of your AWS account."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-trails", "Trails")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        "name": S("Name"),
        "trail_s3_bucket_name": S("S3BucketName"),
        "trail_s3_key_prefix": S("S3KeyPrefix"),
        "trail_sns_topic_name": S("SnsTopicName"),
        "trail_sns_topic_arn": S("SnsTopicARN"),
        "trail_include_global_service_events": S("IncludeGlobalServiceEvents"),
        "trail_is_multi_region_trail": S("IsMultiRegionTrail"),
        "trail_home_region": S("HomeRegion"),
        "arn": S("TrailARN"),
        "trail_log_file_validation_enabled": S("LogFileValidationEnabled"),
        "trail_cloud_watch_logs_log_group_arn": S("CloudWatchLogsLogGroupArn"),
        "trail_cloud_watch_logs_role_arn": S("CloudWatchLogsRoleArn"),
        "trail_kms_key_id": S("KmsKeyId"),
        "trail_has_custom_event_selectors": S("HasCustomEventSelectors"),
        "trail_has_insight_selectors": S("HasInsightSelectors"),
        "trail_is_organization_trail": S("IsOrganizationTrail"),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_s3_bucket", "aws_sns_topic", "aws_kms_key"]},
    }
    trail_s3_bucket_name: Optional[str] = attrs_field(default=None)
    trail_s3_key_prefix: Optional[str] = attrs_field(default=None)
    trail_sns_topic_name: Optional[str] = attrs_field(default=None)
    trail_sns_topic_arn: Optional[str] = attrs_field(default=None)
    trail_include_global_service_events: Optional[bool] = attrs_field(default=None)
    trail_is_multi_region_trail: Optional[bool] = attrs_field(default=None)
    trail_home_region: Optional[str] = attrs_field(default=None)
    arn: Optional[str] = attrs_field(default=None)
    trail_log_file_validation_enabled: Optional[bool] = attrs_field(default=None)
    trail_cloud_watch_logs_log_group_arn: Optional[str] = attrs_field(default=None)
    trail_cloud_watch_logs_role_arn: Optional[str] = attrs_field(default=None)
    trail_kms_key_id: Optional[str] = attrs_field(default=None)
    trail_has_custom_event_selectors: Optional[bool] = attrs_field(default=None)
    trail_has_insight_selectors: Optional[bool] = attrs_field(default=None)
    trail_is_organization_trail: Optional[bool] = attrs_field(default=None)
    trail_status: Optional[AwsCloudTrailStatus] = attrs_field(default=None, metadata=dict(ignore_history=True))
    trail_event_selectors: Optional[AwsCloudTrailEventSelectors] = attrs_field(default=None)
    trail_insight_selectors: Optional[List[str]] = attrs_field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-trails"),
            AwsApiSpec(service_name, "get-trail"),
            AwsApiSpec(service_name, "get-trail-status"),
            AwsApiSpec(service_name, "list-tags"),
            AwsApiSpec(service_name, "get-event-selectors"),
            AwsApiSpec(service_name, "get-insight-selectors"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def collect_trail(trail_arn: str) -> None:
            if trail_raw := builder.client.get(service_name, "get-trail", "Trail", Name=trail_arn):
                if instance := AwsCloudTrail.from_api(trail_raw, builder):
                    builder.add_node(instance, js)
                    collect_status(instance)
                    collect_tags(instance)
                    if instance.trail_has_custom_event_selectors:
                        collect_event_selectors(instance)
                    if instance.trail_has_insight_selectors:
                        collect_insight_selectors(instance)

        def collect_event_selectors(trail: AwsCloudTrail) -> None:
            if esj := builder.client.get(service_name, "get-event-selectors", TrailName=trail.arn):
                if es := parse_json(esj, AwsCloudTrailEventSelectors, builder, AwsCloudTrailEventSelectors.mapping):
                    trail.trail_event_selectors = es

        def collect_insight_selectors(trail: AwsCloudTrail) -> None:
            trail.trail_insight_selectors = []
            for item in builder.client.list(
                service_name,
                "get-insight-selectors",
                "InsightSelectors",
                TrailName=trail.arn,
                expected_errors=["InsightNotEnabledException"],
            ):
                trail.trail_insight_selectors.append(item["InsightType"])

        def collect_status(trail: AwsCloudTrail) -> None:
            status_raw = builder.client.get(service_name, "get-trail-status", Name=trail.arn)
            mapped = bend(AwsCloudTrailStatus.mapping, status_raw)
            if status := parse_json(mapped, AwsCloudTrailStatus, builder):
                trail.trail_status = status
                trail.ctime = status.start_logging_time
                trail.mtime = status.latest_delivery_time

        def collect_tags(trail: AwsCloudTrail) -> None:
            for tr in builder.client.list(
                service_name,
                "list-tags",
                "ResourceTagList",
                ResourceIdList=[trail.arn],
                expected_errors=["CloudTrailARNInvalidException", "AccessDeniedException"],
            ):
                trail.tags = bend(S("TagsList", default=[]) >> ToDict(), tr)

        for js in json:
            arn = js["TrailARN"]
            # list trails will return multi account trails in all regions
            if js["HomeRegion"] == builder.region.name and builder.account.id in arn:
                # only collect trails in the current account and current region
                builder.submit_work(service_name, collect_trail, arn)
            else:
                # add a deferred edge to the trails in another account or region
                builder.add_deferred_edge(
                    builder.region, EdgeType.default, f'is(aws_cloud_trail) and reported.arn=="{arn}"'
                )

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if s3 := self.trail_s3_bucket_name:
            builder.add_edge(self, clazz=AwsS3Bucket, name=s3)
        if sns := self.trail_sns_topic_arn:
            builder.add_edge(self, clazz=AwsSnsTopic, arn=sns)
        if kms := self.trail_kms_key_id:
            builder.add_edge(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(kms))
        if log_group := self.trail_cloud_watch_logs_log_group_arn:
            builder.add_edge(self, clazz=AwsCloudwatchLogGroup, arn=log_group)
        if log_role := self.trail_cloud_watch_logs_role_arn:
            builder.add_edge(self, clazz=AwsIamRole, arn=log_role)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(service_name, "add-tags", ResourceId=self.arn, TagsList=[{"Key": key, "Value": value}])
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(service_name, "remove-tags", ResourceId=self.arn, TagsList=[{"Key": key}])
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(service_name, "delete-trail", Name=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "add-tags"),
            AwsApiSpec(service_name, "remove-tags"),
            AwsApiSpec(service_name, "delete-trail"),
        ]


resources: List[Type[AwsResource]] = [AwsCloudTrail]
