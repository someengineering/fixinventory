import re
from datetime import datetime, timedelta
from typing import ClassVar, Dict, List, Optional, Type, Tuple

from attr import define, field

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference
from resotolib.graph import Graph
from resotolib.json import from_json
from resotolib.json_bender import S, Bend, Bender, ForallBend, bend, F, SecondsFromEpochToDatetime
from resotolib.types import Json
from resotolib.utils import chunks

service_name = "cloudwatch"


# noinspection PyUnresolvedReferences
class CloudwatchTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name,
            action="tag-resource",
            result_name=None,
            ResourceARN=self.arn,  # type: ignore
            Tags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=service_name,
            action="untag-resource",
            result_name=None,
            ResourceARN=self.arn,  # type: ignore
            TagKeys=[key],
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "tag-resource"), AwsApiSpec(service_name, "untag-resource")]


# noinspection PyUnresolvedReferences
class LogsTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if arn := self.arn:  # type: ignore
            if arn.endswith(":*"):
                arn = arn[:-2]
            client.call(
                aws_service="logs",
                action="tag-resource",
                result_name=None,
                resourceArn=arn,
                tags={key: value},
            )
            return True
        else:
            return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if arn := self.arn:  # type: ignore
            if arn.endswith(":*"):
                arn = arn[:-2]
            client.call(
                aws_service="logs",
                action="untag-resource",
                result_name=None,
                resourceArn=arn,
                tagKeys=[key],
            )
            return True
        else:
            return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("logs", "tag-resource"), AwsApiSpec("logs", "untag-resource")]


@define(eq=False, slots=False)
class AwsCloudwatchDimension:
    kind: ClassVar[str] = "aws_cloudwatch_dimension"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "value": S("Value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudwatchMetric:
    kind: ClassVar[str] = "aws_cloudwatch_metric"
    mapping: ClassVar[Dict[str, Bender]] = {
        "namespace": S("Namespace"),
        "metric_name": S("MetricName"),
        "dimensions": S("Dimensions", default=[]) >> ForallBend(AwsCloudwatchDimension.mapping),
    }
    namespace: Optional[str] = field(default=None)
    metric_name: Optional[str] = field(default=None)
    dimensions: List[AwsCloudwatchDimension] = field(factory=list)


@define(eq=False, slots=False)
class AwsCloudwatchMetricStat:
    kind: ClassVar[str] = "aws_cloudwatch_metric_stat"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric": S("Metric") >> Bend(AwsCloudwatchMetric.mapping),
        "period": S("Period"),
        "stat": S("Stat"),
        "unit": S("Unit"),
    }
    metric: Optional[AwsCloudwatchMetric] = field(default=None)
    period: Optional[int] = field(default=None)
    stat: Optional[str] = field(default=None)
    unit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudwatchMetricDataQuery:
    kind: ClassVar[str] = "aws_cloudwatch_metric_data_query"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "metric_stat": S("MetricStat") >> Bend(AwsCloudwatchMetricStat.mapping),
        "expression": S("Expression"),
        "label": S("Label"),
        "return_data": S("ReturnData"),
        "period": S("Period"),
        "account_id": S("AccountId"),
    }
    id: Optional[str] = field(default=None)
    metric_stat: Optional[AwsCloudwatchMetricStat] = field(default=None)
    expression: Optional[str] = field(default=None)
    label: Optional[str] = field(default=None)
    return_data: Optional[bool] = field(default=None)
    period: Optional[int] = field(default=None)
    account_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudwatchAlarm(CloudwatchTaggable, AwsResource):
    kind: ClassVar[str] = "aws_cloudwatch_alarm"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-alarms", "MetricAlarms")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_ec2_instance"], "delete": ["aws_ec2_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AlarmName"),
        "name": S("AlarmName"),
        "mtime": S("AlarmConfigurationUpdatedTimestamp"),
        "arn": S("AlarmArn"),
        "cloudwatch_alarm_description": S("AlarmDescription"),
        "cloudwatch_actions_enabled": S("ActionsEnabled"),
        "cloudwatch_ok_actions": S("OKActions", default=[]),
        "cloudwatch_alarm_actions": S("AlarmActions", default=[]),
        "cloudwatch_insufficient_data_actions": S("InsufficientDataActions", default=[]),
        "cloudwatch_state_value": S("StateValue"),
        "cloudwatch_state_reason": S("StateReason"),
        "cloudwatch_state_reason_data": S("StateReasonData"),
        "cloudwatch_state_updated_timestamp": S("StateUpdatedTimestamp"),
        "cloudwatch_metric_name": S("MetricName"),
        "cloudwatch_namespace": S("Namespace"),
        "cloudwatch_statistic": S("Statistic"),
        "cloudwatch_extended_statistic": S("ExtendedStatistic"),
        "cloudwatch_dimensions": S("Dimensions", default=[]) >> ForallBend(AwsCloudwatchDimension.mapping),
        "cloudwatch_period": S("Period"),
        "cloudwatch_unit": S("Unit"),
        "cloudwatch_evaluation_periods": S("EvaluationPeriods"),
        "cloudwatch_datapoints_to_alarm": S("DatapointsToAlarm"),
        "cloudwatch_threshold": S("Threshold"),
        "cloudwatch_comparison_operator": S("ComparisonOperator"),
        "cloudwatch_treat_missing_data": S("TreatMissingData"),
        "cloudwatch_evaluate_low_sample_count_percentile": S("EvaluateLowSampleCountPercentile"),
        "cloudwatch_metrics": S("Metrics", default=[]) >> ForallBend(AwsCloudwatchMetricDataQuery.mapping),
        "cloudwatch_threshold_metric_id": S("ThresholdMetricId"),
    }
    arn: Optional[str] = field(default=None)
    cloudwatch_alarm_description: Optional[str] = field(default=None)
    cloudwatch_actions_enabled: Optional[bool] = field(default=None)
    cloudwatch_ok_actions: List[str] = field(factory=list)
    cloudwatch_alarm_actions: List[str] = field(factory=list)
    cloudwatch_insufficient_data_actions: List[str] = field(factory=list)
    cloudwatch_state_value: Optional[str] = field(default=None)
    cloudwatch_state_reason: Optional[str] = field(default=None)
    cloudwatch_state_reason_data: Optional[str] = field(default=None)
    cloudwatch_state_updated_timestamp: Optional[datetime] = field(default=None)
    cloudwatch_metric_name: Optional[str] = field(default=None)
    cloudwatch_namespace: Optional[str] = field(default=None)
    cloudwatch_statistic: Optional[str] = field(default=None)
    cloudwatch_extended_statistic: Optional[str] = field(default=None)
    cloudwatch_dimensions: List[AwsCloudwatchDimension] = field(factory=list)
    cloudwatch_period: Optional[int] = field(default=None)
    cloudwatch_unit: Optional[str] = field(default=None)
    cloudwatch_evaluation_periods: Optional[int] = field(default=None)
    cloudwatch_datapoints_to_alarm: Optional[int] = field(default=None)
    cloudwatch_threshold: Optional[float] = field(default=None)
    cloudwatch_comparison_operator: Optional[str] = field(default=None)
    cloudwatch_treat_missing_data: Optional[str] = field(default=None)
    cloudwatch_evaluate_low_sample_count_percentile: Optional[str] = field(default=None)
    cloudwatch_metrics: List[AwsCloudwatchMetricDataQuery] = field(factory=list)
    cloudwatch_threshold_metric_id: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(alarm: AwsCloudwatchAlarm) -> None:
            tags = builder.client.list(service_name, "list-tags-for-resource", "Tags", ResourceARN=alarm.arn)
            if tags:
                alarm.tags = bend(ToDict(), tags)

        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)
            builder.submit_work(service_name, add_tags, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for dimension in self.cloudwatch_dimensions:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, kind="aws_ec2_instance", id=dimension.value
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-alarms", result_name=None, AlarmNames=[self.name])
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-alarms")]


@define(eq=False, slots=False)
class AwsCloudwatchLogGroup(LogsTaggable, AwsResource):
    kind: ClassVar[str] = "aws_cloudwatch_log_group"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("logs", "describe-log-groups", "logGroups")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_kms_key"]},
        "predecessors": {"delete": ["aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("logGroupName"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("logGroupName"),
        "ctime": S("creationTime") >> F(lambda x: x // 1000) >> SecondsFromEpochToDatetime(),
        "arn": S("arn"),
        "group_retention_in_days": S("retentionInDays"),
        "group_metric_filter_count": S("metricFilterCount"),
        "group_stored_bytes": S("storedBytes"),
        "group_data_protection_status": S("dataProtectionStatus"),
    }
    group_retention_in_days: Optional[int] = field(default=None)
    group_metric_filter_count: Optional[int] = field(default=None)
    group_stored_bytes: Optional[int] = field(default=None)
    group_data_protection_status: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if kms_key_id := source.get("kmsKeyId"):
            builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(kms_key_id))

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-log-group")]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-log-group", logGroupName=self.name)
        return True


@define(eq=False, slots=False)
class AwsCloudwatchMetricTransformation:
    kind: ClassVar[str] = "aws_cloudwatch_metric_transformation"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_name": S("metricName"),
        "metric_namespace": S("metricNamespace"),
        "metric_value": S("metricValue"),
        "default_value": S("defaultValue"),
        "dimensions": S("dimensions"),
        "unit": S("unit"),
    }
    metric_name: Optional[str] = field(default=None)
    metric_namespace: Optional[str] = field(default=None)
    metric_value: Optional[str] = field(default=None)
    default_value: Optional[float] = field(default=None)
    dimensions: Optional[Dict[str, str]] = field(default=None)
    unit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudwatchMetricFilter(AwsResource):
    kind: ClassVar[str] = "aws_cloudwatch_metric_filter"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("logs", "describe-metric-filters", "metricFilters")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_cloudwatch_log_group"]},
        "successors": {"default": ["aws_cloudwatch_alarm"], "delete": ["aws_cloudwatch_log_group"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("filterName"),
        "name": S("filterName"),
        "ctime": S("creationTime") >> F(lambda x: x // 1000) >> SecondsFromEpochToDatetime(),
        "filter_pattern": S("filterPattern"),
        "filter_transformations": S("metricTransformations", default=[])
        >> ForallBend(AwsCloudwatchMetricTransformation.mapping),
    }
    filter_pattern: Optional[str] = field(default=None)
    filter_transformations: List[AwsCloudwatchMetricTransformation] = field(factory=list)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if log_group_name := source.get("logGroupName"):
            builder.dependant_node(self, reverse=True, clazz=AwsCloudwatchLogGroup, name=log_group_name)
        for transformation in self.filter_transformations:
            # every metric can be used by multiple alarms
            for alarm in builder.nodes(
                clazz=AwsCloudwatchAlarm,
                cloudwatch_namespace=transformation.metric_namespace,
                cloudwatch_metric_name=transformation.metric_name,
            ):
                builder.add_edge(self, node=alarm)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-metric-filter")]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        if log_group := graph.search_first_parent_class(self, AwsCloudwatchLogGroup):
            client.call(
                aws_service=self.api_spec.service,
                action="delete-metric-filter",
                logGroupName=log_group.name,
                filterName=self.name,
            )
            return True
        return False


@define(hash=True, frozen=True)
class AwsCloudwatchQuery:
    metric_name: str
    namespace: str
    dimensions: Tuple[Tuple[str, str], ...]
    period: timedelta
    ref_id: str
    metric_id: str

    def to_json(self) -> Json:
        return {
            "Id": self.metric_id,
            "MetricStat": {
                "Metric": {
                    "Namespace": self.namespace,
                    "MetricName": self.metric_name,
                    "Dimensions": [{"Name": k, "Value": v} for k, v in self.dimensions],
                },
                "Period": int((self.period.total_seconds() / 60) * 60),  # round to the next 60 seconds
                "Stat": "Sum",
                "Unit": "Count",
            },
            "ReturnData": True,
        }

    @staticmethod
    def create(
        metric_name: str,
        namespace: str,
        period: timedelta,
        ref_id: str,
        metric_id: Optional[str] = None,
        **dimensions: str,
    ) -> "AwsCloudwatchQuery":
        dims = "_".join(f"{k}+{v}" for k, v in dimensions.items())
        rid = metric_id or re.sub("\\W", "_", f"{metric_name}-{namespace}-{dims}".lower())
        # noinspection PyTypeChecker
        return AwsCloudwatchQuery(
            metric_name=metric_name,
            namespace=namespace,
            period=period,
            dimensions=tuple(dimensions.items()),
            ref_id=ref_id,
            metric_id=rid,
        )


@define(eq=False, slots=False)
class AwsCloudwatchMessageData:
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "value": S("Value")}
    code: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudwatchMetricData:
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "label": S("Label"),
        "metric_timestamps": S("Timestamps", default=[]),
        "metric_values": S("Values", default=[]),
        "metric_status_code": S("StatusCode"),
        "metric_messages": S("Messages", default=[]) >> ForallBend(AwsCloudwatchMessageData.mapping),
    }
    id: Optional[str] = field(default=None)
    label: Optional[str] = field(default=None)
    metric_timestamps: List[datetime] = field(factory=list)
    metric_values: List[float] = field(factory=list)
    metric_status_code: Optional[str] = field(default=None)
    metric_messages: List[AwsCloudwatchMessageData] = field(factory=list)

    def first_non_zero(self) -> Optional[Tuple[datetime, float]]:
        for timestamp, value in zip(self.metric_timestamps, self.metric_values):
            if value != 0:
                return timestamp, value
        return None

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "get-metric-data")]

    @staticmethod
    def query_for(
        client: AwsClient,
        queries: List[AwsCloudwatchQuery],
        start_time: datetime,
        end_time: datetime,
        scan_desc: bool = True,
    ) -> "Dict[AwsCloudwatchQuery, AwsCloudwatchMetricData]":
        lookup = {q.metric_id: q for q in queries}
        result: Dict[AwsCloudwatchQuery, AwsCloudwatchMetricData] = {}
        # the api only allows for up to 500 metrics at once
        for chunk in chunks(queries, 499):
            part = client.list(
                service_name,
                "get-metric-data",
                "MetricDataResults",
                MetricDataQueries=[a.to_json() for a in chunk],
                StartTime=start_time,
                EndTime=end_time,
                ScanBy="TimestampDescending" if scan_desc else "TimestampAscending",
            )
            for single in part:
                metric = from_json(bend(AwsCloudwatchMetricData.mapping, single), AwsCloudwatchMetricData)
                if metric.id:
                    result[lookup[metric.id]] = metric

        return result


resources: List[Type[AwsResource]] = [AwsCloudwatchAlarm, AwsCloudwatchLogGroup, AwsCloudwatchMetricFilter]
