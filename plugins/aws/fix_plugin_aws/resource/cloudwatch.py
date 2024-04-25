import logging
import re
from datetime import datetime, timedelta
from typing import ClassVar, Dict, List, Optional, Type, Tuple, TypeVar, Any
from concurrent.futures import as_completed

from attr import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.utils import ToDict, MetricNormalization
from fixlib.baseresources import ModelReference, BaseResource, StatName
from fixlib.graph import Graph
from fixlib.json import from_json
from fixlib.json_bender import S, Bend, Bender, ForallBend, bend, F, SecondsFromEpochToDatetime
from fixlib.types import Json
from fixlib.utils import chunks

log = logging.getLogger("fix.plugins.aws")
service_name = "cloudwatch"

# Cloudwatch Alarm: Namespace -> Dimension Name -> (Kind, Property)
CloudwatchAlarmReferences: Dict[str, Dict[str, Tuple[str, str]]] = {
    "AWS/EC2": {
        "InstanceId": ("aws_ec2_instance", "id"),
        "AutoScalingGroupName": ("aws_autoscaling_group", "name"),
    },
    "AWS/S3": {"BucketName": ("aws_s3_bucket", "name")},
    "AWS/DynamoDB": {"TableName": ("aws_dynamodb_table", "name")},
    "AWS/EBS": {"VolumeId": ("aws_ebs_volume", "id")},
    "AWS/ECS": {"ClusterName": ("aws_ecs_cluster", "name")},
    "AWS/EFS": {"FileSystemId": ("aws_efs_file_system", "id")},
    "AWS/ELB": {"LoadBalancerName": ("aws_elb_load_balancer", "name")},
    "AWS/ALB": {"LoadBalancer": ("aws_alb_load_balancer", "name")},
    "AWS/SQS": {"QueueName": ("aws_sqs_queue", "name")},
    "AWS/SNS": {"TopicName": ("aws_sns_topic", "name")},
    "AWS/Redshift": {"ClusterIdentifier": ("aws_redshift_cluster", "id")},
    "AWS/Autoscaling": {"AutoScalingGroupName": ("aws_autoscaling_group", "name")},
    "AWS/Kinesis": {"StreamName": ("aws_kinesis_stream", "name")},
}


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
    kind_display: ClassVar[str] = "AWS CloudWatch Dimension"
    kind_description: ClassVar[str] = (
        "CloudWatch Dimensions are used to categorize and filter metrics in Amazon"
        " CloudWatch. They can be used to add more context to the metrics and make it"
        " easier to monitor and analyze cloud resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "value": S("Value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudwatchMetric:
    kind: ClassVar[str] = "aws_cloudwatch_metric"
    kind_display: ClassVar[str] = "AWS CloudWatch Metric"
    kind_description: ClassVar[str] = (
        "AWS CloudWatch Metric is a time-ordered set of data points that represent a measurable aspect of your AWS"
        " resources or applications, such as CPU utilization or request counts, which can be tracked for"
        " analysis and alerting."
    )
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
    kind_display: ClassVar[str] = "AWS CloudWatch Metric Stat"
    kind_description: ClassVar[str] = (
        "AWS CloudWatch Metric Stat refers to a set of statistical values (e.g., average, sum, minimum, maximum)"
        " computed from the metric data points over a specified time period, providing insights into the metric's"
        " behavior and performance."
    )
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
    kind_display: ClassVar[str] = "AWS CloudWatch Metric Data Query"
    kind_description: ClassVar[str] = (
        "AWS CloudWatch Metric Data Query is a structure used in CloudWatch to specify the metric data to retrieve"
        " and how to process it, allowing users to aggregate, transform, and filter metric data points for analysis"
        " or visualization in CloudWatch dashboards."
    )
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
    kind_display: ClassVar[str] = "AWS CloudWatch Alarm"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudwatch/home?region={region}#alarmsV2:alarm/{name}", "arn_tpl": "arn:{partition}:cloudwatch:{region}:{account}:alarm/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudWatch Alarms allow you to monitor metrics and send notifications based on the thresholds you set."
    )
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
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if self.cloudwatch_namespace and (refs := CloudwatchAlarmReferences.get(self.cloudwatch_namespace)):
            for dimension in self.cloudwatch_dimensions:
                if dimension.name and (connect_def := refs.get(dimension.name)):
                    kind, prop = connect_def
                    builder.dependant_node(
                        self, reverse=True, delete_same_as_default=True, kind=kind, **{prop: dimension.value}
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
    kind_display: ClassVar[str] = "AWS CloudWatch Log Group"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{name}", "arn_tpl": "arn:{partition}:logs:{region}:{account}:log-group/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudWatch Log Groups are containers for log streams in Amazon's CloudWatch"
        " service, enabling centralized storage and analysis of log data from various"
        " AWS resources."
    )
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
    group_metric_filter_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    group_stored_bytes: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    group_data_protection_status: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if kms_key_id := source.get("kmsKeyId"):
            builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(kms_key_id))

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec("logs", "delete-log-group")]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service="logs", action="delete-log-group", logGroupName=self.name)
        return True


@define(eq=False, slots=False)
class AwsCloudwatchMetricTransformation:
    kind: ClassVar[str] = "aws_cloudwatch_metric_transformation"
    kind_display: ClassVar[str] = "AWS CloudWatch Metric Transformation"
    kind_description: ClassVar[str] = (
        "CloudWatch Metric Transformation is a service provided by Amazon Web"
        " Services that allows users to create custom metrics by manipulating existing"
        " CloudWatch metrics."
    )
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
    kind_display: ClassVar[str] = "AWS CloudWatch Metric Filter"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{arn}", "arn_tpl": "arn:{partition}:logs:{region}:{account}:metric-filter/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudWatch Metric Filter is a feature in Amazon CloudWatch that allows you"
        " to define a pattern to extract information from your log events and use it"
        " to create CloudWatch metrics."
    )
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
    stat: str = "Sum"
    unit: str = "Count"

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
                "Stat": self.stat,
                "Unit": self.unit,
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
        stat: str = "Sum",
        unit: str = "Count",
        **dimensions: str,
    ) -> "AwsCloudwatchQuery":
        dims = "_".join(f"{k}+{v}" for k, v in dimensions.items())
        rid = metric_id or re.sub("\\W", "_", f"{metric_name}-{namespace}-{dims}-{stat}".lower())
        # noinspection PyTypeChecker
        return AwsCloudwatchQuery(
            metric_name=metric_name,
            namespace=namespace,
            period=period,
            dimensions=tuple(dimensions.items()),
            ref_id=ref_id,
            metric_id=rid,
            stat=stat,
            unit=unit,
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
        builder: GraphBuilder,
        queries: List[AwsCloudwatchQuery],
        start_time: datetime,
        end_time: datetime,
        scan_desc: bool = True,
    ) -> "Dict[AwsCloudwatchQuery, AwsCloudwatchMetricData]":
        lookup = {q.metric_id: q for q in queries}
        result: Dict[AwsCloudwatchQuery, AwsCloudwatchMetricData] = {}
        futures = []
        # the api only allows for up to 500 metrics at once
        for chunk in chunks(queries, 499):
            future = builder.submit_work(
                service_name,
                AwsCloudwatchMetricData._query_for_single,
                builder.client,
                MetricDataQueries=[a.to_json() for a in chunk],
                StartTime=start_time,
                EndTime=end_time,
                ScanBy="TimestampDescending" if scan_desc else "TimestampAscending",
            )
            futures.append(future)

        # Retrieve results from submitted queries and populate the result dictionary
        for future in as_completed(futures):
            try:
                metric_query_result = future.result()
                for metric, metric_id in metric_query_result:
                    if metric is not None and metric_id is not None:
                        result[lookup[metric_id]] = metric
            except Exception as e:
                log.error(f"An error occurred while processing a metric query: {e}")
                raise e

        return result

    @staticmethod
    def _query_for_single(
        client: AwsClient,
        **kwargs: Any,
    ) -> "List[Tuple[AwsCloudwatchMetricData, str]]":
        query_result = []
        try:
            part = client.list(service_name, "get-metric-data", "MetricDataResults", **kwargs)
            for single in part:
                metric = from_json(bend(AwsCloudwatchMetricData.mapping, single), AwsCloudwatchMetricData)
                if metric.id:
                    query_result.append((metric, metric.id))
            return query_result
        except Exception as e:
            raise e


resources: List[Type[AwsResource]] = [AwsCloudwatchAlarm, AwsCloudwatchLogGroup, AwsCloudwatchMetricFilter]

V = TypeVar("V", bound=BaseResource)


def update_resource_metrics(
    resources_map: Dict[str, V],
    cloudwatch_result: Dict[AwsCloudwatchQuery, AwsCloudwatchMetricData],
    metric_normalizers: Dict[str, MetricNormalization],
) -> None:
    for query, metric in cloudwatch_result.items():
        resource = resources_map.get(query.ref_id)
        if resource is None:
            continue
        if len(metric.metric_values) == 0:
            continue
        normalizer = metric_normalizers.get(query.metric_name)
        if not normalizer:
            continue

        for metric_value, maybe_stat_name in normalizer.compute_stats(metric.metric_values):
            name = normalizer.metric_name + "_" + normalizer.unit
            value = normalizer.normalize_value(metric_value)
            stat_name = str(maybe_stat_name or normalizer.stat_map[query.stat])

            resource._resource_usage[name][stat_name] = value


def bytes_to_megabits_per_second(bytes: float, period: timedelta) -> float:
    return round((bytes * 8) / (1024**2 * period.total_seconds()), 4)


def bytes_to_megabytes_per_second(bytes: float, period: timedelta) -> float:
    return round(bytes / (1024**2 * period.total_seconds()), 4)


def operations_to_iops(ops: float, period: timedelta) -> float:
    return round(ops / period.total_seconds(), 4)


def calculate_min_max_avg(values: List[float]) -> List[Tuple[float, Optional[StatName]]]:
    return [
        (min(values), StatName.min),
        (max(values), StatName.max),
        (sum(values) / len(values), StatName.avg),
    ]
