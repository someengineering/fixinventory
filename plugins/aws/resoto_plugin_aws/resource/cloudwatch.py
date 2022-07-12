from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Type
from attr import define, field
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource
from resotolib.baseresources import BaseAccount  # noqa: F401
from resotolib.json_bender import S, Bend, Bender, ForallBend


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
class AwsCloudwatchAlarm(AwsResource):
    kind: ClassVar[str] = "aws_cloudwatch_alarm"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudwatch", "describe-alarms", "MetricAlarms")
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


resources: List[Type[AwsResource]] = [AwsCloudwatchAlarm]
