import logging
import re
from typing import ClassVar, Dict, Optional, Type, Any, List, Pattern, Union

from attr import field, evolve
from attrs import define

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec, AwsRegion
from resotolib.baseresources import BaseQuota, EdgeType, ModelReference
from resotolib.json_bender import Bender, S, Bend
from resotolib.types import Json
from resoto_plugin_aws.aws_client import AwsClient

log = logging.getLogger("resoto.plugins.aws")


@define(eq=False, slots=False)
class AwsQuotaMetricInfo:
    kind: ClassVar[str] = "aws_quota_metric_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_namespace": S("MetricNamespace"),
        "metric_name": S("MetricName"),
        "metric_dimensions": S("MetricDimensions"),
        "metric_statistic_recommendation": S("MetricStatisticRecommendation"),
    }
    metric_namespace: Optional[str] = field(default=None)
    metric_name: Optional[str] = field(default=None)
    metric_dimensions: Optional[Dict[str, str]] = field(default=None)
    metric_statistic_recommendation: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsQuotaPeriod:
    kind: ClassVar[str] = "aws_quota_period"
    mapping: ClassVar[Dict[str, Bender]] = {"period_value": S("PeriodValue"), "period_unit": S("PeriodUnit")}
    period_value: Optional[int] = field(default=None)
    period_unit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsQuotaErrorReason:
    kind: ClassVar[str] = "aws_quota_error_reason"
    mapping: ClassVar[Dict[str, Bender]] = {"error_code": S("ErrorCode"), "error_message": S("ErrorMessage")}
    error_code: Optional[str] = field(default=None)
    error_message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsServiceQuota(AwsResource, BaseQuota):
    kind: ClassVar[str] = "aws_service_quota"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "aws_ec2_instance_type",
                "aws_ec2_volume_type",
                "aws_vpc",
                "aws_elb",
                "aws_alb",
                "aws_iam_server_certificate",
            ]
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("QuotaCode"),
        "name": S("QuotaName"),
        "service_code": S("ServiceCode"),
        "service_name": S("ServiceName"),
        "arn": S("QuotaArn"),
        "quota": S("Value"),
        "quota_unit": S("Unit"),
        "quota_adjustable": S("Adjustable"),
        "quota_global": S("GlobalQuota"),
        "quota_usage_metric": S("UsageMetric") >> Bend(AwsQuotaMetricInfo.mapping),
        "quota_period": S("Period") >> Bend(AwsQuotaPeriod.mapping),
        "quota_error_reason": S("ErrorReason") >> Bend(AwsQuotaErrorReason.mapping),
    }
    quota_unit: Optional[str] = field(default=None)
    quota_adjustable: Optional[bool] = field(default=None)
    quota_global: Optional[bool] = field(default=None)
    quota_usage_metric: Optional[AwsQuotaMetricInfo] = field(default=None)
    quota_period: Optional[AwsQuotaPeriod] = field(default=None)
    quota_error_reason: Optional[AwsQuotaErrorReason] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(
                "service-quotas", "list-service-quotas", override_iam_permission="servicequotas:ListServiceQuotas"
            )
        ]

    @classmethod
    def collect_service(cls, service_code: str, matchers: List["QuotaMatcher"], builder: GraphBuilder) -> None:
        log.debug(f"Collecting Service quotas for {service_code} in region {builder.region.name}")
        for js in builder.client.list("service-quotas", "list-service-quotas", "Quotas", ServiceCode=service_code):
            quota = AwsServiceQuota.from_api(js)
            for matcher in matchers:
                if matcher.match(quota):
                    builder.add_node(quota, dict(source=js, matcher=evolve(matcher, region=builder.region)))

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        # This collect run will be called for the global region as well as any configured region.
        # We select the quotas to select based on the given region.
        quotas = GlobalQuotas if builder.region.name == "global" else RegionalQuotas
        for service, ms in quotas.items():
            AwsServiceQuota.collect_service(service, ms, builder)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        matcher: Optional[QuotaMatcher] = source.get("matcher", None)

        def prop_matches(attr: Any, expect: Any) -> bool:
            if isinstance(expect, Pattern):
                return expect.match(attr) is not None
            else:
                return bool(attr == expect)

        if matcher:
            for node in builder.graph.nodes:
                if (
                    node.kind == matcher.node_kind
                    and (matcher.region is None or node.region().id == matcher.region.id)
                    and all(prop_matches(getattr(node, k, None), v) for k, v in matcher.node_selector.items())
                ):
                    builder.add_edge(self, EdgeType.default, node=node)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service="service-quotas",
            action="tag-resource",
            result_name=None,
            ResourceARN=self.arn,
            Tags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service="service-quotas",
            action="untag-resource",
            result_name=None,
            ResourceARN=self.arn,
            TagKeys=[key],
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("service-quotas", "tag-resource", override_iam_permission="servicequotas:TagResource"),
            AwsApiSpec("service-quotas", "untag-resource", override_iam_permission="servicequotas:UntagResource"),
        ]


@define
class QuotaMatcher:
    quota_name: Union[str, Pattern[str], None]
    node_kind: str
    node_selector: Dict[str, Any] = field(factory=dict)
    region: Optional[AwsRegion] = None

    def match(self, quota: AwsServiceQuota) -> bool:
        if self.quota_name is None:
            return False
        elif isinstance(self.quota_name, Pattern):
            return self.quota_name.match(quota.safe_name) is not None
        else:
            return self.quota_name == quota.safe_name


RegionalQuotas = {
    "ec2": [
        # Example: "Running On-Demand F instances" --> match InstanceTypes that start with F
        QuotaMatcher(
            quota_name=f"Running On-Demand {name} instances",
            node_kind="aws_ec2_instance_type",
            node_selector=dict(instance_type=re.compile("^" + start + "\\d")),
        )
        for name, start in {
            "Standard (A, C, D, H, I, M, R, T, Z)": "[acdhimrtz]",  # matches e.g. m4.large, i3en.3xlarge
            "F": "f",
            "G and VT": "g",
            "P": "p",
            "Inf": "inf",
            "X": "x",
            "High Memory instances": "u",
            "DL": "dl",
        }.items()
    ],
    "ebs": [
        QuotaMatcher(
            quota_name=re.compile(name_pattern),
            node_kind="aws_ec2_volume_type",
            node_selector=dict(volume_type=volume_type),
        )
        for name_pattern, volume_type in {
            "^Storage for.*gp2": "gp2",
            "^Storage for.*gp3": "gp3",
            "^Storage for.*standard": "standard",
            "^Storage for.*io1": "io1",
            "^Storage for.*io2": "io2",
            "^Storage for.*sc1": "sc1",
            "^Storage for.*st1": "st1",
        }.items()
    ],
    "vpc": [QuotaMatcher(quota_name="Internet gateways per Region", node_kind="aws_vpc")],
    "elasticloadbalancing": [
        QuotaMatcher(quota_name="Application Load Balancers per Region", node_kind="aws_alb"),
        QuotaMatcher(quota_name="Classic Load Balancers per Region", node_kind="aws_elb"),
    ],
}

GlobalQuotas = {
    "iam": [
        QuotaMatcher(quota_name="Server certificates per account", node_kind="aws_iam_server_certificate"),
    ],
}


resources: List[Type[AwsResource]] = [AwsServiceQuota]
