from datetime import timedelta
from functools import partial
from typing import ClassVar, Dict, Optional, Type, List, Any

from attrs import define, field

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec, parse_json
from fix_plugin_aws.resource.ec2 import AwsEc2Vpc, AwsEc2Subnet, AwsEc2Instance, AwsEc2SecurityGroup
from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchQuery,
    AwsCloudwatchMetricData,
    calculate_min_max_avg,
    update_resource_metrics,
    bytes_to_megabits_per_second,
)
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.utils import ToDict, MetricNormalization
from fixlib.baseresources import BaseLoadBalancer, MetricName, MetricUnit, ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, bend, ForallBend, K
from fixlib.types import Json


service_name = "elbv2"


# noinspection PyUnresolvedReferences
class ElbV2Taggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="add-tags",
                    result_name=None,
                    ResourceArns=[self.arn],
                    Tags=[{"Key": key, "Value": value}],
                )
                return True
            return False
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="remove-tags",
                    result_name=None,
                    ResourceArns=[self.arn],
                    TagKeys=[key],
                )
                return True
            return False
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("elb", "add-tags", override_iam_permission="elasticloadbalancing:AddTags"),
            AwsApiSpec("elb", "remove-tags", override_iam_permission="elasticloadbalancing:RemoveTags"),
        ]


@define(eq=False, slots=False)
class AwsAlbLoadBalancerState:
    kind: ClassVar[str] = "aws_alb_load_balancer_state"
    kind_display: ClassVar[str] = "AWS ALB Load Balancer State"
    kind_description: ClassVar[str] = (
        "ALB Load Balancer State represents the state of an Application Load Balancer"
        " (ALB) in Amazon Web Services. The ALB distributes incoming traffic across"
        " multiple targets, such as EC2 instances, containers, and IP addresses, to"
        " ensure high availability and scalability of applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "reason": S("Reason")}
    code: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbLoadBalancerAddress:
    kind: ClassVar[str] = "aws_alb_load_balancer_address"
    kind_display: ClassVar[str] = "AWS ALB Load Balancer Address"
    kind_description: ClassVar[str] = (
        "An address associated with an Application Load Balancer (ALB) in AWS, which"
        " is responsible for distributing incoming traffic across multiple targets."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ip_address": S("IpAddress"),
        "allocation_id": S("AllocationId"),
        "private_i_pv4_address": S("PrivateIPv4Address"),
        "i_pv6_address": S("IPv6Address"),
    }
    ip_address: Optional[str] = field(default=None)
    allocation_id: Optional[str] = field(default=None)
    private_i_pv4_address: Optional[str] = field(default=None)
    i_pv6_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbAvailabilityZone:
    kind: ClassVar[str] = "aws_alb_availability_zone"
    kind_display: ClassVar[str] = "AWS ALB Availability Zone"
    kind_description: ClassVar[str] = (
        "ALB Availability Zone is a feature of AWS Application Load Balancer that"
        " allows distribution of incoming traffic to different availability zones"
        " within a region for increased availability and fault tolerance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "zone_name": S("ZoneName"),
        "subnet_id": S("SubnetId"),
        "outpost_id": S("OutpostId"),
        "load_balancer_addresses": S("LoadBalancerAddresses", default=[])
        >> ForallBend(AwsAlbLoadBalancerAddress.mapping),
    }
    zone_name: Optional[str] = field(default=None)
    subnet_id: Optional[str] = field(default=None)
    outpost_id: Optional[str] = field(default=None)
    load_balancer_addresses: List[AwsAlbLoadBalancerAddress] = field(factory=list)


@define(eq=False, slots=False)
class AwsAlbCertificate:
    kind: ClassVar[str] = "aws_alb_certificate"
    kind_display: ClassVar[str] = "AWS ALB Certificate"
    kind_description: ClassVar[str] = (
        "AWS ALB Certificate is a digital certificate used to secure HTTPS"
        " connections for an Application Load Balancer (ALB) in Amazon Web Services"
        " (AWS)."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"certificate_arn": S("CertificateArn"), "is_default": S("IsDefault")}
    certificate_arn: Optional[str] = field(default=None)
    is_default: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbAuthenticateOidcActionConfig:
    kind: ClassVar[str] = "aws_alb_authenticate_oidc_action_config"
    kind_display: ClassVar[str] = "AWS ALB Authenticate OIDC Action Configuration"
    kind_description: ClassVar[str] = (
        "The AWS ALB Authenticate OIDC Action Configuration allows users to configure"
        " OpenID Connect (OIDC) authentication for Application Load Balancers (ALBs)"
        " in Amazon Web Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "issuer": S("Issuer"),
        "authorization_endpoint": S("AuthorizationEndpoint"),
        "token_endpoint": S("TokenEndpoint"),
        "user_info_endpoint": S("UserInfoEndpoint"),
        "client_id": S("ClientId"),
        "client_secret": S("ClientSecret"),
        "session_cookie_name": S("SessionCookieName"),
        "scope": S("Scope"),
        "session_timeout": S("SessionTimeout"),
        "authentication_request_extra_params": S("AuthenticationRequestExtraParams"),
        "on_unauthenticated_request": S("OnUnauthenticatedRequest"),
        "use_existing_client_secret": S("UseExistingClientSecret"),
    }
    issuer: Optional[str] = field(default=None)
    authorization_endpoint: Optional[str] = field(default=None)
    token_endpoint: Optional[str] = field(default=None)
    user_info_endpoint: Optional[str] = field(default=None)
    client_id: Optional[str] = field(default=None)
    client_secret: Optional[str] = field(default=None)
    session_cookie_name: Optional[str] = field(default=None)
    scope: Optional[str] = field(default=None)
    session_timeout: Optional[int] = field(default=None)
    authentication_request_extra_params: Optional[Dict[str, str]] = field(default=None)
    on_unauthenticated_request: Optional[str] = field(default=None)
    use_existing_client_secret: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbAuthenticateCognitoActionConfig:
    kind: ClassVar[str] = "aws_alb_authenticate_cognito_action_config"
    kind_display: ClassVar[str] = "AWS ALB Authenticate Cognito Action Config"
    kind_description: ClassVar[str] = (
        "ALB Authenticate Cognito Action Config is a configuration option for an AWS"
        " Application Load Balancer to authenticate users via Amazon Cognito."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "user_pool_arn": S("UserPoolArn"),
        "user_pool_client_id": S("UserPoolClientId"),
        "user_pool_domain": S("UserPoolDomain"),
        "session_cookie_name": S("SessionCookieName"),
        "scope": S("Scope"),
        "session_timeout": S("SessionTimeout"),
        "authentication_request_extra_params": S("AuthenticationRequestExtraParams"),
        "on_unauthenticated_request": S("OnUnauthenticatedRequest"),
    }
    user_pool_arn: Optional[str] = field(default=None)
    user_pool_client_id: Optional[str] = field(default=None)
    user_pool_domain: Optional[str] = field(default=None)
    session_cookie_name: Optional[str] = field(default=None)
    scope: Optional[str] = field(default=None)
    session_timeout: Optional[int] = field(default=None)
    authentication_request_extra_params: Optional[Dict[str, str]] = field(default=None)
    on_unauthenticated_request: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbRedirectActionConfig:
    kind: ClassVar[str] = "aws_alb_redirect_action_config"
    kind_display: ClassVar[str] = "AWS ALB Redirect Action Config"
    kind_description: ClassVar[str] = (
        "ALB Redirect Action Config is a configuration for redirect actions in the"
        " Application Load Balancer (ALB) service in Amazon Web Services. It allows"
        " for redirecting incoming requests to a different URL or path in a flexible"
        " and configurable way."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "protocol": S("Protocol"),
        "port": S("Port"),
        "host": S("Host"),
        "path": S("Path"),
        "query": S("Query"),
        "status_code": S("StatusCode"),
    }
    protocol: Optional[str] = field(default=None)
    port: Optional[str] = field(default=None)
    host: Optional[str] = field(default=None)
    path: Optional[str] = field(default=None)
    query: Optional[str] = field(default=None)
    status_code: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbFixedResponseActionConfig:
    kind: ClassVar[str] = "aws_alb_fixed_response_action_config"
    kind_display: ClassVar[str] = "AWS ALB Fixed Response Action Config"
    kind_description: ClassVar[str] = (
        "ALB Fixed Response Action Config is a configuration for the fixed response"
        " action on an Application Load Balancer (ALB) in Amazon Web Services (AWS)."
        " It allows users to define custom HTTP responses with fixed status codes and"
        " messages for specific paths or conditions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "message_body": S("MessageBody"),
        "status_code": S("StatusCode"),
        "content_type": S("ContentType"),
    }
    message_body: Optional[str] = field(default=None)
    status_code: Optional[str] = field(default=None)
    content_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetGroupTuple:
    kind: ClassVar[str] = "aws_alb_target_group_tuple"
    kind_display: ClassVar[str] = "AWS ALB Target Group Tuple"
    kind_description: ClassVar[str] = (
        "ALB Target Group Tuples are used in AWS Application Load Balancers to define"
        " rules for routing incoming requests to registered targets, such as EC2"
        " instances or Lambda functions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"target_group_arn": S("TargetGroupArn"), "weight": S("Weight")}
    target_group_arn: Optional[str] = field(default=None)
    weight: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetGroupStickinessConfig:
    kind: ClassVar[str] = "aws_alb_target_group_stickiness_config"
    kind_display: ClassVar[str] = "AWS ALB Target Group Stickiness Configuration"
    kind_description: ClassVar[str] = (
        "ALB Target Group Stickiness Configuration allows you to enable or configure"
        " stickiness for incoming traffic to an Application Load Balancer (ALB) target"
        " group in AWS."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("Enabled"), "duration_seconds": S("DurationSeconds")}
    enabled: Optional[bool] = field(default=None)
    duration_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbForwardActionConfig:
    kind: ClassVar[str] = "aws_alb_forward_action_config"
    kind_display: ClassVar[str] = "AWS ALB Forward Action Configuration"
    kind_description: ClassVar[str] = (
        "The AWS Application Load Balancer (ALB) Forward Action Configuration"
        " represents the configuration for forwarding requests to a target group in"
        " the ALB."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "target_groups": S("TargetGroups", default=[]) >> ForallBend(AwsAlbTargetGroupTuple.mapping),
        "target_group_stickiness_config": S("TargetGroupStickinessConfig")
        >> Bend(AwsAlbTargetGroupStickinessConfig.mapping),
    }
    target_groups: List[AwsAlbTargetGroupTuple] = field(factory=list)
    target_group_stickiness_config: Optional[AwsAlbTargetGroupStickinessConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbAction:
    kind: ClassVar[str] = "aws_alb_action"
    kind_display: ClassVar[str] = "AWS Application Load Balancer Action"
    kind_description: ClassVar[str] = (
        "An AWS Application Load Balancer Action determines what action to take when a request fulfills a listener"
        " rule. This could be to forward requests to a target group, redirect requests to another URL, or return a"
        " custom HTTP response."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "type": S("Type"),
        "target_group_arn": S("TargetGroupArn"),
        "authenticate_oidc_config": S("AuthenticateOidcConfig") >> Bend(AwsAlbAuthenticateOidcActionConfig.mapping),
        "authenticate_cognito_config": S("AuthenticateCognitoConfig")
        >> Bend(AwsAlbAuthenticateCognitoActionConfig.mapping),
        "order": S("Order"),
        "redirect_config": S("RedirectConfig") >> Bend(AwsAlbRedirectActionConfig.mapping),
        "fixed_response_config": S("FixedResponseConfig") >> Bend(AwsAlbFixedResponseActionConfig.mapping),
        "forward_config": S("ForwardConfig") >> Bend(AwsAlbForwardActionConfig.mapping),
    }
    type: Optional[str] = field(default=None)
    target_group_arn: Optional[str] = field(default=None)
    authenticate_oidc_config: Optional[AwsAlbAuthenticateOidcActionConfig] = field(default=None)
    authenticate_cognito_config: Optional[AwsAlbAuthenticateCognitoActionConfig] = field(default=None)
    order: Optional[int] = field(default=None)
    redirect_config: Optional[AwsAlbRedirectActionConfig] = field(default=None)
    fixed_response_config: Optional[AwsAlbFixedResponseActionConfig] = field(default=None)
    forward_config: Optional[AwsAlbForwardActionConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbListener:
    kind: ClassVar[str] = "aws_alb_listener"
    kind_display: ClassVar[str] = "AWS ALB Listener"
    kind_description: ClassVar[str] = (
        "An Application Load Balancer (ALB) Listener is a configuration that defines"
        " how an ALB distributes incoming traffic to target groups."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "listener_arn": S("ListenerArn"),
        "load_balancer_arn": S("LoadBalancerArn"),
        "port": S("Port"),
        "protocol": S("Protocol"),
        "certificates": S("Certificates", default=[]) >> ForallBend(AwsAlbCertificate.mapping),
        "ssl_policy": S("SslPolicy"),
        "default_actions": S("DefaultActions", default=[]) >> ForallBend(AwsAlbAction.mapping),
        "alpn_policy": S("AlpnPolicy", default=[]),
    }
    listener_arn: Optional[str] = field(default=None)
    load_balancer_arn: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)
    certificates: List[AwsAlbCertificate] = field(factory=list)
    ssl_policy: Optional[str] = field(default=None)
    default_actions: List[AwsAlbAction] = field(factory=list)
    alpn_policy: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsAlb(ElbV2Taggable, AwsResource, BaseLoadBalancer):
    kind: ClassVar[str] = "aws_alb"
    kind_display: ClassVar[str] = "AWS ALB"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#LoadBalancer:loadBalancerArn={arn}", "arn_tpl": "arn:{partition}:elasticloadbalancing:{region}:{account}:loadbalancer/app/{name}/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS ALB is an Application Load Balancer that distributes incoming"
        " application traffic across multiple targets, such as EC2 instances, in"
        " multiple availability zones."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name,
        "describe-load-balancers",
        "LoadBalancers",
        override_iam_permission="elasticloadbalancing:DescribeLoadBalancers",
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_vpc", "aws_ec2_subnet", "aws_ec2_security_group"],
            "delete": ["aws_vpc", "aws_ec2_subnet", "aws_ec2_security_group"],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("LoadBalancerName"),
        "name": S("LoadBalancerName"),
        "ctime": S("CreatedTime"),
        "arn": S("LoadBalancerArn"),
        "public_ip_address": S("AvailabilityZones")[0] >> S("LoadBalancerAddresses")[0] >> S("IpAddress"),
        "alb_dns_name": S("DNSName"),
        "alb_canonical_hosted_zone_id": S("CanonicalHostedZoneId"),
        "alb_scheme": S("Scheme"),
        "alb_state": S("State") >> Bend(AwsAlbLoadBalancerState.mapping),
        "alb_type": S("Type"),
        "lb_type": K("alb"),
        "alb_availability_zones": S("AvailabilityZones", default=[]) >> ForallBend(AwsAlbAvailabilityZone.mapping),
        "alb_security_groups": S("SecurityGroups", default=[]),
        "alb_ip_address_type": S("IpAddressType"),
        "alb_customer_owned_ipv4_pool": S("CustomerOwnedIpv4Pool"),
    }
    alb_dns_name: Optional[str] = field(default=None)
    alb_canonical_hosted_zone_id: Optional[str] = field(default=None)
    alb_scheme: Optional[str] = field(default=None)
    alb_state: Optional[AwsAlbLoadBalancerState] = field(default=None)
    alb_availability_zones: List[AwsAlbAvailabilityZone] = field(factory=list)
    alb_security_groups: List[str] = field(factory=list)
    alb_ip_address_type: Optional[str] = field(default=None)
    alb_customer_owned_ipv4_pool: Optional[str] = field(default=None)
    alb_type: Optional[str] = field(default=None)
    alb_listener: List[AwsAlbListener] = field(factory=list)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(
                service_name, "describe-listeners", override_iam_permission="elasticloadbalancing:DescribeListeners"
            ),
            AwsApiSpec(service_name, "describe-tags", override_iam_permission="elasticloadbalancing:DescribeTags"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            if lb := AwsAlb.from_api(js, builder):
                tags = builder.client.list(
                    service_name,
                    "describe-tags",
                    "TagDescriptions",
                    ResourceArns=[lb.arn],
                    expected_errors=["LoadBalancerNotFound"],
                )
                if tags:
                    lb.tags = bend(S("Tags", default=[]) >> ToDict(), tags[0])
                for listener in builder.client.list(
                    service_name, "describe-listeners", "Listeners", LoadBalancerArn=lb.arn
                ):
                    mapped = bend(AwsAlbListener.mapping, listener)
                    if listener := parse_json(mapped, AwsAlbListener, builder):
                        lb.alb_listener.append(listener)
                builder.add_node(lb, js)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        albs = {alb.id: alb for alb in builder.nodes(clazz=AwsAlb) if alb.region().id == builder.region.id}
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at
        period = min(timedelta(minutes=5), delta)
        for alb_id, alb in albs.items():
            lb_id = "/".join((alb.arn or "").split("/")[-3:])
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric,
                        namespace="AWS/ApplicationELB",
                        period=period,
                        ref_id=alb_id,
                        stat="Sum",
                        unit="Count",
                        LoadBalancer=lb_id,
                    )
                    for metric in [
                        "RequestCount",
                        "ActiveConnectionCount",
                        "RejectedConnectionCount",
                        "IPv6RequestCount",
                        "IPv6ProcessedBytes",
                        "HTTPCode_Target_2XX_Count",
                        "HTTPCode_Target_4XX_Count",
                        "HTTPCode_Target_5XX_Count",
                    ]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="TargetResponseTime",
                        namespace="AWS/ApplicationELB",
                        period=period,
                        ref_id=alb_id,
                        stat=stat,
                        unit="Seconds",
                        LoadBalancer=lb_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="ProcessedBytes",
                        namespace="AWS/ApplicationELB",
                        period=period,
                        ref_id=alb_id,
                        stat="Sum",
                        unit="Bytes",
                        LoadBalancer=lb_id,
                    )
                ]
            )

        metric_normalizers = {
            "RequestCount": MetricNormalization(
                metric_name=MetricName.RequestCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
                compute_stats=calculate_min_max_avg,
            ),
            "ActiveConnectionCount": MetricNormalization(
                metric_name=MetricName.ActiveConnection,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "HTTPCode_Target_2XX_Count": MetricNormalization(
                metric_name=MetricName.StatusCode2XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "HTTPCode_Target_4XX_Count": MetricNormalization(
                metric_name=MetricName.StatusCode4XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "HTTPCode_Target_5XX_Count": MetricNormalization(
                metric_name=MetricName.StatusCode5XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "TargetResponseTime": MetricNormalization(
                metric_name=MetricName.Latency, unit=MetricUnit.Seconds, normalize_value=lambda x: round(x, ndigits=4)
            ),
            "ProcessedBytes": MetricNormalization(
                metric_name=MetricName.ProcessedBytes,
                unit=MetricUnit.MegabitsPerSecond,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(bytes_to_megabits_per_second, period=period),
            ),
            "RejectedConnectionCount": MetricNormalization(
                metric_name=MetricName.StatusCode5XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "IPv6RequestCount": MetricNormalization(
                metric_name=MetricName.StatusCode5XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "IPv6ProcessedBytes": MetricNormalization(
                metric_name=MetricName.StatusCode5XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(albs, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
        for sg in self.alb_security_groups:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=sg)
        for sn in self.alb_availability_zones:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=sn.subnet_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-load-balancer", result_name=None, LoadBalancerArn=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(
                service_name, "delete-load-balancer", override_iam_permission="elasticloadbalancing:DeleteLoadBalancer"
            ),
        ]


@define(eq=False, slots=False)
class AwsAlbMatcher:
    kind: ClassVar[str] = "aws_alb_matcher"
    kind_display: ClassVar[str] = "AWS ALB Matcher"
    kind_description: ClassVar[str] = (
        "ALB Matchers are rules defined for an Application Load Balancer (ALB) to"
        " route incoming requests to specific target groups based on the content of"
        " the request."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"http_code": S("HttpCode"), "grpc_code": S("GrpcCode")}
    http_code: Optional[str] = field(default=None)
    grpc_code: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetDescription:
    kind: ClassVar[str] = "aws_alb_target_description"
    kind_display: ClassVar[str] = "AWS ALB Target Description"
    kind_description: ClassVar[str] = (
        "The target description specifies information about the instances registered"
        " with an Application Load Balancer (ALB) in Amazon Web Services. This"
        " includes details such as the instance ID, IP address, health check status,"
        " and other metadata."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "port": S("Port"),
        "availability_zone": S("AvailabilityZone"),
    }
    id: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    availability_zone: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetHealth:
    kind: ClassVar[str] = "aws_alb_target_health"
    kind_display: ClassVar[str] = "AWS ALB Target Health"
    kind_description: ClassVar[str] = (
        "ALB Target Health is a feature of AWS Application Load Balancer that"
        " provides information about the current health status of registered targets."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"state": S("State"), "reason": S("Reason"), "description": S("Description")}
    state: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetHealthDescription:
    kind: ClassVar[str] = "aws_alb_target_health_description"
    kind_display: ClassVar[str] = "AWS ALB Target Health Description"
    kind_description: ClassVar[str] = (
        "ALB Target Health Description is a feature of AWS Application Load Balancer"
        " that provides information about the health of targets registered with the"
        " load balancer, including target status and reason for any health checks"
        " failures."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name,
        "describe-target-health",
        "TargetHealthDescriptions",
        override_iam_permission="elasticloadbalancing:DescribeTargetHealth",
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "target": S("Target") >> Bend(AwsAlbTargetDescription.mapping),
        "health_check_port": S("HealthCheckPort"),
        "target_health": S("TargetHealth") >> Bend(AwsAlbTargetHealth.mapping),
    }
    target: Optional[AwsAlbTargetDescription] = field(default=None)
    health_check_port: Optional[str] = field(default=None)
    target_health: Optional[AwsAlbTargetHealth] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetGroup(ElbV2Taggable, AwsResource):
    kind: ClassVar[str] = "aws_alb_target_group"
    kind_display: ClassVar[str] = "AWS ALB Target Group"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#TargetGroup:targetGroupArn={arn}", "arn_tpl": "arn:{partition}:elasticloadbalancing:{region}:{account}:targetgroup/{name}/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An ALB Target Group is a group of instances or IP addresses registered with"
        " an Application Load Balancer that receives traffic and distributes it to the"
        " registered targets."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name,
        "describe-target-groups",
        "TargetGroups",
        override_iam_permission="elasticloadbalancing:DescribeTargetGroups",
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_vpc", "aws_alb"], "delete": ["aws_ec2_instance", "aws_vpc"]},
        "successors": {"delete": ["aws_alb"], "default": ["aws_ec2_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("TargetGroupName"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("TargetGroupName"),
        "arn": S("TargetGroupArn"),
        "protocol": S("Protocol"),
        "port": S("Port"),
        "alb_health_check_protocol": S("HealthCheckProtocol"),
        "alb_health_check_port": S("HealthCheckPort"),
        "alb_health_check_enabled": S("HealthCheckEnabled"),
        "alb_health_check_interval_seconds": S("HealthCheckIntervalSeconds"),
        "alb_health_check_timeout_seconds": S("HealthCheckTimeoutSeconds"),
        "alb_healthy_threshold_count": S("HealthyThresholdCount"),
        "alb_unhealthy_threshold_count": S("UnhealthyThresholdCount"),
        "alb_health_check_path": S("HealthCheckPath"),
        "alb_matcher": S("Matcher") >> Bend(AwsAlbMatcher.mapping),
        "target_type": S("TargetType"),
        "alb_protocol_version": S("ProtocolVersion"),
        "alb_ip_address_type": S("IpAddressType"),
        "alb_lb_arns": S("LoadBalancerArns"),
    }
    target_type: Optional[str] = field(default=None)
    protocol: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    alb_health_check_protocol: Optional[str] = field(default=None)
    alb_health_check_port: Optional[str] = field(default=None)
    alb_health_check_enabled: Optional[bool] = field(default=None)
    alb_health_check_interval_seconds: Optional[int] = field(default=None)
    alb_health_check_timeout_seconds: Optional[int] = field(default=None)
    alb_healthy_threshold_count: Optional[int] = field(default=None)
    alb_unhealthy_threshold_count: Optional[int] = field(default=None)
    alb_health_check_path: Optional[str] = field(default=None)
    alb_matcher: Optional[AwsAlbMatcher] = field(default=None)
    alb_protocol_version: Optional[str] = field(default=None)
    alb_ip_address_type: Optional[str] = field(default=None)
    alb_target_health: List[AwsAlbTargetHealthDescription] = field(factory=list)
    alb_lb_arns: List[str] = field(factory=list)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(
                service_name,
                "describe-target-health",
                override_iam_permission="elasticloadbalancing:DescribeTargetHealth",
            ),
            AwsApiSpec(service_name, "describe-tags", override_iam_permission="elasticloadbalancing:DescribeTags"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            if tg := AwsAlbTargetGroup.from_api(js, builder):
                tags = builder.client.list(service_name, "describe-tags", "TagDescriptions", ResourceArns=[tg.arn])
                if tags:
                    tg.tags = bend(S("Tags", default=[]) >> ToDict(), tags[0])
                for health in builder.client.list(
                    service_name, "describe-target-health", "TargetHealthDescriptions", TargetGroupArn=tg.arn
                ):
                    mapped = bend(AwsAlbTargetHealthDescription.mapping, health)
                    if tgh := parse_json(mapped, AwsAlbTargetHealthDescription, builder):
                        tg.alb_target_health.append(tgh)
                builder.add_node(tg, js)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        target_groups = {
            tg.id: tg
            for tg in builder.nodes(clazz=AwsAlbTargetGroup)
            if tg.region().id == builder.region.id and tg.alb_lb_arns
        }
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at
        period = min(timedelta(minutes=5), delta)

        for tg_id, tg in target_groups.items():
            tg_arn_id = (tg.arn or "").split(":")[-1]
            lb_arn_id = "/".join(tg.alb_lb_arns[0].split("/")[-3:])
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric,
                        namespace="AWS/ApplicationELB",
                        period=period,
                        ref_id=tg_id,
                        stat="Sum",
                        unit="Count",
                        LoadBalancer=lb_arn_id,
                        TargetGroup=tg_arn_id,
                    )
                    for metric in [
                        "RequestCount",
                        "HTTPCode_Target_2XX_Count",
                        "HTTPCode_Target_4XX_Count",
                        "HTTPCode_Target_5XX_Count",
                    ]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric,
                        namespace="AWS/ApplicationELB",
                        period=delta,
                        ref_id=tg_id,
                        stat=stat,
                        unit="Count",
                        LoadBalancer=lb_arn_id,
                        TargetGroup=tg_arn_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for metric in [
                        "HealthyHostCount",
                        "UnHealthyHostCount",
                    ]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="TargetResponseTime",
                        namespace="AWS/ApplicationELB",
                        period=delta,
                        ref_id=tg_id,
                        stat=stat,
                        unit="Seconds",
                        LoadBalancer=lb_arn_id,
                        TargetGroup=tg_arn_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric,
                        namespace="AWS/ApplicationELB",
                        period=delta,
                        ref_id=tg_id,
                        stat="Min",  # since it reports the number of AZ that meets requirements, we're only interested in the min (max is constant and equals to the number of AZs) # noqa
                        unit="Count",
                        LoadBalancer=lb_arn_id,
                        TargetGroup=tg_arn_id,
                    )
                    for metric in [
                        "HealthyStateRouting",
                        "UnhealthyStateRouting",
                        "HealthyStateDNS",
                        "UnhealthyStateDNS",
                    ]
                ]
            )

        metric_normalizers = {
            "RequestCount": MetricNormalization(
                metric_name=MetricName.RequestCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
                compute_stats=calculate_min_max_avg,
            ),
            "HealthyHostCount": MetricNormalization(
                metric_name=MetricName.HealthyHostCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "UnHealthyHostCount": MetricNormalization(
                metric_name=MetricName.UnhealthyHostCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "HTTPCode_Target_2XX_Count": MetricNormalization(
                metric_name=MetricName.StatusCode2XX,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
                compute_stats=calculate_min_max_avg,
            ),
            "HTTPCode_Target_4XX_Count": MetricNormalization(
                metric_name=MetricName.StatusCode4XX,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
                compute_stats=calculate_min_max_avg,
            ),
            "HTTPCode_Target_5XX_Count": MetricNormalization(
                metric_name=MetricName.StatusCode5XX,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
                compute_stats=calculate_min_max_avg,
            ),
            "TargetResponseTime": MetricNormalization(
                metric_name=MetricName.Latency, unit=MetricUnit.Seconds, normalize_value=lambda x: round(x, ndigits=4)
            ),
            "HealthyStateRouting": MetricNormalization(
                metric_name=MetricName.HealthyStateRouting,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "UnhealthyStateRouting": MetricNormalization(
                metric_name=MetricName.UnhealthyStateRouting,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "HealthyStateDNS": MetricNormalization(
                metric_name=MetricName.HealthyStateDNS,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "UnhealthyStateDNS": MetricNormalization(
                metric_name=MetricName.UnhealthyStateDNS,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(target_groups, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
        for lb_arn in bend(S("LoadBalancerArns", default=[]), source):
            if lb := builder.node(AwsAlb, arn=lb_arn):
                builder.dependant_node(lb, node=self)
                for th in self.alb_target_health:
                    if th.target and th.target.id:
                        lb.backends.append(th.target.id)
                        builder.dependant_node(self, clazz=AwsEc2Instance, id=th.target.id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-target-group", result_name=None, TargetGroupArn=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(
                service_name, "delete-target-group", override_iam_permission="elasticloadbalancing:DeleteTargetGroup"
            ),
        ]


resources: List[Type[AwsResource]] = [AwsAlb, AwsAlbTargetGroup]
