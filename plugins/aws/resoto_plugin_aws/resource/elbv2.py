from typing import ClassVar, Dict, Optional, Type, List

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2Vpc, AwsEc2Subnet, AwsEc2Instance, AwsEc2SecurityGroup
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import BaseLoadBalancer, EdgeType, ModelReference
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, Bend, bend, ForallBend, K
from resotolib.types import Json
from resoto_plugin_aws.aws_client import AwsClient


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
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "reason": S("Reason")}
    code: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbLoadBalancerAddress:
    kind: ClassVar[str] = "aws_alb_load_balancer_address"
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
    mapping: ClassVar[Dict[str, Bender]] = {"certificate_arn": S("CertificateArn"), "is_default": S("IsDefault")}
    certificate_arn: Optional[str] = field(default=None)
    is_default: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbAuthenticateOidcActionConfig:
    kind: ClassVar[str] = "aws_alb_authenticate_oidc_action_config"
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
    mapping: ClassVar[Dict[str, Bender]] = {"target_group_arn": S("TargetGroupArn"), "weight": S("Weight")}
    target_group_arn: Optional[str] = field(default=None)
    weight: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetGroupStickinessConfig:
    kind: ClassVar[str] = "aws_alb_target_group_stickiness_config"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("Enabled"), "duration_seconds": S("DurationSeconds")}
    enabled: Optional[bool] = field(default=None)
    duration_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbForwardActionConfig:
    kind: ClassVar[str] = "aws_alb_forward_action_config"
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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "elbv2",
        "describe-load-balancers",
        "LoadBalancers",
        override_iam_permission="elasticloadbalancing:DescribeLoadBalancers",
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_vpc", "aws_ec2_subnet", "aws_ec2_security_group"],
            "delete": ["aws_vpc", "aws_ec2_subnet"],
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
            AwsApiSpec("elbv2", "describe-listeners", override_iam_permission="elasticloadbalancing:DescribeListeners"),
            AwsApiSpec("elbv2", "describe-tags", override_iam_permission="elasticloadbalancing:DescribeTags"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            lb = AwsAlb.from_api(js)
            tags = builder.client.list("elbv2", "describe-tags", "TagDescriptions", ResourceArns=[lb.arn])
            if tags:
                lb.tags = bend(S("Tags", default=[]) >> ToDict(), tags[0])
            for listener in builder.client.list("elbv2", "describe-listeners", "Listeners", LoadBalancerArn=lb.arn):
                mapped = bend(AwsAlbListener.mapping, listener)
                lb.alb_listener.append(from_json(mapped, AwsAlbListener))
            builder.add_node(lb, js)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
        for sg in self.alb_security_groups:
            builder.add_edge(self, EdgeType.default, reverse=True, clazz=AwsEc2SecurityGroup, id=sg)
        for sn in self.alb_availability_zones:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=sn.subnet_id)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-load-balancer", result_name=None, LoadBalancerArn=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(
                "elbv2", "delete-load-balancer", override_iam_permission="elasticloadbalancing:DeleteLoadBalancer"
            ),
        ]


@define(eq=False, slots=False)
class AwsAlbMatcher:
    kind: ClassVar[str] = "aws_alb_matcher"
    mapping: ClassVar[Dict[str, Bender]] = {"http_code": S("HttpCode"), "grpc_code": S("GrpcCode")}
    http_code: Optional[str] = field(default=None)
    grpc_code: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetDescription:
    kind: ClassVar[str] = "aws_alb_target_description"
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
    mapping: ClassVar[Dict[str, Bender]] = {"state": S("State"), "reason": S("Reason"), "description": S("Description")}
    state: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAlbTargetHealthDescription:
    kind: ClassVar[str] = "aws_alb_target_health_description"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "elbv2",
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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "elbv2",
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

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(
                "elbv2", "describe-target-health", override_iam_permission="elasticloadbalancing:DescribeTargetHealth"
            ),
            AwsApiSpec("elbv2", "describe-tags", override_iam_permission="elasticloadbalancing:DescribeTags"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            tg = AwsAlbTargetGroup.from_api(js)
            tags = builder.client.list("elbv2", "describe-tags", "TagDescriptions", ResourceArns=[tg.arn])
            if tags:
                tg.tags = bend(S("Tags", default=[]) >> ToDict(), tags[0])
            for health in builder.client.list(
                "elbv2", "describe-target-health", "TargetHealthDescriptions", TargetGroupArn=tg.arn
            ):
                mapped = bend(AwsAlbTargetHealthDescription.mapping, health)
                tg.alb_target_health.append(from_json(mapped, AwsAlbTargetHealthDescription))
            builder.add_node(tg, js)

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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-target-group", result_name=None, TargetGroupArn=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(
                "elbv2", "delete-target-group", override_iam_permission="elasticloadbalancing:DeleteTargetGroup"
            ),
        ]


resources: List[Type[AwsResource]] = [AwsAlb, AwsAlbTargetGroup]
