from datetime import timedelta
from typing import ClassVar, Dict, Optional, Type, List, Any

from attrs import define, field

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec, parse_json
from fix_plugin_aws.resource.ec2 import AwsEc2Subnet, AwsEc2SecurityGroup, AwsEc2Vpc, AwsEc2Instance
from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchQuery,
    AwsCloudwatchMetricData,
    calculate_min_max_avg,
    update_resource_metrics,
)
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.utils import ToDict, MetricNormalization
from fixlib.baseresources import BaseLoadBalancer, MetricName, MetricUnit, ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, bend, ForallBend, K
from fixlib.types import Json

service_name = "elb"


# noinspection PyUnresolvedReferences
class ElbTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="add-tags",
                    result_name=None,
                    LoadBalancerNames=[self.name],
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
                    LoadBalancerNames=[self.name],
                    Tags=[{"Key": key}],
                )
                return True
            return False
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "add-tags", override_iam_permission="elasticloadbalancing:AddTags"),
            AwsApiSpec(service_name, "remove-tags", override_iam_permission="elasticloadbalancing:RemoveTags"),
        ]


@define(eq=False, slots=False)
class AwsElbListener:
    kind: ClassVar[str] = "aws_elb_listener"
    kind_display: ClassVar[str] = "AWS ELB Listener"
    kind_description: ClassVar[str] = (
        "ELB (Elastic Load Balancer) Listeners define the rules for how traffic"
        " should be distributed between registered instances in an application load"
        " balancer or network load balancer."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "protocol": S("Protocol"),
        "load_balancer_port": S("LoadBalancerPort"),
        "instance_protocol": S("InstanceProtocol"),
        "instance_port": S("InstancePort"),
        "ssl_certificate_id": S("SSLCertificateId"),
    }
    protocol: Optional[str] = field(default=None)
    load_balancer_port: Optional[int] = field(default=None)
    instance_protocol: Optional[str] = field(default=None)
    instance_port: Optional[int] = field(default=None)
    ssl_certificate_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElbListenerDescription:
    kind: ClassVar[str] = "aws_elb_listener_description"
    kind_display: ClassVar[str] = "AWS ELB Listener Description"
    kind_description: ClassVar[str] = (
        "ELB Listener Description provides information about a listener used in"
        " Elastic Load Balancing (ELB) service in AWS. It contains details such as the"
        " protocol, port, and SSL certificate configuration for the listener."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "listener": S("Listener") >> Bend(AwsElbListener.mapping),
        "policy_names": S("PolicyNames", default=[]),
    }
    listener: Optional[AwsElbListener] = field(default=None)
    policy_names: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsElbAppCookieStickinessPolicy:
    kind: ClassVar[str] = "aws_elb_app_cookie_stickiness_policy"
    kind_display: ClassVar[str] = "AWS ELB Application Cookie Stickiness Policy"
    kind_description: ClassVar[str] = (
        "ELB Application Cookie Stickiness Policy is a feature provided by AWS"
        " Elastic Load Balancer that allows the load balancer to bind a user's session"
        " to a specific instance based on the provided application cookie."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"policy_name": S("PolicyName"), "cookie_name": S("CookieName")}
    policy_name: Optional[str] = field(default=None)
    cookie_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElbLBCookieStickinessPolicy:
    kind: ClassVar[str] = "aws_elb_lb_cookie_stickiness_policy"
    kind_display: ClassVar[str] = "AWS ELB LB Cookie Stickiness Policy"
    kind_description: ClassVar[str] = (
        "Cookie stickiness policy for an Elastic Load Balancer (ELB) in Amazon Web"
        " Services (AWS) ensures that subsequent requests from a client are sent to"
        " the same backend server, based on the presence of a cookie."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "policy_name": S("PolicyName"),
        "cookie_expiration_period": S("CookieExpirationPeriod"),
    }
    policy_name: Optional[str] = field(default=None)
    cookie_expiration_period: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsElbPolicies:
    kind: ClassVar[str] = "aws_elb_policies"
    kind_display: ClassVar[str] = "AWS ELB Policies"
    kind_description: ClassVar[str] = (
        "ELB Policies are rules that define how the Elastic Load Balancer distributes"
        " incoming traffic to the registered instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "app_cookie_stickiness_policies": S("AppCookieStickinessPolicies", default=[])
        >> ForallBend(AwsElbAppCookieStickinessPolicy.mapping),
        "lb_cookie_stickiness_policies": S("LBCookieStickinessPolicies", default=[])
        >> ForallBend(AwsElbLBCookieStickinessPolicy.mapping),
        "other_policies": S("OtherPolicies", default=[]),
    }
    app_cookie_stickiness_policies: List[AwsElbAppCookieStickinessPolicy] = field(factory=list)
    lb_cookie_stickiness_policies: List[AwsElbLBCookieStickinessPolicy] = field(factory=list)
    other_policies: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsElbBackendServerDescription:
    kind: ClassVar[str] = "aws_elb_backend_server_description"
    kind_display: ClassVar[str] = "AWS ELB Backend Server Description"
    kind_description: ClassVar[str] = (
        "This is a description of the backend server in an AWS Elastic Load Balancer"
        " (ELB). The backend server is the target where the ELB forwards incoming"
        " requests."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_port": S("InstancePort"),
        "policy_names": S("PolicyNames", default=[]),
    }
    instance_port: Optional[int] = field(default=None)
    policy_names: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsElbHealthCheck:
    kind: ClassVar[str] = "aws_elb_health_check"
    kind_display: ClassVar[str] = "AWS ELB Health Check"
    kind_description: ClassVar[str] = (
        "ELB Health Check is a feature provided by Amazon Web Services to monitor the"
        " health of resources behind an Elastic Load Balancer (ELB) and automatically"
        " adjust traffic flow based on the health check results."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "target": S("Target"),
        "interval": S("Interval"),
        "timeout": S("Timeout"),
        "unhealthy_threshold": S("UnhealthyThreshold"),
        "healthy_threshold": S("HealthyThreshold"),
    }
    target: Optional[str] = field(default=None)
    interval: Optional[int] = field(default=None)
    timeout: Optional[int] = field(default=None)
    unhealthy_threshold: Optional[int] = field(default=None)
    healthy_threshold: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsElbSourceSecurityGroup:
    kind: ClassVar[str] = "aws_elb_source_security_group"
    kind_display: ClassVar[str] = "AWS ELB Source Security Group"
    kind_description: ClassVar[str] = (
        "The AWS ELB Source Security Group is used to control access to an Elastic Load Balancer"
        " by identifying a trusted group of sources that can send traffic to it."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"owner_alias": S("OwnerAlias"), "group_name": S("GroupName")}
    owner_alias: Optional[str] = field(default=None)
    group_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElbAccessLog:
    kind: ClassVar[str] = "aws_elb_access_log"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "s3_bucket_name": S("S3BucketName"),
        "emit_interval": S("EmitInterval"),
        "s3_bucket_prefix": S("S3BucketPrefix"),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "Specifies whether access logs are enabled for the load balancer."})  # fmt: skip
    s3_bucket_name: Optional[str] = field(default=None, metadata={"description": "The name of the Amazon S3 bucket where the access logs are stored."})  # fmt: skip
    emit_interval: Optional[int] = field(default=None, metadata={"description": "The interval for publishing the access logs. You can specify an interval of either 5 minutes or 60 minutes. Default: 60 minutes"})  # fmt: skip
    s3_bucket_prefix: Optional[str] = field(default=None, metadata={"description": "The logical hierarchy you created for your Amazon S3 bucket, for example my-bucket-prefix/prod. If the prefix is not provided, the log is placed at the root level of the bucket."})  # fmt: skip


@define(eq=False, slots=False)
class AwsElbConnectionDraining:
    kind: ClassVar[str] = "aws_elb_connection_draining"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("Enabled"), "timeout": S("Timeout")}
    enabled: Optional[bool] = field(default=None, metadata={"description": "Specifies whether connection draining is enabled for the load balancer."})  # fmt: skip
    timeout: Optional[int] = field(default=None, metadata={"description": "The maximum time, in seconds, to keep the existing connections open before deregistering the instances."})  # fmt: skip


@define(eq=False, slots=False)
class AwsElbAdditionalAttribute:
    kind: ClassVar[str] = "aws_elb_additional_attribute"
    mapping: ClassVar[Dict[str, Bender]] = {"key": S("Key"), "value": S("Value")}
    key: Optional[str] = field(default=None, metadata={"description": "The name of the attribute. The following attribute is supported.    elb.http.desyncmitigationmode - Determines how the load balancer handles requests that might pose a security risk to your application. The possible values are monitor, defensive, and strictest. The default is defensive."})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "This value of the attribute."})  # fmt: skip


@define(eq=False, slots=False)
class AwsElbLoadBalancerAttributes:
    kind: ClassVar[str] = "aws_elb_load_balancer_attributes"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cross_zone_load_balancing": S("CrossZoneLoadBalancing", "Enabled"),
        "access_log": S("AccessLog") >> Bend(AwsElbAccessLog.mapping),
        "connection_draining": S("ConnectionDraining") >> Bend(AwsElbConnectionDraining.mapping),
        "connection_settings": S("ConnectionSettings", "IdleTimeout"),
        "additional_attributes": S("AdditionalAttributes", default=[]) >> ForallBend(AwsElbAdditionalAttribute.mapping),
    }
    cross_zone_load_balancing: Optional[bool] = field(default=None, metadata={"description": "If enabled, the load balancer routes the request traffic evenly across all instances regardless of the Availability Zones. For more information, see Configure Cross-Zone Load Balancing in the Classic Load Balancers Guide."})  # fmt: skip
    access_log: Optional[AwsElbAccessLog] = field(default=None, metadata={"description": "If enabled, the load balancer captures detailed information of all requests and delivers the information to the Amazon S3 bucket that you specify. For more information, see Enable Access Logs in the Classic Load Balancers Guide."})  # fmt: skip
    connection_draining: Optional[AwsElbConnectionDraining] = field(default=None, metadata={"description": "If enabled, the load balancer allows existing requests to complete before the load balancer shifts traffic away from a deregistered or unhealthy instance. For more information, see Configure Connection Draining in the Classic Load Balancers Guide."})  # fmt: skip
    connection_settings: Optional[int] = field(default=None, metadata={"description": "If enabled, the load balancer allows the connections to remain idle (no data is sent over the connection) for the specified duration. By default, Elastic Load Balancing maintains a 60-second idle connection timeout for both front-end and back-end connections of your load balancer. For more information, see Configure Idle Connection Timeout in the Classic Load Balancers Guide."})  # fmt: skip
    additional_attributes: Optional[List[AwsElbAdditionalAttribute]] = field(factory=list, metadata={"description": "Any additional attributes."})  # fmt: skip


@define(eq=False, slots=False)
class AwsElb(ElbTaggable, AwsResource, BaseLoadBalancer):
    kind: ClassVar[str] = "aws_elb"
    kind_display: ClassVar[str] = "AWS ELB"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#LoadBalancer:loadBalancerArn={name}", "arn_tpl": "arn:{partition}:elasticloadbalancing:{region}:{account}:loadbalancer/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "ELB stands for Elastic Load Balancer. It is a service provided by Amazon Web"
        " Services that automatically distributes incoming application traffic across"
        " multiple Amazon EC2 instances, making it easier to achieve fault tolerance"
        " in your applications."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name,
        "describe-load-balancers",
        "LoadBalancerDescriptions",
        override_iam_permission="elasticloadbalancing:DescribeLoadBalancers",
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_vpc", "aws_ec2_subnet", "aws_ec2_security_group"],
            "delete": ["aws_vpc", "aws_ec2_subnet", "aws_ec2_security_group", "aws_ec2_instance"],
        },
        "successors": {
            "default": ["aws_ec2_instance"],
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("DNSName"),
        "name": S("LoadBalancerName"),
        "lb_type": K("elb"),
        "ctime": S("CreatedTime"),
        "backends": S("Instances", default=[]) >> ForallBend(S("InstanceId")),
        "elb_canonical_hosted_zone_name": S("CanonicalHostedZoneName"),
        "elb_canonical_hosted_zone_name_id": S("CanonicalHostedZoneNameID"),
        "elb_listener_descriptions": S("ListenerDescriptions", default=[])
        >> ForallBend(AwsElbListenerDescription.mapping),
        "elb_policies": S("Policies") >> Bend(AwsElbPolicies.mapping),
        "elb_backend_server_descriptions": S("BackendServerDescriptions", default=[])
        >> ForallBend(AwsElbBackendServerDescription.mapping),
        "elb_availability_zones": S("AvailabilityZones", default=[]),
        "elb_health_check": S("HealthCheck") >> Bend(AwsElbHealthCheck.mapping),
        "elb_source_security_group": S("SourceSecurityGroup") >> Bend(AwsElbSourceSecurityGroup.mapping),
        "scheme": S("Scheme"),
    }
    scheme: Optional[str] = field(default=None)
    elb_canonical_hosted_zone_name: Optional[str] = field(default=None)
    elb_canonical_hosted_zone_name_id: Optional[str] = field(default=None)
    elb_listener_descriptions: List[AwsElbListenerDescription] = field(factory=list)
    elb_policies: Optional[AwsElbPolicies] = field(default=None)
    elb_backend_server_descriptions: List[AwsElbBackendServerDescription] = field(factory=list)
    elb_availability_zones: List[str] = field(factory=list)
    elb_health_check: Optional[AwsElbHealthCheck] = field(default=None)
    elb_source_security_group: Optional[AwsElbSourceSecurityGroup] = field(default=None)
    elb_attributes: Optional[AwsElbLoadBalancerAttributes] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(
                service_name,
                "describe-tags",
                override_iam_permission="elasticloadbalancing:DescribeTags",
            ),
            AwsApiSpec(
                service_name,
                "describe-load-balancer-attributes",
                override_iam_permission="elasticloadbalancing:DescribeLoadBalancerAttributes",
            ),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def fetch_attributes(elb: AwsElb) -> None:
            if attributes := builder.client.get(
                service_name,
                "describe-load-balancer-attributes",
                "LoadBalancerAttributes",
                LoadBalancerName=elb.name,
                expected_errors=["LoadBalancerNotFound"],
            ):
                elb.elb_attributes = parse_json(
                    attributes, AwsElbLoadBalancerAttributes, builder, AwsElbAdditionalAttribute.mapping
                )

        def add_tags(elb: AwsElb) -> None:
            tags = builder.client.list(
                service_name,
                "describe-tags",
                "TagDescriptions",
                LoadBalancerNames=[elb.name],
                expected_errors=["LoadBalancerNotFound"],
            )
            if tags:
                elb.tags = bend(S("Tags", default=[]) >> ToDict(), tags[0])

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)
                builder.submit_work(service_name, fetch_attributes, instance)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        elbs = {elb.id: elb for elb in builder.nodes(clazz=AwsElb) if elb.region().id == builder.region.id}
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at
        period = min(timedelta(minutes=5), delta)

        for elb_id, elb in elbs.items():
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric,
                        namespace="AWS/ELB",
                        period=period,
                        ref_id=elb_id,
                        stat="Sum",
                        unit="Count",
                        LoadBalancerName=elb.name or elb.safe_name,
                    )
                    for metric in [
                        "RequestCount",
                        "EstimatedALBActiveConnectionCount",
                        "HTTPCode_Backend_2XX",
                        "HTTPCode_Backend_4XX",
                        "HTTPCode_Backend_5XX",
                    ]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric,
                        namespace="AWS/ELB",
                        period=delta,
                        ref_id=elb_id,
                        stat=stat,
                        unit="Count",
                        LoadBalancerName=elb.name or elb.safe_name,
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
                        metric_name="Latency",
                        namespace="AWS/ELB",
                        period=delta,
                        ref_id=elb_id,
                        stat=stat,
                        unit="Seconds",
                        LoadBalancerName=elb.name or elb.safe_name,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="EstimatedProcessedBytes",
                        namespace="AWS/ELB",
                        period=delta,
                        ref_id=elb_id,
                        stat=stat,
                        unit="Bytes",
                        LoadBalancerName=elb.name or elb.safe_name,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )

        metric_normalizers = {
            "RequestCount": MetricNormalization(
                metric_name=MetricName.RequestCount,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "EstimatedALBActiveConnectionCount": MetricNormalization(
                metric_name=MetricName.ActiveConnection,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "HTTPCode_Backend_2XX": MetricNormalization(
                metric_name=MetricName.StatusCode2XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "HTTPCode_Backend_4XX": MetricNormalization(
                metric_name=MetricName.StatusCode4XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "HTTPCode_Backend_5XX": MetricNormalization(
                metric_name=MetricName.StatusCode5XX,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "HealthyHostCount": MetricNormalization(
                metric_name=MetricName.HealthyHostCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "UnHealthyHostCount": MetricNormalization(
                metric_name=MetricName.UnhealthyHostCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "Latency": MetricNormalization(
                metric_name=MetricName.Latency,
                unit=MetricUnit.Seconds,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "EstimatedProcessedBytes": MetricNormalization(
                metric_name=MetricName.ProcessedBytes,
                unit=MetricUnit.BytesPerSecond,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(elbs, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if vpc_id := source.get("VPCId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
        for subnet_id in source.get("Subnets", []):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet_id)
        for sg_id in source.get("SecurityGroups", []):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=sg_id)
        for instance in self.backends:
            builder.dependant_node(self, clazz=AwsEc2Instance, id=instance)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-load-balancer",
            result_name=None,
            LoadBalancerName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(
                service_name, "delete-load-balancer", override_iam_permission="elasticloadbalancing:DeleteLoadBalancer"
            ),
        ]


resources: List[Type[AwsResource]] = [AwsElb]
