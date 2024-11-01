import json  # noqa: F401
import re
from textwrap import dedent
from typing import Any, List, Set, Optional, Tuple, Union, Dict

import boto3
from attrs import define
from bs4 import BeautifulSoup  # pip install beautifulsoup4 lxml
from botocore.model import ServiceModel, StringShape, ListShape, Shape, StructureShape, MapShape
from jsons import pascalcase

from fixlib.types import JsonElement
from fixlib.utils import utc_str


@define
class AwsProperty:
    name: str
    from_name: Union[str, List[str]]
    type: str
    description: str
    is_array: bool = False
    is_complex: bool = False
    field_default: Optional[str] = None
    extractor: Optional[str] = None

    def assignment(self) -> str:
        default = self.field_default or ("factory=list" if self.is_array else "default=None")
        description = BeautifulSoup(self.description, "lxml").get_text().strip()
        return f'field({default}, metadata={{"description": "{description}"}})  # fmt: skip'

    def type_string(self) -> str:
        if self.is_array:
            return f"Optional[List[{self.type}]]"
        else:
            return f"Optional[{self.type}]"

    def mapping(self) -> str:
        # in case an extractor is defined explicitly
        if self.extractor:
            return f'"{self.name}": {self.extractor}'
        from_p = self.from_name if isinstance(self.from_name, list) else [self.from_name]
        from_p_path = ",".join(f'"{p}"' for p in from_p)
        base = f'"{self.name}": S({from_p_path}'
        if self.is_array and self.is_complex:
            base += f", default=[]) >> ForallBend({self.type}.mapping)"
        elif self.is_array:
            base += ", default=[])"
        elif self.is_complex:
            base += f") >> Bend({self.type}.mapping)"
        else:
            base += ")"

        return base


@define
class AwsModel:
    name: str
    props: List[AwsProperty]
    aggregate_root: bool
    base_class: Optional[str] = None
    api_info: Optional[Tuple[str, str, str]] = None

    def to_class(self) -> str:
        bc = ", " + self.base_class if self.base_class else ""
        base = f"(AwsResource{bc}):" if self.aggregate_root else ":"
        kind = f'    kind: ClassVar[str] = "aws_{to_snake(self.name[3:])}"'
        if self.api_info:
            srv, act, res = self.api_info
            api = f'    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("{srv}", "{act}", "{res}")\n'
        else:
            api = ""
        base_mapping = {
            "id": 'S("id")',
            "tags": 'S("Tags", default=[]) >> ToDict()',
            "name": 'S("Tags", default=[]) >> TagsValue("Name")',
            "ctime": "K(None)",
            "mtime": "K(None)",
            "atime": "K(None)",
        }
        mapping = "    mapping: ClassVar[Dict[str, Bender]] = {\n"
        if self.aggregate_root:
            mapping += ",\n".join(f'        "{k}": {v}' for k, v in base_mapping.items())
            mapping += ",\n"
        mapping += ",\n".join(f"        {p.mapping()}" for p in self.props)
        mapping += "\n    }"
        props = "\n".join(f"    {p.name}: {p.type_string()} = {p.assignment()}" for p in self.props)
        return f"@define(eq=False, slots=False)\nclass {self.name}{base}\n{kind}\n{api}{mapping}\n{props}\n"


@define
class AwsFixModel:
    api_action: str  # action to perform on the client
    result_property: str  # this property holds the resulting list
    result_shape: Optional[str] = None  # the shape of the result according to the service specification
    prefix: Optional[str] = None  # prefix for the resources
    prop_prefix: Optional[str] = None  # prefix for the attributes
    name: Optional[str] = None  # name of the clazz - uses the shape name by default
    base: Optional[str] = None  # the base class to use, BaseResource otherwise


def to_snake(name: str) -> str:
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub("__([A-Z])", r"_\1", name)
    name = re.sub("([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower()


simple_type_map = {
    "Long": "int",
    "Float": "float",
    "Double": "float",
    "Integer": "int",
    "Boolean": "bool",
    "String": "str",
    "DateTime": "datetime",
    "Timestamp": "datetime",
    "TagsMap": "Dict[str, str]",
    "MillisecondDateTime": "datetime",
    "SearchString": "str",
}
simple_type_map |= {k.lower(): v for k, v in simple_type_map.items()}

ignore_props = {"Tags", "tags"}


def service_model(name: str) -> ServiceModel:
    return boto3.client(name, region_name="us-east-1")._service_model


def clazz_model(
    shape: Shape,
    visited: Set[str],
    prefix: Optional[str] = None,
    prop_prefix: Optional[str] = None,
    clazz_name: Optional[str] = None,
    base_class: Optional[str] = None,
    aggregate_root: bool = False,
    api_info: Optional[Tuple[str, str, str]] = None,
) -> List[AwsModel]:
    def type_name(s: Shape) -> str:
        spl = simple_shape(s)
        return spl if spl else f"Aws{prefix}{s.name}"

    def simple_shape(s: Shape) -> Optional[str]:
        if isinstance(s, StringShape):
            return "str"
        elif simple := simple_type_map.get(s.name):
            return simple
        elif simple := simple_type_map.get(s.type_name):
            return simple
        else:
            return None

    def complex_simple_shape(s: Shape) -> Optional[Tuple[str, str]]:
        # in case this shape is complex, but has only property of simple type, return that type
        if isinstance(s, StructureShape) and len(s.members) == 1:
            p_name, p_shape = next(iter(s.members.items()))
            p_simple = simple_shape(p_shape)
            return (p_name, p_simple) if p_simple else None
        else:
            return None

    if type_name(shape) in visited:
        return []
    visited.add(type_name(shape))
    result: List[AwsModel] = []
    props = []
    prefix = prefix or ""
    prop_prefix = prop_prefix or ""

    def process_shape_items(shape_items: List[Tuple[Any, Any]], prop_prefix: str, clazz_name: Optional[str]) -> None:
        for name, prop_shape in shape_items:
            prop = to_snake(name)
            if prop in ignore_props:
                continue
            if simple := simple_shape(prop_shape):
                props.append(AwsProperty(prop_prefix + prop, name, simple, prop_shape.documentation))
            elif isinstance(prop_shape, ListShape):
                inner = prop_shape.member
                if simple := simple_shape(inner):
                    props.append(AwsProperty(prop_prefix + prop, name, simple, prop_shape.documentation, is_array=True))
                elif simple_path := complex_simple_shape(inner):
                    prop_name, prop_type = simple_path
                    props.append(
                        AwsProperty(
                            prop_prefix + prop,
                            [name, prop_name],
                            prop_type,
                            prop_shape.documentation,
                            is_array=True,
                            extractor=f'S("{name}", default=[]) >> ForallBend(S("{prop_name}"))',
                        )
                    )

                else:
                    result.extend(clazz_model(inner, visited, prefix))
                    props.append(
                        AwsProperty(
                            prop_prefix + prop,
                            name,
                            type_name(inner),
                            prop_shape.documentation,
                            is_array=True,
                            is_complex=True,
                        )
                    )
            elif isinstance(prop_shape, MapShape):
                key_type = simple_shape(prop_shape.key)
                assert key_type, f"Key type must be a simple type: {prop_shape.key.name}"
                value_type = type_name(prop_shape.value)
                result.extend(clazz_model(prop_shape.value, visited, prefix))
                props.append(
                    AwsProperty(prop_prefix + prop, name, f"Dict[{key_type}, {value_type}]", prop_shape.documentation)
                )

            elif isinstance(prop_shape, StructureShape):
                if maybe_simple := complex_simple_shape(prop_shape):
                    s_prop_name, s_prop_type = maybe_simple
                    props.append(
                        AwsProperty(prop_prefix + prop, [name, s_prop_name], s_prop_type, prop_shape.documentation)
                    )
                else:
                    result.extend(clazz_model(prop_shape, visited, prefix))
                    props.append(
                        AwsProperty(
                            prop_prefix + prop, name, type_name(prop_shape), prop_shape.documentation, is_complex=True
                        )
                    )
            else:
                raise NotImplementedError(f"Unsupported shape: {prop_shape}")

        clazz_name = clazz_name if clazz_name else type_name(shape)
        result.append(AwsModel(clazz_name, props, aggregate_root, base_class, api_info))

    if isinstance(shape, StructureShape):
        process_shape_items(shape.members.items(), prop_prefix, clazz_name)
    elif isinstance(shape, StringShape):
        return []
    elif isinstance(shape, ListShape):
        if isinstance(shape.member, StringShape):
            return []
        process_shape_items(shape.member.members.items(), prop_prefix, clazz_name)
    else:
        if getattr(shape, "members", None) is None:
            return []
        process_shape_items(shape.members.items(), prop_prefix, clazz_name)
    return result


def all_models() -> List[AwsModel]:
    visited: Set[str] = set()
    result: List[AwsModel] = []
    for name, endpoints in models.items():
        sm = service_model(name)
        for ep in endpoints:
            shape = (
                sm.shape_for(ep.result_shape)
                if ep.result_shape
                else sm.operation_model(pascalcase(ep.api_action)).output_shape
            )
            result.extend(
                clazz_model(
                    shape,
                    visited,
                    aggregate_root=True,
                    clazz_name=ep.name,
                    base_class=ep.base,
                    prop_prefix=ep.prop_prefix,
                    prefix=ep.prefix,
                    api_info=(name, ep.api_action, ep.result_property),
                )
            )

    return result


def create_test_response(service: str, function: str, is_pascal: bool = False) -> JsonElement:
    sm = service_model(service)
    op = sm.operation_model(function if is_pascal else pascalcase(function))

    def sample(shape: Shape) -> JsonElement:
        if isinstance(shape, StringShape) and shape.enum:
            return shape.enum[-1]
        elif isinstance(shape, StringShape) and "8601" in shape.documentation:
            return utc_str()
        elif isinstance(shape, StringShape) and "URL" in shape.documentation:
            return "https://example.com"
        elif isinstance(shape, StringShape):
            return "foo"
        elif isinstance(shape, ListShape):
            inner = shape.member
            return [sample(inner)]
        elif isinstance(shape, MapShape):
            value_type = shape.value
            return {f"{num}": sample(value_type) for num in range(1)}
        elif isinstance(shape, StructureShape):
            return {name: sample(shape) for name, shape in shape.members.items()}
        elif shape.type_name == "double":
            return 1.234
        elif shape.type_name == "integer":
            return 123
        elif shape.type_name == "boolean":
            return True
        elif shape.type_name == "long":
            return 123
        elif shape.type_name == "timestamp":
            return utc_str()
        else:
            raise NotImplementedError(f"Unsupported shape: {type(shape)}")

    return sample(op.output_shape)


def default_imports() -> str:
    return dedent(
        """
        from typing import ClassVar, Dict, Optional
        from attr import define, field
        from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource
        from fix_plugin_aws.utils import ToDict, TagsValue
        from fixlib.json_bender import Bender, S, K
        """
    )


models: Dict[str, List[AwsFixModel]] = {
    "accessanalyzer": [
        # AwsFixModel("list-analyzers", "analyzers", "AnalyzerSummary", prefix="AccessAnalyzer"),
    ],
    "acm-pca": [
        # AwsFixModel(
        #     "list-certificate-authorities", "CertificateAuthorities", "CertificateAuthority", prefix="ACMPCA"
        # ),
    ],
    "amp": [
        # AwsFixModel("list-workspaces", "workspaces", "WorkspaceSummary", prefix="Amp"),
    ],
    "amplify": [
        # AwsFixModel("list-apps", "apps", "App", prefix="Amplify"),
    ],
    "apigateway": [
        # AwsFixModel("get-vpc-links", "items", "VpcLink", prefix="ApiGateway"),
        # AwsFixModel("get-sdk-types", "items", "SdkType", prefix="ApiGateway"),
        # AwsFixModel("get-resources", "items", "Resource", prefix="ApiGateway"),
        # AwsFixModel("get-domain-names", "items", "DomainName", prefix="ApiGateway"),
        # AwsFixModel("get-client-certificates", "items", "ClientCertificate", prefix="ApiGateway"),
        # AwsFixModel("get-domain-names", "items", "DomainName", prefix="ApiGateway", prop_prefix="domain_")
    ],
    "apigatewayv2": [
        # AwsFixModel("get-domain-names", "Items", "DomainName", prefix="ApiGatewayV2"),
        # AwsFixModel("get-apis", "Items", "Api", prefix="ApiGatewayV2"),
    ],
    "appconfig": [
        # AwsFixModel("list-applications", "Items", "Application", prefix="AppConfig"),
    ],
    "appflow": [
        # AwsFixModel("list-flows", "flows", "FlowDefinition", prefix="Appflow"),
        # AwsFixModel("list-connectors", "connectors", "ConnectorDetail", prefix="Appflow"),
    ],
    "appintegrations": [
        # AwsFixModel(
        #     "list-data-integrations", "DataIntegrations", "DataIntegrationSummary", prefix="AppIntegrations"
        # ),
        # AwsFixModel("list-event-integrations", "EventIntegrations", "EventIntegration", prefix="AppIntegrations"),
    ],
    "application-insights": [
        # AwsFixModel("list-applications", "ApplicationInfoList", "ApplicationInfo", prefix="ApplicationInsights"),
        # AwsFixModel("list-problems", "ProblemList", "Problem", prefix="ApplicationInsights"),
    ],
    "applicationcostprofiler": [
        # AwsFixModel(
        #     "list-report-definitions", "reportDefinitions", "ReportDefinition", prefix="ApplicationCostProfiler"
        # ),
    ],
    "appmesh": [
        # AwsFixModel("list-meshes", "meshes", "MeshRef", prefix="AppMesh"),
    ],
    "apprunner": [
        # AwsFixModel("list-services", "ServiceSummaryList", "ServiceSummary", prefix="AppRunner"),
        # AwsFixModel("list-vpc-connectors", "VpcConnectors", "VpcConnector", prefix="AppRunner"),
        # AwsFixModel("list-connections", "ConnectionSummaryList", "ConnectionSummary", prefix="AppRunner"),
        # AwsFixModel(
        #     "list-auto-scaling-configurations",
        #     "AutoScalingConfigurationSummaryList",
        #     "AutoScalingConfigurationSummary",
        #     prefix="AppRunner",
        # ),
        # AwsFixModel(
        #     "list-observability-configurations ",
        #     "ObservabilityConfigurationSummaryList",
        #     "ObservabilityConfigurationSummary",
        #     prefix="AppRunner",
        # ),
    ],
    "appstream": [
        # AwsFixModel("describe-fleets", "Fleets", "Fleet", prefix="AppStream"),
        # AwsFixModel("describe-stacks", "Stacks", "Stack", prefix="AppStream"),
        # AwsFixModel("describe-images", "Images", "Image", prefix="AppStream"),
    ],
    "appsync": [
        # AwsFixModel("list-graphql-apis", "graphqlApis", "GraphqlApi", prefix="AppSync"),
        # AwsFixModel("list-domain-names", "domainNameConfigs", "DomainNameConfig", prefix="AppSync"),
    ],
    "athena": [
        # AwsFixModel("list-work-groups", "WorkGroups", "WorkGroup", prefix="Athena"),
        # AwsFixModel("list-data-catalogs", "DataCatalogs", "DataCatalog", prefix="Athena"),
    ],
    "autoscaling": [
        # AwsFixModel( "describe-auto-scaling-groups", "AutoScalingGroupName", "AutoScalingGroup", prefix="AutoScaling", prop_prefix="autoscaling_"),
    ],
    "cloudformation": [
        # AwsFixModel("describe-stacks", "Stacks", "Stack", prefix="CloudFormation", prop_prefix="stack_"),
        # AwsFixModel(
        #     "list-stack-sets", "Summaries", "StackSetSummary", prefix="CloudFormation", prop_prefix="stack_set_"
        # ),
        # AwsFixModel(
        #     "list-stack-instances",
        #     "Summaries",
        #     "StackInstanceSummary",
        #     prefix="CloudFormation",
        #     prop_prefix="stack_instance_",
        # ),
    ],
    "cloudfront": [
        # AwsFixModel(
        #     "get-distribution",
        #     "Distribution",
        #     "Distribution",
        #     prefix="CloudFront",
        #     prop_prefix="distribution_",
        # ),
        # AwsFixModel(
        #     "list-distributions",
        #     "DistributionSummary",
        #     "DistributionSummary",
        #     prefix="CloudFront",
        #     prop_prefix="distribution_",
        # ),
        # AwsFixModel(
        #     "list-functions", "FunctionSummary", "FunctionSummary", prefix="CloudFront", prop_prefix="function_"
        # ),
        # AwsFixModel(
        #     "list-invalidations",
        #     "InvalidationSummary",
        #     "InvalidationSummary",
        #     prefix="CloudFront",
        #     prop_prefix="invalidation_",
        # ),
        # AwsFixModel(
        #     "list-public-keys", "PublicKeySummary", "PublicKeySummary", prefix="CloudFront", prop_prefix="public_key_"
        # ),
        # AwsFixModel(
        #     "list-realtime-log-configs",
        #     "RealtimeLogSummary",
        #     "RealtimeLogConfig",
        #     prefix="CloudFront",
        #     prop_prefix="realtime_log_",
        # ),
        # AwsFixModel(
        #     "list-response-headers-policies",
        #     "ResponseHeadersPolicy",
        #     "ResponseHeadersPolicy",
        #     prefix="CloudFront",
        #     prop_prefix="response_header_policy_",
        # ),
        # AwsFixModel(
        #     "list-streaming-distributions",
        #     "StreamingDistributionList",
        #     "StreamingDistribution",
        #     prefix="CloudFront",
        #     prop_prefix="streaming_distribution_",
        # ),
        # AwsFixModel(
        #     "list-origin-access-controls",
        #     "OriginAccessControlList",
        #     "OriginAccessControlConfig",
        #     prefix="CloudFront",
        #     prop_prefix="origin_access_control_",
        # ),
        # AwsFixModel(
        #     "list-cache-policies",
        #     "CachePolicyList",
        #     "CachePolicy",
        #     prefix="CloudFront",
        #     prop_prefix="cache_policy_",
        # ),
        # AwsFixModel(
        #     "list-field-level-encryption-configs",
        #     "FieldLevelEncryptionList",
        #     "FieldLevelEncryptionConfig",
        #     prefix="CloudFront",
        #     prop_prefix="field_level_encryption_config_",
        # ),
        # AwsFixModel(
        #     "list-field-level-encryption-profiles",
        #     "FieldLevelEncryptionProfileList",
        #     "FieldLevelEncryptionProfileSummary",
        #     prefix="CloudFront",
        #     prop_prefix="field_level_encryption_profile_",
        # ),
    ],
    "cloudwatch": [
        # AwsFixModel(
        #     "describe-alarms",
        #     "Alarms",
        #     "MetricAlarm",
        #     prefix="Cloudwatch",
        #     prop_prefix="cloudwatch_"
        # ),
        # AwsFixModel(
        #     "get-metric-data", "GetMetricDataResult", "MetricDataResult", prefix="Cloudwatch", prop_prefix="metric_"
        # )
    ],
    "cognito-idp": [
        # AwsFixModel(
        #     "list-user-pools", "UserPools", "ListUserPoolsResponse", prefix="Cognito", prop_prefix="user_pool_"
        # ),
        # AwsFixModel("list-users", "Users", "ListUsersResponse", prefix="Cognito", prop_prefix="user_"),
        # AwsFixModel("list-groups", "Groups", "ListGroupsResponse", prefix="Cognito", prop_prefix="group_")
    ],
    "dynamodb": [
        # AwsFixModel("list-tables", "TableNames", "TableDescription", prefix="DynamoDb", prop_prefix="dynamodb_"),
        # AwsFixModel(
        #     "list-global-tables", "GlobalTables", "GlobalTableDescription", prefix="DynamoDb", prop_prefix="dynamodb_"
        # ),
    ],
    "ec2": [
        # AwsFixModel("describe-hosts", "Hosts", "Host", prefix="Ec2", prop_prefix="host_")
        # AwsFixModel( "describe-route-tables", "RouteTables", "RouteTable", base="BaseRoutingTable", prefix="Ec2", prop_prefix="route_table_", ),
        # AwsFixModel( "describe-vpc-endpoints", "VpcEndpoints", "VpcEndpoint", base="BaseEndpoint", prefix="Ec2", prop_prefix="endpoint_", ),
        # AwsFixModel( "describe-vpc-peering-connections", "VpcPeeringConnections", "VpcPeeringConnection", base="BasePeeringConnection", prefix="Ec2", prop_prefix="connection_", ),
        # AwsFixModel( "describe-snapshots", "Snapshots", "Snapshot", base="BaseSnapshot", prefix="Ec2", prop_prefix="snapshot_" ),
        # AwsFixModel( "describe-internet-gateways", "InternetGateways", "InternetGateway", base="BaseGateway", prefix="Ec2", prop_prefix="gateway_", ),
        # AwsFixModel( "describe-nat-gateways", "NatGateways", "NatGateway", base="BaseGateway", prefix="Ec2", prop_prefix="nat_" ),
        # AwsFixModel( "describe-security-groups", "SecurityGroups", "SecurityGroup", base="BaseSecurityGroup", prefix="Ec2", prop_prefix="group_", ),
        # AwsFixModel( "describe-subnets", "Subnets", "Subnet", base="BaseSubnet", prefix="Ec2", prop_prefix="subnet_", ),
        # AwsFixModel("describe-vpcs", "Vpcs", "Vpc", base="BaseNetwork", prefix="Ec2", prop_prefix="vpc_"),
        # AwsFixModel( "describe-addresses", "Addresses", "Address", base="BaseIPAddress", prefix="Ec2", prop_prefix="ip_" ),
        # AwsFixModel( "describe-network-interfaces", "NetworkInterfaces", "NetworkInterface", base="BaseNetworkInterface", prefix="Ec2", prop_prefix="nic_", ),
        # AwsFixModel( "describe-instances", "Reservations", "Instance", base="BaseInstance", prefix="Ec2", prop_prefix="instance_", ),
        # AwsFixModel("describe-key-pairs", "KeyPairs", "KeyPairInfo", prefix="Ec2"),
        # AwsFixModel("describe-volumes", "Volumes", "Volume", base="BaseVolume", prefix="Ec2"),
        # AwsFixModel("describe_addresses", "Addresses", "Address", prefix="Ec2"),
        # AwsFixModel( "describe-instance-types", "InstanceTypes", "InstanceTypeInfo", prefix="Ec2", prop_prefix="reservation_" ),
        # AwsFixModel( "describe_reserved_instances", "ReservedInstances", "ReservedInstances", prefix="Ec2", prop_prefix="reservation_", ),
        # AwsFixModel("describe-network-acls", "NetworkAcls", "NetworkAcl", prefix="Ec2"),
        # AwsFixModel("describe-flow-logs", "FlowLogs", "FlowLog", prefix="Ec2"),
        # AwsFixModel("describe-images", "Images", "Image", prefix="Ec2"),
        # AwsFixModel( "describe-launch-template-versions", "LaunchTemplateVersions", "LaunchTemplateVersion", prefix="LaunchTemplate", ),
    ],
    "ecs": [
        # AwsFixModel(
        #     "describe-clusters", "clusters", "DescribeClustersResponse", prefix="Ecs", prop_prefix="cluster_"
        # ),
        # AwsFixModel(
        #     "describe-container-instances",
        #     "containerInstances",
        #     "DescribeContainerInstancesResponse",
        #     prefix="Ecs",
        #     prop_prefix="container_",
        # ),
        # AwsFixModel("describe-tasks", "tasks", "DescribeTasksResponse", prefix="Ecs", prop_prefix="task_"),
        # AwsFixModel(
        #     "describe-task-definition",
        #     "taskDefinition",
        #     "DescribeTaskDefinitionResponse",
        #     prefix="Ecs",
        #     prop_prefix="task_definition_",
        # ),
        # AwsFixModel(
        # "describe-services", "services", "DescribeServicesResponse", prefix="Ecs", prop_prefix="service_"
        # ),
        # AwsFixModel(
        #     "describe-capacity-providers",
        #     "capacityProviders",
        #     "DescribeCapacityProvidersResponse",
        #     prefix="Ecs",
        #     prop_prefix="capacity_provider_",
        # )
    ],
    "efs": [
        # AwsFixModel(
        #     "describe-file-systems", "FileSystems", "FileSystemDescription", prefix="Efs", name="EfsFileSystem"
        # ),
        # AwsFixModel("describe-mount-targets", "MountTargets", "MountTargetDescription", prefix="Efs"),
        # AwsFixModel(
        #     "describe-access-points", "AccessPoints", "AccessPointDescription", prefix="Efs", name="EfsAccessPoint"
        # ),
    ],
    "elasticbeanstalk": [
        # AwsFixModel(
        #     "describe-applications",
        #     "Applications",
        #     "ApplicationDescriptionsMessage",
        #     prefix="Beanstalk",
        #     prop_prefix="beanstalk_",
        # ),
        # AwsFixModel(
        #     "describe-environments",
        #     "Environments",
        #     "EnvironmentDescriptionsMessage",
        #     prefix="Beanstalk",
        #     prop_prefix="environment_"
        # )
    ],
    "elasticache": [
        # AwsFixModel(
        #     "describe-cache-clusters",
        #     "CacheClusters",
        #     "CacheCluster",
        #     prefix="ElastiCache",
        #     prop_prefix="cluster_",
        # ),
        # AwsFixModel(
        #     "describe-replication-groups",
        #     "ReplicationGroups",
        #     "ReplicationGroup",
        #     prefix="ElastiCache",
        #     prop_prefix="replication_group_",
        # ),
    ],
    "elb": [
        # AwsFixModel( "describe-load-balancers", "LoadBalancerDescriptions", "LoadBalancerDescription", prefix="Elb", prop_prefix="elb_", ),
        # AwsFixModel( "describe-load-balancer-attributes", "DescribeLoadBalancerAttributesResult", "LoadBalancerAttributes", prefix="Elb" ),
    ],
    "elbv2": [
        # AwsFixModel(
        #     "describe-load-balancers",
        #     "DescribeLoadBalancersResult",
        #     "LoadBalancer",
        #     prefix="Alb",
        #     prop_prefix="alb_",
        # ),
        # AwsFixModel(
        #     "describe-target-groups",
        #     "TargetGroups",
        #     "TargetGroup",
        #     prefix="Alb",
        #     prop_prefix="alb_",
        # ),
        # AwsFixModel(
        #     "describe-target-health",
        #     "TargetHealthDescriptions",
        #     "TargetHealthDescription",
        #     prefix="Alb",
        # ),
        # AwsFixModel(
        #     "describe-listeners",
        #     "DescribeListenersResult",
        #     "Listener",
        #     prefix="Alb",
        # ),
    ],
    "ecr": [
        # AwsFixModel("describe-repositories", "repositories", "Repository", prefix="Ecr"),
        # AwsFixModel("describe-images", "images", "Image", prefix="Ecr"),
    ],
    "eks": [
        # AwsFixModel("list-clusters", "clusters", "Cluster", prefix="Eks", prop_prefix="cluster_"),
        # AwsFixModel("list-nodegroups", "nodegroup", "Nodegroup", prefix="Eks", prop_prefix="group_"),
    ],
    "glacier": [
        # AwsFixModel("list-vaults", "VaultList", "ListVaultsOutput", prefix="Glacier", prop_prefix="glacier_"),
    ],
    "kinesis": [
        # AwsFixModel("list-streams", "StreamNames", "StreamDescription", prefix="Kinesis", prop_prefix="kinesis_"),
    ],
    "kms": [
        # AwsFixModel(
        #     "list-keys",
        #     result_property="Keys",
        #     result_shape="ListKeysResponse",
        #     prefix="Kms",
        #     prop_prefix="kms_"
        # )
    ],
    "lambda": [
        # AwsFixModel(
        #     "list-functions",
        #     "Functions",
        #     "FunctionConfiguration",
        #     prefix="Lambda",
        #     prop_prefix="function_",
        # )
        # AwsFixModel("get-policy", "Policy", "GetPolicyResponse", prefix="Lambda", prop_prefix="policy_")
        # AwsFixModel(
        #     "get-function-url-config",
        #     "",
        #     "GetFunctionUrlConfigResponse",
        #     name="AwsLambdaFunctionUrlConfig",
        #     prefix="Lambda",
        # )
    ],
    "logs": [
        # AwsFixModel("describe-log-groups", "logGroups", "LogGroup", prefix="Cloudwatch", prop_prefix="group_"),
        # AwsFixModel(
        #     "describe-metric-filters", "metricFilters", "MetricFilter", prefix="Cloudwatch", prop_prefix="filter_"
        # ),
    ],
    "iam": [
        # AwsFixModel(
        #     "list-server-certificates",
        #     "ServerCertificateMetadataList",
        #     "ServerCertificateMetadata",
        #     prefix="Iam",
        #     prop_prefix="server_certificate_",
        # ),
        # AwsFixModel(
        #     "get-account-authorization-details",
        #     "GetAccountAuthorizationDetailsResult",
        #     "GetAccountAuthorizationDetailsResponse",
        #     prefix="Iam",
        #     prop_prefix="policy_",
        # ),
        # AwsFixModel(
        #     "get-account-authorization-details",
        #     "GetAccountAuthorizationDetailsResult",
        #     "GetAccountAuthorizationDetailsResponse",
        #     prefix="Iam",
        #     prop_prefix="policy_",
        # ),
        # AwsFixModel(
        #     "list-instance-profiles",
        #     "InstanceProfiles",
        #     "InstanceProfile",
        #     prefix="Iam",
        #     prop_prefix="instance_profile_",
        # ),
        # AwsFixModel(
        #     "list-policies",
        #     "Policies",
        #     "Policy",
        #     prefix="Iam",
        #     prop_prefix="policy_",
        # ),
        # AwsFixModel(
        #     "list-groups",
        #     "Groups",
        #     "Group",
        #     prefix="Iam",
        #     prop_prefix="group_",
        # ),
        # AwsFixModel(
        #     "list-roles",
        #     "Roles",
        #     "Role",
        #     prefix="Iam",
        #     prop_prefix="role_",
        # ),
        # AwsFixModel(
        #     "list-users",
        #     "Users",
        #     "User",
        #     prefix="Iam",
        #     prop_prefix="user_",
        # ),
        # AwsFixModel(
        #     "list-access-keys",
        #     "AccessKeyMetadata",
        #     "AccessKeyMetadata",
        #     prefix="Iam",
        #     prop_prefix="access_key_",
        # ),
        # AwsFixModel(
        #     "list-access-keys-last-user",
        #     "AccessKeyLastUsed",
        #     "AccessKeyLastUsed",
        #     prefix="Iam",
        #     prop_prefix="access_key_",
        # ),
    ],
    "pricing": [
        # AwsFixModel("get-products", "PriceList", "PriceListItemJSON", prefix="Price", prop_prefix="price_")
    ],
    "redshift": [
        # AwsFixModel( "describe-clusters", "Clusters", "Cluster", prefix="Redshift", prop_prefix="redshift_"),
        # AwsFixModel("describe-logging-status", "DescribeLoggingStatusResponse", prefix="Redshift"),
    ],
    "rds": [
        #     # AwsFixModel("describe-db-instances", "Instances", "DBInstance", prefix="Rds", prop_prefix="rds_")
        #     # AwsFixModel("describe-db-clusters", "Clusters", "DBCluster", prefix="Rds", prop_prefix="rds_")
        #     # AwsFixModel("describe-db-snapshots", "DBSnapshots", "DBSnapshot", prefix="Rds", prop_prefix="rds_")
        #     AwsFixModel( "describe-db-cluster-snapshots", "DBClusterSnapshots", "DBClusterSnapshot", prefix="Rds", prop_prefix="rds_")
    ],
    "route53": [
        # AwsFixModel("list_hosted_zones", "HostedZones", "HostedZone", prefix="Route53", prop_prefix="zone_"),
        # AwsFixModel( "list_resource_record_sets", "ResourceRecordSets", "ResourceRecordSet", prefix="Route53", prop_prefix="record_", ),
        # AwsFixModel("list-query-logging-configs", "QueryLoggingConfigs", "QueryLoggingConfig", prefix="Route53"),
    ],
    "s3": [
        # AwsFixModel("list-buckets", "Buckets", "Bucket", prefix="S3", prop_prefix="s3_"),
        # AwsFixModel(
        #     "get-bucket-encryption", "ServerSideEncryptionConfiguration", "GetBucketEncryptionOutput", prefix="S3"
        # ),
        # AwsFixModel("get-public-access-block", "PublicAccessBlockConfiguration", prefix="S3"),
        # AwsFixModel("get-bucket-acl", "", prefix="S3"),
        # AwsFixModel("get-bucket-logging", "", prefix="S3"),
    ],
    "sagemaker": [
        # AwsFixModel(
        #     "describe-notebook-instance",
        #     None,
        #     "DescribeNotebookInstanceOutput",
        #     prefix="Sagemaker",
        #     prop_prefix="notebook_",
        # ),
        # AwsFixModel("describe-algorithm", None, "DescribeAlgorithmOutput", "Sagemaker", "algorithm_"),
        # AwsFixModel("describe-app", None, "DescribeAppResponse", prefix="Sagemaker", prop_prefix="app_"),
        # AwsFixModel("describe-model", None, "DescribeModelOutput", "Sagemaker", "model_")
        # AwsFixModel("describe-domain", None, "DescribeDomainResponse", prefix="Sagemaker", prop_prefix="domain_"),
        # AwsFixModel("list-experiments", None, "ExperimentSummary", "Sagemaker", "experiment_"),
        # AwsFixModel("describe-trial", "TrialSummaries", "DescribeTrialResponse", "Sagemaker", "trial_"),
        # AwsFixModel(
        #     "list-code-repositories",
        #     "CodeRepositorySummaryList",
        #     "CodeRepositorySummary",
        #     "Sagemaker",
        #     "code_repository_",
        # ),
        # AwsFixModel("describe-endpoint", "Endpoints", "DescribeEndpointOutput", "Sagemaker", "endpoint_"),
        # AwsFixModel("describe-image", "Images", "DescribeImageResponse", "Sagemaker", "image_"),
        # AwsFixModel(
        #     "describe-artifact",
        #     "ArtifactSummaries",
        #     "DescribeArtifactResponse",
        #     "Sagemaker",
        #     "artifact_"
        # ),
        # AwsFixModel("list-user-profiles", "UserProfiles", "UserProfileDetails", "Sagemaker", "user_profile_"),
        # AwsFixModel("list-pipelines", "PipelineSummaries", "DescribePipelineResponse", "Sagemaker", "pipeline_"),
        # AwsFixModel(
        #     "list-auto-ml-jobs", "AutoMLJobSummaries", "DescribeAutoMLJobResponse", "Sagemaker", "auto_ml_job_"
        # ),
        # AwsFixModel("list-workteams", "Workteams", "Workteam", "Sagemaker", "workteam_"),
        # AwsFixModel(
        #     "list-compilation-jobs",
        #     "CompilationJobSummaries",
        #     "DescribeCompilationJobResponse",
        #     "Sagemaker",
        #     "compilation_job_",
        # ),
        # AwsFixModel(
        #     "list-edge-packaging-jobs",
        #     "EdgePackagingJobSummaries",
        #     "DescribeEdgePackagingJobResponse",
        #     "Sagemaker",
        #     "edge_packaging_job_",
        # ),
        # AwsFixModel(
        #     "list-hyper-parameter-tuning-jobs",
        #     "HyperParameterTuningJobSummaries",
        #     "DescribeHyperParameterTuningJobResponse",
        #     "Sagemaker",
        #     "hyper_parameter_tuning_job_",
        # ),
        # AwsFixModel(
        #     "list-inference-recommendations-job",
        #     "InferenceRecommendationsJobs",
        #     "DescribeInferenceRecommendationsJobResponse",
        #     "Sagemaker",
        #     "inference_recommendations_job_",
        # ),
        # AwsFixModel(
        #     "list-labeling-jobs",
        #     "LabelingJobSummaryList",
        #     "DescribeLabelingJobResponse",
        #     "Sagemaker",
        #     "labeling_job_"
        # ),
        # AwsFixModel("list-projects", "ProjectSummaryList", "ProjectSummary", "Sagemaker", "project_")
        # AwsFixModel(
        #     "list-processing-jobs",
        #     "ProcessingJobSummaries",
        #     "DescribeProcessingJobResponse",
        #     "Sagemaker",
        #     "processing_job_",
        # ),
        # AwsFixModel(
        #     "list-training-jobs", "TrainingJobSummaries", "DescribeTrainingJobResponse", "Sagemaker", "training_job_"
        # ),
        # AwsFixModel(
        #     "list-transform-jobs",
        #     "TransformJobSummaries",
        #     "DescribeTransformJobResponse",
        #     "Sagemaker",
        #     "transform_job_",
        # )
    ],
    "service-quotas": [
        # AwsFixModel("list-service-quotas", "Quotas", "ServiceQuota", prefix="Quota", prop_prefix="quota_")
    ],
    "sns": [
        # AwsFixModel(
        #     "get-topic-attributes",
        #     result_property="Attributes",
        #     result_shape="GetTopicAttributesResponse",
        #     prefix="Sns",
        #     prop_prefix="topic_",
        # )
        # AwsFixModel(
        #     "get-subscription-attributes",
        #     result_property="Attributes",
        #     result_shape="GetSubscriptionAttributesResponse",
        #     prefix="Sns",
        #     prop_prefix="subscription_",
        # )
    ],
    "sqs": [
        # AwsFixModel(
        #     "get-queue-attributes", "Attributes", "GetQueueAttributesResult", prefix="Sqs", prop_prefix="sqs_"
        # )
    ],
    "cloudtrail": [
        # AwsFixModel("list-trails", "Trails", "TrailInfo", prefix="CloudTrail", prop_prefix="trail_")
        # AwsFixModel("get-trail-status", "", prefix="CloudTrail")
        # AwsFixModel("get-event-selectors", "", prefix="CloudTrail")
    ],
    "config": [
        # AwsFixModel(
        #     "describe-configuration-recorders-status",
        #     "ConfigurationRecorders",
        #     "ConfigurationRecorder",
        #     prefix="Config",
        #     prop_prefix="configuration_recorder_",
        # ),
    ],
    "ssm": [
        # AwsFixModel("describe-instance-information", "InstanceInformationList", "InstanceInformation", prefix="SSM"),
        # AwsFixModel("list-documents", "DocumentIdentifiers", "DocumentIdentifier", prefix="SSM"),
        # AwsFixModel("list-documents", "DocumentIdentifiers", "DescribeDocumentPermissionResponse", prefix="SSM"),
        # AwsFixModel( "list-resource-compliance-summaries", "ResourceComplianceSummaryItems", "ResourceComplianceSummaryItem", prefix="SSM", ),
    ],
    "secretsmanager": [
        # AwsFixModel( "list-secrets", "SecretList", "SecretListEntry", prefix="SecretsManager", name="AwsSecretsManagerSecret" ),
        # AwsFixModel("list-secrets", "SecretList", "SecretVersionStagesType", prefix="SecretsManager"),
    ],
    "opensearch": [
        # AwsFixModel("describe-domains", "DomainStatusList", "DomainStatus", prefix="OpenSearch", name="AwsOpenSearchDomain"),
    ],
    "acm": [
        # AwsFixModel("describe-certificate", "Certificate", "CertificateDetail", prefix="Acm", name="AcmCertificate")
    ],
    "wafv2": [
        # AwsFixModel("get-logging-configuration", "LoggingConfigurations", "LoggingConfiguration", prefix="Waf")
    ],
    "qbusiness": [
        # AwsFixModel(
        #     api_action="list-applications",
        #     result_property="applications",
        #     result_shape="Applications",
        #     prefix="QBusiness",
        # ),
    ],
    "qapps": [
        # AwsFixModel(
        #     api_action="list-qapps",
        #     result_property="apps",
        #     result_shape="ListQAppsOutput",
        #     prefix="QApps",
        # ),
    ],
    "backup": [
        # AwsFixModel(
        #     api_action="list-backup-job-summaries",
        #     result_property="BackupJobSummaries",
        #     result_shape="BackupJobSummaryList",
        #     prefix="Backup",
        # ),
    ],
    "bedrock": [
        # AwsFixModel(
        #     api_action="list-foundation-models",
        #     result_property="modelSummaries",
        #     result_shape="ListFoundationModelsResponse",
        #     prefix="Bedrock",
        # )
    ],
    "bedrock-agent": [
        # AwsFixModel(
        #     api_action="get-agent",
        #     result_property="Agents",
        #     result_shape=None,
        #     prefix="Bedrock",
        # )
    ],
    "guardduty": [
        # AwsFixModel(
        #     api_action="get-findings",
        #     result_property="Findings",
        #     result_shape="GetFindingsResponse",
        #     prefix="GuardDuty",
        # ),
    ],
    "inspector2": [
        # AwsFixModel(
        #     api_action="list-findings",
        #     result_property="findings",
        #     result_shape="ListFindingsResponse",
        #     prefix="InspectorV2",
        # ),
    ],
}


if __name__ == "__main__":
    """print some test data"""
    # print(json.dumps(create_test_response("inspector2", "list-coverage"), indent=2))

    """print the class models"""
    # print(default_imports())
    for model in all_models():
        # pass
        print(model.to_class())
