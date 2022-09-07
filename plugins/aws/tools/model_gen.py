import re
from typing import List, Set, Optional, Tuple, Union, Dict

import boto3
from attrs import define
from botocore.model import ServiceModel, StringShape, ListShape, Shape, StructureShape, MapShape


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
        return f"field({default})"

    def type_string(self) -> str:
        if self.is_array:
            return f"List[{self.type}]"
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
class AwsResotoModel:
    api_action: str  # action to perform on the client
    result_property: str  # this property holds the resulting list
    result_shape: str  # the shape of the result according to the service specification
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
}
simple_type_map |= {k.lower(): v for k, v in simple_type_map.items()}

ignore_props = {"Tags", "tags"}


def service_model(name: str) -> ServiceModel:
    return boto3.client(name, region_name="us-east-1")._service_model


def clazz_model(
    model: ServiceModel,
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
    if isinstance(shape, StructureShape):
        for name, prop_shape in shape.members.items():
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
                    result.extend(clazz_model(model, inner, visited, prefix))
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
                result.extend(clazz_model(model, prop_shape.value, visited, prefix))
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
                    result.extend(clazz_model(model, prop_shape, visited, prefix))
                    props.append(
                        AwsProperty(
                            prop_prefix + prop, name, type_name(prop_shape), prop_shape.documentation, is_complex=True
                        )
                    )
            else:
                raise NotImplementedError(f"Unsupported shape: {prop_shape}")

        clazz_name = clazz_name if clazz_name else type_name(shape)
        result.append(AwsModel(clazz_name, props, aggregate_root, base_class, api_info))
    return result


def all_models() -> List[AwsModel]:
    visited: Set[str] = set()
    result: List[AwsModel] = []
    for name, endpoint in models.items():
        sm = service_model(name)
        for ep in endpoint:
            shape = sm.shape_for(ep.result_shape)
            result.extend(
                clazz_model(
                    sm,
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


models: Dict[str, List[AwsResotoModel]] = {
    "accessanalyzer": [
        # AwsResotoModel("list-analyzers", "analyzers", "AnalyzerSummary", prefix="AccessAnalyzer"),
    ],
    "acm": [
        # AwsResotoModel("list-certificates", "CertificateSummaryList", "CertificateSummary", prefix="ACM"),
    ],
    "acm-pca": [
        # AwsResotoModel(
        #     "list-certificate-authorities", "CertificateAuthorities", "CertificateAuthority", prefix="ACMPCA"
        # ),
    ],
    "alexaforbusiness": [],  # TODO: implement
    "amp": [
        # AwsResotoModel("list-workspaces", "workspaces", "WorkspaceSummary", prefix="Amp"),
    ],
    "amplify": [
        # AwsResotoModel("list-apps", "apps", "App", prefix="Amplify"),
    ],
    "apigateway": [
        # AwsResotoModel("get-vpc-links", "items", "VpcLink", prefix="ApiGateway"),
        # AwsResotoModel("get-sdk-types", "items", "SdkType", prefix="ApiGateway"),
        # AwsResotoModel("get-resources", "items", "Resource", prefix="ApiGateway"),
        # AwsResotoModel("get-domain-names", "items", "DomainName", prefix="ApiGateway"),
        # AwsResotoModel("get-client-certificates", "items", "ClientCertificate", prefix="ApiGateway"),
        AwsResotoModel("get-domain-names", "items", "DomainName", prefix="ApiGateway", prop_prefix="domain_")
    ],
    "apigatewayv2": [
        # AwsResotoModel("get-domain-names", "Items", "DomainName", prefix="ApiGatewayV2"),
        # AwsResotoModel("get-apis", "Items", "Api", prefix="ApiGatewayV2"),
    ],
    "appconfig": [
        # AwsResotoModel("list-applications", "Items", "Application", prefix="AppConfig"),
    ],
    "appflow": [
        # AwsResotoModel("list-flows", "flows", "FlowDefinition", prefix="Appflow"),
        # AwsResotoModel("list-connectors", "connectors", "ConnectorDetail", prefix="Appflow"),
    ],
    "appintegrations": [
        # AwsResotoModel(
        #     "list-data-integrations", "DataIntegrations", "DataIntegrationSummary", prefix="AppIntegrations"
        # ),
        # AwsResotoModel("list-event-integrations", "EventIntegrations", "EventIntegration", prefix="AppIntegrations"),
    ],
    "application-insights": [
        # AwsResotoModel("list-applications", "ApplicationInfoList", "ApplicationInfo", prefix="ApplicationInsights"),
        # AwsResotoModel("list-problems", "ProblemList", "Problem", prefix="ApplicationInsights"),
    ],
    "applicationcostprofiler": [
        # AwsResotoModel(
        #     "list-report-definitions", "reportDefinitions", "ReportDefinition", prefix="ApplicationCostProfiler"
        # ),
    ],
    "appmesh": [
        # AwsResotoModel("list-meshes", "meshes", "MeshRef", prefix="AppMesh"),
    ],
    "apprunner": [
        # AwsResotoModel("list-services", "ServiceSummaryList", "ServiceSummary", prefix="AppRunner"),
        # AwsResotoModel("list-vpc-connectors", "VpcConnectors", "VpcConnector", prefix="AppRunner"),
        # AwsResotoModel("list-connections", "ConnectionSummaryList", "ConnectionSummary", prefix="AppRunner"),
        # AwsResotoModel(
        #     "list-auto-scaling-configurations",
        #     "AutoScalingConfigurationSummaryList",
        #     "AutoScalingConfigurationSummary",
        #     prefix="AppRunner",
        # ),
        # AwsResotoModel(
        #     "list-observability-configurations ",
        #     "ObservabilityConfigurationSummaryList",
        #     "ObservabilityConfigurationSummary",
        #     prefix="AppRunner",
        # ),
    ],
    "appstream": [
        # AwsResotoModel("describe-fleets", "Fleets", "Fleet", prefix="AppStream"),
        # AwsResotoModel("describe-stacks", "Stacks", "Stack", prefix="AppStream"),
        # AwsResotoModel("describe-images", "Images", "Image", prefix="AppStream"),
    ],
    "appsync": [
        # AwsResotoModel("list-graphql-apis", "graphqlApis", "GraphqlApi", prefix="AppSync"),
        # AwsResotoModel("list-domain-names", "domainNameConfigs", "DomainNameConfig", prefix="AppSync"),
    ],
    "athena": [
        # AwsResotoModel("list-work-groups", "WorkGroups", "WorkGroup", prefix="Athena"),
        # AwsResotoModel("list-data-catalogs", "DataCatalogs", "DataCatalog", prefix="Athena"),
    ],
    "autoscaling": [
        # AwsResotoModel(
        #     "describe-auto-scaling-groups",
        #     "AutoScalingGroupName",
        #     "AutoScalingGroup",
        #     prefix="AutoScaling",
        #     prop_prefix="autoscaling_",
        # ),
    ],
    "cloudformation": [
        # AwsResotoModel("describe-stacks", "Stacks", "Stack", prefix="CloudFormation", prop_prefix="stack_"),
        # AwsResotoModel(
        #     "list-stack-sets", "Summaries", "StackSetSummary", prefix="CloudFormation", prop_prefix="stack_set_"
        # ),
    ],
    "cloudwatch": [
        # AwsResotoModel(
        #     "describe-alarms",
        #     "Alarms",
        #     "MetricAlarm",
        #     prefix="Cloudwatch",
        #     prop_prefix="cloudwatch_"
        # ),
        # AwsResotoModel(
        #     "get-metric-data", "GetMetricDataResult", "MetricDataResult", prefix="Cloudwatch", prop_prefix="metric_"
        # )
    ],
    "dynamodb": [
        # AwsResotoModel("list-tables", "TableNames", "TableDescription", prefix="DynamoDb", prop_prefix="dynamodb_"),
        # AwsResotoModel(
        #     "list-global-tables", "GlobalTables", "GlobalTableDescription", prefix="DynamoDb", prop_prefix="dynamodb_"
        # ),
    ],
    "ec2": [
        # AwsResotoModel("describe-hosts", "Hosts", "Host", prefix="Ec2", prop_prefix="host_")
        # AwsResotoModel(
        #     "describe-route-tables",
        #     "RouteTables",
        #     "RouteTable",
        #     base="BaseRoutingTable",
        #     prefix="Ec2",
        #     prop_prefix="route_table_",
        # ),
        # AwsResotoModel(
        #     "describe-vpc-endpoints",
        #     "VpcEndpoints",
        #     "VpcEndpoint",
        #     base="BaseEndpoint",
        #     prefix="Ec2",
        #     prop_prefix="endpoint_",
        # ),
        # AwsResotoModel(
        #     "describe-vpc-peering-connections",
        #     "VpcPeeringConnections",
        #     "VpcPeeringConnection",
        #     base="BasePeeringConnection",
        #     prefix="Ec2",
        #     prop_prefix="connection_",
        # ),
        # AwsResotoModel(
        #     "describe-snapshots", "Snapshots", "Snapshot", base="BaseSnapshot", prefix="Ec2", prop_prefix="snapshot_"
        # ),
        # AwsResotoModel(
        #     "describe-internet-gateways",
        #     "InternetGateways",
        #     "InternetGateway",
        #     base="BaseGateway",
        #     prefix="Ec2",
        #     prop_prefix="gateway_",
        # ),
        # AwsResotoModel(
        #     "describe-nat-gateways", "NatGateways", "NatGateway", base="BaseGateway", prefix="Ec2", prop_prefix="nat_"
        # ),
        # AwsResotoModel(
        #     "describe-security-groups",
        #     "SecurityGroups",
        #     "SecurityGroup",
        #     base="BaseSecurityGroup",
        #     prefix="Ec2",
        #     prop_prefix="group_",
        # ),
        # AwsResotoModel(
        #     "describe-subnets",
        #     "Subnets",
        #     "Subnet",
        #     base="BaseSubnet",
        #     prefix="Ec2",
        #     prop_prefix="subnet_",
        # ),
        # AwsResotoModel("describe-vpcs", "Vpcs", "Vpc", base="BaseNetwork", prefix="Ec2", prop_prefix="vpc_"),
        # AwsResotoModel(
        #     "describe-addresses", "Addresses", "Address", base="BaseIPAddress", prefix="Ec2", prop_prefix="ip_"
        # ),
        # AwsResotoModel(
        #     "describe-network-interfaces",
        #     "NetworkInterfaces",
        #     "NetworkInterface",
        #     base="BaseNetworkInterface",
        #     prefix="Ec2",
        #     prop_prefix="nic_",
        # ),
        # AwsResotoModel(
        #     "describe-instances",
        #     "Reservations",
        #     "Instance",
        #     base="BaseInstance",
        #     prefix="Ec2",
        #     prop_prefix="instance_",
        # ),
        # AwsResotoModel("describe-key-pairs", "KeyPairs", "KeyPairInfo", prefix="Ec2"),
        # AwsResotoModel("describe-volumes", "Volumes", "Volume", base="BaseVolume", prefix="Ec2"),
        # AwsResotoModel("describe_addresses", "Addresses", "Address", prefix="Ec2"),
        # AwsResotoModel(
        #     "describe-instance-types", "InstanceTypes", "InstanceTypeInfo", prefix="Ec2", prop_prefix="reservation_"
        # ),
        # AwsResotoModel(
        #     "describe_reserved_instances",
        #     "ReservedInstances",
        #     "ReservedInstances",
        #     prefix="Ec2",
        #     prop_prefix="reservation_",
        # ),
        # AwsResotoModel("describe-network-acls", "NetworkAcls", "NetworkAcl", prefix="Ec2"),
    ],
    "elasticbeanstalk": [
        # AwsResotoModel(
        #     "describe-applications",
        #     "Applications",
        #     "ApplicationDescriptionsMessage",
        #     prefix="Beanstalk",
        #     prop_prefix="beanstalk_",
        # ),
        # AwsResotoModel(
        #     "describe-environments",
        #     "Environments",
        #     "EnvironmentDescriptionsMessage",
        #     prefix="Beanstalk",
        #     prop_prefix="environment_"
        # )
    ],
    "elasticache": [
        # AwsResotoModel(
        #     "describe-cache-clusters",
        #     "CacheClusters",
        #     "CacheCluster",
        #     prefix="ElastiCache",
        #     prop_prefix="cluster_",
        # ),
        # AwsResotoModel(
        #     "describe-replication-groups",
        #     "ReplicationGroups",
        #     "ReplicationGroup",
        #     prefix="ElastiCache",
        #     prop_prefix="replication_group_",
        # ),
    ],
    "elb": [
        # AwsResotoModel(
        #     "describe-load-balancers",
        #     "LoadBalancerDescriptions",
        #     "LoadBalancerDescription",
        #     prefix="Elb",
        #     prop_prefix="elb_",
        # ),
    ],
    "elbv2": [
        # AwsResotoModel(
        #     "describe-load-balancers",
        #     "DescribeLoadBalancersResult",
        #     "LoadBalancer",
        #     prefix="Alb",
        #     prop_prefix="alb_",
        # ),
        # AwsResotoModel(
        #     "describe-target-groups",
        #     "TargetGroups",
        #     "TargetGroup",
        #     prefix="Alb",
        #     prop_prefix="alb_",
        # ),
        # AwsResotoModel(
        #     "describe-target-health",
        #     "TargetHealthDescriptions",
        #     "TargetHealthDescription",
        #     prefix="Alb",
        # ),
        # AwsResotoModel(
        #     "describe-listeners",
        #     "DescribeListenersResult",
        #     "Listener",
        #     prefix="Alb",
        # ),
    ],
    "eks": [
        # AwsResotoModel("list-clusters", "clusters", "Cluster", prefix="Eks", prop_prefix="cluster_"),
        # AwsResotoModel("list-nodegroups", "nodegroup", "Nodegroup", prefix="Eks", prop_prefix="group_"),
    ],
    "glacier": [
        # AwsResotoModel("list-vaults", "VaultList", "ListVaultsOutput", prefix="Glacier", prop_prefix="glacier_"),
    ],
    "kinesis": [
        # AwsResotoModel("list-streams", "StreamNames", "StreamDescription", prefix="Kinesis", prop_prefix="kinesis_"),
    ],
    "kms": [
        # AwsResotoModel(
        #     "list-keys",
        #     result_property="Keys",
        #     result_shape="ListKeysResponse",
        #     prefix="Kms",
        #     prop_prefix="kms_"
        # )
    ],
    "lambda": [
        # AwsResotoModel(
        #     "list-functions",
        #     "Functions",
        #     "FunctionConfiguration",
        #     prefix="Lambda",
        #     prop_prefix="function_",
        # )
        # AwsResotoModel("get-policy", "Policy", "GetPolicyResponse", prefix="Lambda", prop_prefix="policy_")
    ],
    "iam": [
        # AwsResotoModel(
        #     "list-server-certificates",
        #     "ServerCertificateMetadataList",
        #     "ServerCertificateMetadata",
        #     prefix="Iam",
        #     prop_prefix="server_certificate_",
        # ),
        # AwsResotoModel(
        #     "get-account-authorization-details",
        #     "GetAccountAuthorizationDetailsResult",
        #     "GetAccountAuthorizationDetailsResponse",
        #     prefix="Iam",
        #     prop_prefix="policy_",
        # ),
        # AwsResotoModel(
        #     "get-account-authorization-details",
        #     "GetAccountAuthorizationDetailsResult",
        #     "GetAccountAuthorizationDetailsResponse",
        #     prefix="Iam",
        #     prop_prefix="policy_",
        # ),
        # AwsResotoModel(
        #     "list-instance-profiles",
        #     "InstanceProfiles",
        #     "InstanceProfile",
        #     prefix="Iam",
        #     prop_prefix="instance_profile_",
        # ),
        # AwsResotoModel(
        #     "list-policies",
        #     "Policies",
        #     "Policy",
        #     prefix="Iam",
        #     prop_prefix="policy_",
        # ),
        # AwsResotoModel(
        #     "list-groups",
        #     "Groups",
        #     "Group",
        #     prefix="Iam",
        #     prop_prefix="group_",
        # ),
        # AwsResotoModel(
        #     "list-roles",
        #     "Roles",
        #     "Role",
        #     prefix="Iam",
        #     prop_prefix="role_",
        # ),
        # AwsResotoModel(
        #     "list-users",
        #     "Users",
        #     "User",
        #     prefix="Iam",
        #     prop_prefix="user_",
        # ),
        # AwsResotoModel(
        #     "list-access-keys",
        #     "AccessKeyMetadata",
        #     "AccessKeyMetadata",
        #     prefix="Iam",
        #     prop_prefix="access_key_",
        # ),
        # AwsResotoModel(
        #     "list-access-keys-last-user",
        #     "AccessKeyLastUsed",
        #     "AccessKeyLastUsed",
        #     prefix="Iam",
        #     prop_prefix="access_key_",
        # ),
    ],
    "pricing": [
        # AwsResotoModel("get-products", "PriceList", "PriceListItemJSON", prefix="Price", prop_prefix="price_")
    ],
    "redshift": [
        #     AwsResotoModel(
        #         "describe-clusters",
        #         "Clusters",
        #         "Cluster",
        #         prefix="Redshift",
        #         prop_prefix="redshift_",
        #     ),
    ],
    "rds": [
        # AwsResotoModel("describe-db-instances", "Instances", "DBInstance", prefix="Rds", prop_prefix="rds_")
    ],
    "route53": [
        # AwsResotoModel("list_hosted_zones", "HostedZones", "HostedZone", prefix="Route53", prop_prefix="zone_"),
        # AwsResotoModel(
        #     "list_resource_record_sets",
        #     "ResourceRecordSets",
        #     "ResourceRecordSet",
        #     prefix="Route53",
        #     prop_prefix="record_",
        # ),
    ],
    "s3": [
        # AwsResotoModel(#     "list-buckets", "Buckets", "Bucket", prefix="S3", prop_prefix="s3_"
        # )
    ],
    "service-quotas": [
        # AwsResotoModel("list-service-quotas", "Quotas", "ServiceQuota", prefix="Quota", prop_prefix="quota_")
    ],
    "sqs": [
        # AwsResotoModel(
        #     "get-queue-attributes", "Attributes", "GetQueueAttributesResult", prefix="Sqs", prop_prefix="sqs_"
        # )
    ],
}


if __name__ == "__main__":
    for model in all_models():
        print(model.to_class())
