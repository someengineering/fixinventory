import re
from dataclasses import dataclass
from typing import List, Set, Optional, Tuple, Union, Dict

import boto3
from botocore.model import ServiceModel, StringShape, ListShape, Shape, StructureShape, MapShape


@dataclass
class AWSProperty:
    name: str
    from_name: Union[str, List[str]]
    type: str
    description: str
    default: str
    is_array: bool = False
    is_complex: bool = False
    extractor: Optional[str] = None

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
            base += f", default=[])"
        elif self.is_complex:
            base += f") >> Bend({self.type}.mapping)"
        else:
            base += ")"

        return base


@dataclass
class AWSModel:
    name: str
    props: List[AWSProperty]
    aggregate_root: bool
    base_class: Optional[str] = None

    def to_class(self) -> str:
        bc = ", " + self.base_class if self.base_class else ""
        base = f"(AWSResource{bc}):" if self.aggregate_root else ":"
        kind = f'    kind: ClassVar[str] = "aws_{to_snake(self.name[3:])}"'
        mapping = "    mapping: ClassVar[Dict[str, Bender]] = {\n"
        mapping += ",\n".join(f"        {p.mapping()}" for p in self.props)
        mapping += "\n    }"
        props = "\n".join(f"    {p.name}: {p.type_string()} = field({p.default})" for p in self.props)
        return f"@dataclass\nclass {self.name}{base}\n{kind}\n{mapping}\n{props}\n"


@dataclass
class AWSResotoModel:
    api_action: str  # action to perform on the client
    result_property: str  # this property holds the resulting list
    result_shape: str  # the shape of the result according to the service specification
    name: Optional[str] = None  # name of the clazz - uses the shape name by default
    base: Optional[str] = None  # the base class to use, BaseResource otherwise
    prefix: Optional[str] = None  # prefix for the resources


def to_snake(name: str) -> str:
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub("__([A-Z])", r"_\1", name)
    name = re.sub("([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower()


def to_camel(name: str) -> str:
    return "".join(word.title() for word in name.split("_"))


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
    return boto3.client(name)._service_model


def clazz_model(
    model: ServiceModel,
    shape: Shape,
    visited: Set[str],
    prefix: Optional[str] = None,
    clazz_name: Optional[str] = None,
    base_class: Optional[str] = None,
    aggregate_root: bool = False,
) -> List[AWSModel]:
    def type_name(s: Shape) -> str:
        spl = simple_shape(s)
        return spl if spl else f"AWS{prefix}{s.name}"

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
    result: List[AWSModel] = []
    props = []
    prefix = prefix or ""
    if isinstance(shape, StructureShape):
        for name, prop_shape in shape.members.items():
            prop = to_snake(name)
            if prop in ignore_props:
                continue
            if simple := simple_shape(prop_shape):
                props.append(AWSProperty(prop, name, simple, prop_shape.documentation, "default=None"))
            elif isinstance(prop_shape, ListShape):
                inner = prop_shape.member
                if simple := simple_shape(inner):
                    props.append(
                        AWSProperty(prop, name, simple, prop_shape.documentation, "default_factory=list", is_array=True)
                    )
                elif simple_path := complex_simple_shape(inner):
                    prop_name, prop_type = simple_path
                    props.append(
                        AWSProperty(
                            prop,
                            [name, prop_name],
                            prop_type,
                            prop_shape.documentation,
                            "default_factory=list",
                            is_array=True,
                            extractor=f'S("{name}") >> ForallBend(S("{prop_name}"))',
                        )
                    )

                else:
                    result.extend(clazz_model(model, inner, visited, prefix))
                    props.append(
                        AWSProperty(
                            prop,
                            name,
                            type_name(inner),
                            prop_shape.documentation,
                            "default_factory=list",
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
                    AWSProperty(prop, name, f"Dict[{key_type}, {value_type}]", prop_shape.documentation, "default=None")
                )

            elif isinstance(prop_shape, StructureShape):
                result.extend(clazz_model(model, prop_shape, visited, prefix))
                props.append(
                    AWSProperty(
                        prop,
                        name,
                        type_name(prop_shape),
                        prop_shape.documentation,
                        "default=None",
                        is_complex=True,
                    )
                )
            else:
                print(prop_shape)

        clazz_name = clazz_name if clazz_name else type_name(shape)
        result.append(AWSModel(clazz_name, props, aggregate_root, base_class))
    return result


models: Dict[str, List[AWSResotoModel]] = {
    "accessanalyzer": [
        AWSResotoModel("list-analyzers", "analyzers", "AnalyzerSummary", prefix="AccessAnalyzer"),
    ],
    "acm": [
        AWSResotoModel("list-certificates", "CertificateSummaryList", "CertificateSummary", prefix="ACM"),
    ],
    "acm-pca": [
        AWSResotoModel(
            "list-certificate-authorities", "CertificateAuthorities", "CertificateAuthority", prefix="ACMPCA"
        ),
    ],
    "alexaforbusiness": [],  # TODO: implement
    "amp": [
        AWSResotoModel("list-workspaces", "workspaces", "WorkspaceSummary", prefix="Amp"),
    ],
    "amplify": [
        AWSResotoModel("list-apps", "apps", "App", prefix="Amplify"),
    ],
    "apigateway": [
        AWSResotoModel("get-vpc-links", "items", "VpcLink", prefix="ApiGateway"),
        AWSResotoModel("get-sdk-types", "items", "SdkType", prefix="ApiGateway"),
        AWSResotoModel("get-rest-apis", "items", "RestApi", prefix="ApiGateway"),
        AWSResotoModel("get-domain-names", "items", "DomainName", prefix="ApiGateway"),
        AWSResotoModel("get-client-certificates", "items", "ClientCertificate", prefix="ApiGateway"),
    ],
    "apigatewayv2": [
        AWSResotoModel("get-domain-names", "Items", "DomainName", prefix="ApiGatewayV2"),
        AWSResotoModel("get-apis", "Items", "Api", prefix="ApiGatewayV2"),
    ],
    "appconfig": [
        AWSResotoModel("list-applications", "Items", "Application", prefix="AppConfig"),
    ],
    "appflow": [
        AWSResotoModel("list-flows", "flows", "FlowDefinition", prefix="Appflow"),
        AWSResotoModel("list-connectors", "connectors", "ConnectorDetail", prefix="Appflow"),
    ],
    "appintegrations": [
        AWSResotoModel(
            "list-data-integrations", "DataIntegrations", "DataIntegrationSummary", prefix="AppIntegrations"
        ),
        AWSResotoModel("list-event-integrations", "EventIntegrations", "EventIntegration", prefix="AppIntegrations"),
    ],
    "application-insights": [
        AWSResotoModel("list-applications", "ApplicationInfoList", "ApplicationInfo", prefix="ApplicationInsights"),
        AWSResotoModel("list-problems", "ProblemList", "Problem", prefix="ApplicationInsights"),
    ],
    "applicationcostprofiler": [
        AWSResotoModel(
            "list-report-definitions", "reportDefinitions", "ReportDefinition", prefix="ApplicationCostProfiler"
        ),
    ],
    "appmesh": [
        AWSResotoModel("list-meshes", "meshes", "MeshRef", prefix="AppMesh"),
    ],
    "apprunner": [
        AWSResotoModel("list-services", "ServiceSummaryList", "ServiceSummary", prefix="AppRunner"),
        AWSResotoModel("list-vpc-connectors", "VpcConnectors", "VpcConnector", prefix="AppRunner"),
        AWSResotoModel("list-connections", "ConnectionSummaryList", "ConnectionSummary", prefix="AppRunner"),
        AWSResotoModel(
            "list-auto-scaling-configurations",
            "AutoScalingConfigurationSummaryList",
            "AutoScalingConfigurationSummary",
            prefix="AppRunner",
        ),
        AWSResotoModel(
            "list-observability-configurations ",
            "ObservabilityConfigurationSummaryList",
            "ObservabilityConfigurationSummary",
            prefix="AppRunner",
        ),
    ],
    "appstream": [
        AWSResotoModel("describe-fleets", "Fleets", "Fleet", prefix="AppStream"),
        AWSResotoModel("describe-stacks", "Stacks", "Stack", prefix="AppStream"),
        AWSResotoModel("describe-images", "Images", "Image", prefix="AppStream"),
    ],
    "appsync": [
        AWSResotoModel("list-graphql-apis", "graphqlApis", "GraphqlApi", prefix="AppSync"),
        AWSResotoModel("list-domain-names", "domainNameConfigs", "DomainNameConfig", prefix="AppSync"),
    ],
    "athena": [
        AWSResotoModel("list-data-catalogs", "DataCatalogsSummary", "DataCatalogSummary", prefix="Athena"),
    ],
    "autoscaling": [
        AWSResotoModel(
            "describe_auto_scaling_groups", "AutoScalingGroupName", "AutoScalingGroup", prefix="AutoScaling"
        ),
    ],
    "ec2": [
        AWSResotoModel("describe_instances", "Reservations", "Instance", base="BaseInstance", prefix="EC2"),
        AWSResotoModel("describe_addresses", "Addresses", "Address", prefix="EC2"),
        AWSResotoModel("describe_reserved_instances", "ReservedInstances", "ReservedInstances", prefix="EC2"),
    ],
    "route53": [
        AWSResotoModel("list_hosted_zones", "HostedZones", "HostedZone", prefix="Route53"),
    ],
}


def all_models() -> List[AWSModel]:
    visited: Set[str] = set()
    result: List[AWSModel] = []
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
                    prefix=ep.prefix,
                )
            )

    return result


if __name__ == "__main__":
    for model in all_models():
        print(model.to_class())
