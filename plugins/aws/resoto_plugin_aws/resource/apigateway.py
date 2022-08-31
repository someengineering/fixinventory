from typing import ClassVar, Dict, Optional, List, Type, Union

from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2VpcEndpoint
from resotolib.baseresources import EdgeType, ModelReference
from resotolib.json_bender import Bender, S, Bend
from resoto_plugin_aws.utils import arn_partition
from resotolib.types import Json


class ApiGatewayTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    service=spec.service,
                    action="tag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tags={key: value},
                )
                return True
            return False
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    service=spec.service,
                    action="untag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tagKeys=[key],
                )
                return True
            return False
        return False


@define(eq=False, slots=False)
class AwsApiGatewayCanarySetting:
    kind: ClassVar[str] = "aws_api_gateway_canary_setting"
    mapping: ClassVar[Dict[str, Bender]] = {
        "percent_traffic": S("percentTraffic"),
        "deployment_id": S("deploymentId"),
        "stage_variable_overrides": S("stageVariableOverrides"),
        "use_stage_cache": S("useStageCache")
    }
    percent_traffic: int = field(default=None)
    deployment_id: str = field(default=None)
    stage_variable_overrides: Dict[str, str] = field(default=None)
    use_stage_cache: bool = field(default=None)

@define(eq=False, slots=False)
class AwsApiGatewayStage(ApiGatewayTaggable, AwsResource):
    kind: ClassVar[str] = "aws_api_gateway_stage"
    # reference_kinds: ClassVar[ModelReference] = {
    #     "successors": {"default": ["aws_vpc_endpoint"], "delete": ["aws_vpc_endpoint"]}
    # }

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("stageName"),
        "name": S("stageName"),
        "tags": S("tags", default=[]),
        "ctime": S("createdDate"),
        "mtime": S("lastUpdatedDate"),
        "description": S("description"),
        "stage_client_certificate_id": S("clientCertificateId"),
        "stage_cache_cluster_enabled": S("cacheClusterEnabled"),
        "stage_cache_cluster_size": S("cacheClusterSize"),
        "stage_cache_status": S("cacheClusterStatus"),
        "stage_method_settings": S("methodSettings"),
        "stage_variables": S("variables"),
        "stage_documentation_version": S("documentationVersion"),
        "stage_access_log_settings": S("accessLogSettings"),
        "stage_canary_settings": S("canarySettings") >> Bend(AwsApiGatewayCanarySetting.mapping),
        "stage_tracing_enabled": S("tracingEnabled"),
        "stage_web_acl_arn": S("webAclArn"),
    }
    description: Optional[str] = field(default=None)
    stage_client_certificate_id: Optional[str] = field(default=None)
    stage_cache_cluster_enabled: bool = field(default=None)
    stage_cache_cluster_size: Optional[str] = field(default=None)
    stage_cache_status: Optional[str] = field(default=None)
    stage_method_settings: Dict[str, Dict[str, Union[bool, str, int]]] = field(default=None)
    stage_variables: Dict[str, str] = field(default=None)
    stage_documentation_version: Optional[str] = field(default=None)
    stage_access_log_settings: Dict[str, str] = field(default=None)
    stage_canary_settings: Optional[AwsApiGatewayCanarySetting] = field(default=None)
    stage_tracing_enabled: bool = field(default=None)
    stage_web_acl_arn: Optional[str] = field(default=None)




@define(eq=False, slots=False)
class AwsApiGatewayDeployment(AwsResource):
    kind: ClassVar[str] = "aws_api_gateway_deployment"
    # reference_kinds: ClassVar[ModelReference] = {
    #     "successors": {"default": ["aws_vpc_endpoint"], "delete": ["aws_vpc_endpoint"]}
    # }

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        # "tags": S("tags", default=[]),
        "ctime": S("createdDate"),
        "description": S("description"),
        "deployment_api_summary": S("apiSummary"),
    }
    description: Optional[str] = field(default=None)
    deployment_api_summary: Dict[str, Dict[str, Dict[str, Union[str, bool]]]] = field(default=None)


@define(eq=False, slots=False)
class AwsApiGatewayEndpointConfiguration:
    kind: ClassVar[str] = "aws_api_gateway_endpoint_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "types": S("types", default=[]),
        "vpc_endpoint_ids": S("vpcEndpointIds", default=[]),
    }
    types: List[str] = field(factory=list)
    vpc_endpoint_ids: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsApiGatewayRestApi(ApiGatewayTaggable, AwsResource):
    kind: ClassVar[str] = "aws_api_gateway_rest_api"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("apigateway", "get-rest-apis", "items")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_vpc_endpoint"], "delete": ["aws_vpc_endpoint"]}
    }

    @classmethod
    def called_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec("apigateway", "get-deployments"),
            AwsApiSpec("apigateway", "get-stages"),
            AwsApiSpec("apigateway", "get-authorizers"),
            AwsApiSpec("apigateway", "get-resources"),
        ]

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "tags": S("tags", default=[]),
        "ctime": S("createdDate"),
        "description": S("description"),
        "api_version": S("version"),
        "api_warnings": S("warnings", default=[]),
        "api_binary_media_types": S("binaryMediaTypes", default=[]),
        "api_minimum_compression_size": S("minimumCompressionSize"),
        "api_key_source": S("apiKeySource"),
        "api_endpoint_configuration": S("endpointConfiguration") >> Bend(AwsApiGatewayEndpointConfiguration.mapping),
        "api_policy": S("policy"),
        "api_disable_execute_api_endpoint": S("disableExecuteApiEndpoint"),
    }
    description: Optional[str] = field(default=None)
    api_version: Optional[str] = field(default=None)
    api_warnings: List[str] = field(factory=list)
    api_binary_media_types: List[str] = field(factory=list)
    api_minimum_compression_size: Optional[int] = field(default=None)
    api_key_source: Optional[str] = field(default=None)
    api_endpoint_configuration: Optional[AwsApiGatewayEndpointConfiguration] = field(default=None)
    api_policy: Optional[str] = field(default=None)
    api_disable_execute_api_endpoint: Optional[bool] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            api_instance = cls.from_api(js)
            region = builder.region
            api_instance.arn = f"arn:{arn_partition(region)}:apigateway:{region.id}::/restapis/{api_instance.id}"
            builder.add_node(api_instance, js)
            for deployment in builder.client.list("apigateway", "get-deployments", "items", restApiId=api_instance.id):
                deploy_instance = AwsApiGatewayDeployment.from_api(deployment)
                deploy_instance.arn = api_instance.arn + "/deployments/" + deploy_instance.id
                builder.add_node(deploy_instance, deployment)
                builder.add_edge(api_instance, EdgeType.default, node=deploy_instance)
                for stage in builder.client.list("apigateway", "get-stages", "item", restApiId=api_instance.id, deploymentId=deploy_instance.id): #that ain't working
                    stage_instance = AwsApiGatewayStage.from_api(stage)
                    builder.add_node(stage_instance, stage)
                    builder.add_edge(deploy_instance, EdgeType.default, node=stage_instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.api_endpoint_configuration:
            for endpoint in self.api_endpoint_configuration.vpc_endpoint_ids:
                builder.dependant_node(
                    self,
                    clazz=AwsEc2VpcEndpoint,
                    delete_same_as_default=True,
                    id=endpoint,
                )

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service=self.api_spec.service,
            action="delete-rest-api",
            result_name=None,
            restApiId=self.id,
        )
        return True


resources: List[Type[AwsResource]] = [AwsApiGatewayRestApi]
