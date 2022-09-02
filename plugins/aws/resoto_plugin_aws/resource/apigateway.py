from typing import ClassVar, Dict, Optional, List, Type, Union

from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2VpcEndpoint
from resoto_plugin_aws.resource.iam import AwsIamRole

# from resoto_plugin_aws.resource.lambda_ import AwsLambdaFunction
from resotolib.baseresources import EdgeType, ModelReference
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, Bend, bend
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
class AwsApiGatewayMethodResponse:
    kind: ClassVar[str] = "aws_api_gateway_method_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "status_code": S("statusCode"),
        "response_parameters": S("responseParameters"),
        "response_models": S("responseModels"),
    }
    status_code: Optional[str] = field(default=None)
    response_parameters: Optional[Dict[str, bool]] = field(default=None)
    response_models: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsApiGatewayIntegrationResponse:
    kind: ClassVar[str] = "aws_api_gateway_integration_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "status_code": S("statusCode"),
        "selection_pattern": S("selectionPattern"),
        "response_parameters": S("responseParameters"),
        "response_templates": S("responseTemplates"),
        "content_handling": S("contentHandling"),
    }
    status_code: Optional[str] = field(default=None)
    selection_pattern: Optional[str] = field(default=None)
    response_parameters: Optional[Dict[str, str]] = field(default=None)
    response_templates: Optional[Dict[str, str]] = field(default=None)
    content_handling: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsApiGatewayIntegration:
    kind: ClassVar[str] = "aws_api_gateway_integration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "integration_type": S("type"),
        "http_method": S("httpMethod"),
        "uri": S("uri"),
        "connection_type": S("connectionType"),
        "connection_id": S("connectionId"),
        "credentials": S("credentials"),
        "request_parameters": S("requestParameters"),
        "request_templates": S("requestTemplates"),
        "passthrough_behavior": S("passthroughBehavior"),
        "content_handling": S("contentHandling"),
        "timeout_in_millis": S("timeoutInMillis"),
        "cache_namespace": S("cacheNamespace"),
        "cache_key_parameters": S("cacheKeyParameters", default=[]),
        "integration_responses": S("integrationResponses"),
        "tls_config": S("tlsConfig", "insecureSkipVerification"),
    }
    integration_type: Optional[str] = field(default=None)
    http_method: Optional[str] = field(default=None)
    uri: Optional[str] = field(default=None)
    connection_type: Optional[str] = field(default=None)
    connection_id: Optional[str] = field(default=None)
    credentials: Optional[str] = field(default=None)
    request_parameters: Optional[Dict[str, str]] = field(default=None)
    request_templates: Optional[Dict[str, str]] = field(default=None)
    passthrough_behavior: Optional[str] = field(default=None)
    content_handling: Optional[str] = field(default=None)
    timeout_in_millis: Optional[int] = field(default=None)
    cache_namespace: Optional[str] = field(default=None)
    cache_key_parameters: List[str] = field(factory=list)
    integration_responses: Optional[Dict[str, AwsApiGatewayIntegrationResponse]] = field(default=None)
    tls_config: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsApiGatewayMethod:
    kind: ClassVar[str] = "aws_api_gateway_method"
    mapping: ClassVar[Dict[str, Bender]] = {
        "http_method": S("httpMethod"),
        "authorization_type": S("authorizationType"),
        "authorizer_id": S("authorizerId"),
        "api_key_required": S("apiKeyRequired"),
        "request_validator_id": S("requestValidatorId"),
        "operation_name": S("operationName"),
        "request_parameters": S("requestParameters"),
        "request_models": S("requestModels"),
        "method_responses": S("methodResponses"),
        "method_integration": S("methodIntegration") >> Bend(AwsApiGatewayIntegration.mapping),
        "authorization_scopes": S("authorizationScopes", default=[]),
    }
    http_method: Optional[str] = field(default=None)
    authorization_type: Optional[str] = field(default=None)
    authorizer_id: Optional[str] = field(default=None)
    api_key_required: Optional[bool] = field(default=None)
    request_validator_id: Optional[str] = field(default=None)
    operation_name: Optional[str] = field(default=None)
    request_parameters: Optional[Dict[str, bool]] = field(default=None)
    request_models: Optional[Dict[str, str]] = field(default=None)
    method_responses: Optional[Dict[str, AwsApiGatewayMethodResponse]] = field(default=None)
    method_integration: Optional[AwsApiGatewayIntegration] = field(default=None)
    authorization_scopes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsApiGatewayResource(AwsResource):
    kind: ClassVar[str] = "aws_api_gateway_resource"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("apigateway", "get-resources", "items")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "resource_parent_id": S("parentId"),
        "resource_path_part": S("pathPart"),
        "resource_path": S("path"),
        "resource_methods": S("resourceMethods"),
    }
    resource_parent_id: Optional[str] = field(default=None)
    resource_path_part: Optional[str] = field(default=None)
    resource_path: Optional[str] = field(default=None)
    resource_methods: Optional[Dict[str, AwsApiGatewayMethod]] = field(default=None)
    api_link: str = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.resource_methods:
            for method in self.resource_methods:
                builder.add_edge(
                    self,
                    edge_type=EdgeType.default,
                    clazz=AwsApiGatewayAuthorizer,
                    id=self.resource_methods[method].authorizer_id,
                )

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service="apigateway",
            action="delete-resource",
            result_name=None,
            restApiId=self.api_link,
            resourceId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsApiGatewayAuthorizer(AwsResource):
    kind: ClassVar[str] = "aws_api_gateway_authorizer"
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_iam_role"]}}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "authorizer_type": S("type"),
        "authorizer_provider_arns": S("providerARNs", default=[]),
        "authorizer_auth_type": S("authType"),
        "authorizer_uri": S("authorizerUri"),
        "authorizer_credentials": S("authorizerCredentials"),
        "authorizer_identity_source": S("identitySource"),
        "authorizer_identity_validation_expression": S("identityValidationExpression"),
        "authorizer_result_ttl_in_seconds": S("authorizerResultTtlInSeconds"),
    }
    authorizer_type: str = field(default=None)
    authorizer_provider_arns: List[Optional[str]] = field(default=None)
    authorizer_auth_type: Optional[str] = field(default=None)
    authorizer_uri: Optional[str] = field(default=None)
    authorizer_credentials: Optional[str] = field(default=None)
    authorizer_identity_source: Optional[str] = field(default=None)
    authorizer_identity_validation_expression: Optional[str] = field(default=None)
    authorizer_result_ttl_in_seconds: int = field(default=None)
    api_link: str = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # TODO add edge to Cognito User Pool when applicable (via self.authorizer_provider_arns)

        # the following edge to a lambda function would lead to circular import errors
        # if self.authorizer_uri:
        #     lambda_name = self.authorizer_uri.split(":")[-1].removesuffix("/invocations")
        #     builder.dependant_node(
        #         self,
        #         clazz=AwsLambdaFunction,
        #         name=lambda_name,
        #     )
        if self.authorizer_credentials:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AwsIamRole, arn=self.authorizer_credentials)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service="apigateway",
            action="delete-authorizer",
            result_name=None,
            restApiId=self.api_link,
            authorizerId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsApiGatewayCanarySetting:
    kind: ClassVar[str] = "aws_api_gateway_canary_setting"
    mapping: ClassVar[Dict[str, Bender]] = {
        "percent_traffic": S("percentTraffic"),
        "deployment_id": S("deploymentId"),
        "stage_variable_overrides": S("stageVariableOverrides"),
        "use_stage_cache": S("useStageCache"),
    }
    percent_traffic: int = field(default=None)
    deployment_id: str = field(default=None)
    stage_variable_overrides: Dict[str, str] = field(default=None)
    use_stage_cache: bool = field(default=None)


@define(eq=False, slots=False)
class AwsApiGatewayStage(ApiGatewayTaggable, AwsResource):
    kind: ClassVar[str] = "aws_api_gateway_stage"
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
    api_link: str = field(default=None)

    # TODO add edge to Web Acl when applicable (via stage_web_acl_arn)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service="apigateway",
            action="delete-stage",
            result_name=None,
            restApiId=self.api_link,
            stageName=self.name,
        )
        return True


@define(eq=False, slots=False)
class AwsApiGatewayDeployment(AwsResource):
    kind: ClassVar[str] = "aws_api_gateway_deployment"
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_api_gateway_stage"]}}

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "ctime": S("createdDate"),
        "description": S("description"),
        "deployment_api_summary": S("apiSummary"),
    }
    description: Optional[str] = field(default=None)
    deployment_api_summary: Dict[str, Dict[str, Dict[str, Union[str, bool]]]] = field(default=None)
    api_link: str = field(default=None)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service="apigateway",
            action="delete-deployment",
            result_name=None,
            restApiId=self.api_link,
            deploymentId=self.id,
        )
        return True


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
        "successors": {
            "default": [
                "aws_vpc_endpoint",
                "aws_api_gateway_deployment",
                "aws_api_gateway_authorizer",
                "aws_api_gateway_resource",
            ],
            "delete": ["aws_vpc_endpoint"],
        }
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
                deploy_instance.api_link = api_instance.id
                builder.add_node(deploy_instance, deployment)
                builder.add_edge(api_instance, EdgeType.default, node=deploy_instance)
                for stage in builder.client.list(
                    "apigateway", "get-stages", "item", restApiId=api_instance.id, deploymentId=deploy_instance.id
                ):
                    stage_instance = AwsApiGatewayStage.from_api(stage)
                    stage_instance.api_link = api_instance.id
                    builder.add_node(stage_instance, stage)
                    builder.add_edge(deploy_instance, EdgeType.default, node=stage_instance)
            for authorizer in builder.client.list("apigateway", "get-authorizers", "items", restApiId=api_instance.id):
                auth_instance = AwsApiGatewayAuthorizer.from_api(authorizer)
                auth_instance.api_link = api_instance.id
                builder.add_node(auth_instance, authorizer)
                builder.add_edge(api_instance, EdgeType.default, node=auth_instance)
            for resource in builder.client.list("apigateway", "get-resources", "items", restApiId=api_instance.id):
                resource_instance = AwsApiGatewayResource.from_api(resource)
                resource_instance.api_link = api_instance.id
                if resource_instance.resource_methods:
                    for method in resource_instance.resource_methods:
                        mapped = bend(AwsApiGatewayMethod.mapping, resource["resourceMethods"][method])
                        resource_instance.resource_methods[method] = from_json(mapped, AwsApiGatewayMethod)
                builder.add_node(resource_instance, resource)
                builder.add_edge(api_instance, EdgeType.default, node=resource_instance)

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


resources: List[Type[AwsResource]] = [
    AwsApiGatewayRestApi,
    AwsApiGatewayDeployment,
    AwsApiGatewayStage,
    AwsApiGatewayResource,
    AwsApiGatewayAuthorizer,
]
