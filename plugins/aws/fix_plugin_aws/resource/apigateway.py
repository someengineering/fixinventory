from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Union, Any

from attrs import define, field
from fix_plugin_aws.aws_client import AwsClient

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec, parse_json
from fix_plugin_aws.resource.ec2 import AwsEc2VpcEndpoint
from fix_plugin_aws.resource.iam import AwsIamRole
from fix_plugin_aws.resource.route53 import AwsRoute53Zone

from fixlib.baseresources import EdgeType, ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, bend
from fixlib.types import Json

service_name = "apigateway"


class ApiGatewayTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
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
                    aws_service=spec.service,
                    action="untag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tagKeys=[key],
                )
                return True
            return False
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource", override_iam_permission="apigateway:PATCH"),
            AwsApiSpec(service_name, "tag-resource", override_iam_permission="apigateway:POST"),
            AwsApiSpec(service_name, "tag-resource", override_iam_permission="apigateway:PUT"),
            AwsApiSpec(service_name, "untag-resource", override_iam_permission="apigateway:DELETE"),
        ]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsApiGatewayMethodResponse:
    kind: ClassVar[str] = "aws_apigateway_method_response"
    kind_display: ClassVar[str] = "AWS API Gateway Method Response"
    kind_description: ClassVar[str] = (
        "API Gateway Method Response allows users to define the response parameters"
        " and models for a particular method in the API Gateway service, which helps"
        " in shaping the output of API responses."
    )
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
    kind: ClassVar[str] = "aws_apigateway_integration_response"
    kind_display: ClassVar[str] = "AWS API Gateway Integration Response"
    kind_description: ClassVar[str] = (
        "API Gateway Integration Response is used to define the response structure"
        " and mapping for an API Gateway integration."
    )
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
    kind: ClassVar[str] = "aws_apigateway_integration"
    kind_display: ClassVar[str] = "AWS API Gateway Integration"
    kind_description: ClassVar[str] = (
        "API Gateway Integration is a feature provided by AWS API Gateway that allows"
        " users to connect their APIs to other AWS services or external HTTP"
        " endpoints."
    )
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
    kind: ClassVar[str] = "aws_apigateway_method"
    kind_display: ClassVar[str] = "AWS API Gateway Method"
    kind_description: ClassVar[str] = (
        "AWS API Gateway Method allows users to define the individual methods that"
        " are available in a REST API, including the HTTP method and the integration"
        " with backend services."
    )
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
    # collection of resource resources happens in AwsApiGatewayRestApi.collect()
    kind: ClassVar[str] = "aws_apigateway_resource"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": None, "arn_tpl": "arn:{partition}:apigateway:{region}:{account}:/restapis/{id}/{name}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS API Gateway Resource"
    kind_description: ClassVar[str] = (
        "API Gateway Resource is a logical unit used in API Gateway to represent a"
        " part of an API's resource hierarchy."
    )
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_apigateway_authorizer"]}}
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
    api_link: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.resource_methods:
            for method in self.resource_methods:
                builder.add_edge(
                    self,
                    edge_type=EdgeType.default,
                    clazz=AwsApiGatewayAuthorizer,
                    id=self.resource_methods[method].authorizer_id,
                )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-resource",
            result_name=None,
            restApiId=self.api_link,
            resourceId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "delete-resource", override_iam_permission="apigateway:DELETE")]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsApiGatewayAuthorizer(AwsResource):
    # collection of authorizer resources happens in AwsApiGatewayRestApi.collect()
    kind: ClassVar[str] = "aws_apigateway_authorizer"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/apigateway/main/apis/{api_link}/authorizers/{id}?api={api_link}&region={region}", "arn_tpl": "arn:{partition}:apigateway:{region}:{account}:authorizer/{name}/{id}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS API Gateway Authorizer"
    kind_description: ClassVar[str] = (
        "API Gateway Authorizers are mechanisms that help control access to APIs"
        " deployed on AWS API Gateway by authenticating and authorizing client"
        " requests."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_lambda_function"]},
        "predecessors": {"default": ["aws_iam_role"], "delete": ["aws_lambda_function", "aws_iam_role"]},
    }
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
    authorizer_type: Optional[str] = field(default=None)
    authorizer_provider_arns: List[Optional[str]] = field(default=None)
    authorizer_auth_type: Optional[str] = field(default=None)
    authorizer_uri: Optional[str] = field(default=None)
    authorizer_credentials: Optional[str] = field(default=None)
    authorizer_identity_source: Optional[str] = field(default=None)
    authorizer_identity_validation_expression: Optional[str] = field(default=None)
    authorizer_result_ttl_in_seconds: Optional[int] = field(default=None)
    api_link: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.authorizer_uri:
            lambda_name = self.authorizer_uri.split(":")[-1].removesuffix("/invocations")
            builder.dependant_node(
                self,
                kind="aws_lambda_function",
                name=lambda_name,
            )
        if self.authorizer_credentials:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=self.authorizer_credentials
            )
        for user_pool in self.authorizer_provider_arns:
            builder.add_edge(self, edge_type=EdgeType.default, kind="aws_cognito_user_pool", arn=user_pool)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-authorizer",
            result_name=None,
            restApiId=self.api_link,
            authorizerId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "delete-authorizer", override_iam_permission="apigateway:DELETE")]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsApiGatewayCanarySetting:
    kind: ClassVar[str] = "aws_apigateway_canary_setting"
    kind_display: ClassVar[str] = "AWS API Gateway Canary Setting"
    kind_description: ClassVar[str] = (
        "API Gateway Canary Setting is a feature in AWS API Gateway that allows you"
        " to test new deployments or changes to your APIs on a small percentage of"
        " your traffic before rolling them out to the entire API."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "percent_traffic": S("percentTraffic"),
        "deployment_id": S("deploymentId"),
        "stage_variable_overrides": S("stageVariableOverrides"),
        "use_stage_cache": S("useStageCache"),
    }
    percent_traffic: Optional[int] = field(default=None)
    deployment_id: Optional[str] = field(default=None)
    stage_variable_overrides: Optional[Dict[str, str]] = field(default=None)
    use_stage_cache: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsApiGatewayStage(ApiGatewayTaggable, AwsResource):
    # collection of stage resources happens in AwsApiGatewayRestApi.collect()
    kind: ClassVar[str] = "aws_apigateway_stage"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/apigateway/main/apis/{api_link}/stages?api={api_link}&region={region}", "arn_tpl": "arn:{partition}:apigateway:{region}:{account}:/restapis/{id}/stages/{name}"}  # fmt: skip

    kind_display: ClassVar[str] = "AWS API Gateway Stage"
    kind_description: ClassVar[str] = (
        "API Gateway Stages are environment configurations for deploying and managing"
        " APIs in the AWS API Gateway service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("syntheticId"),  # created by Fix to avoid collision with duplicate stage names
        "name": S("stageName"),
        "tags": S("tags", default={}),
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
    stage_cache_cluster_enabled: Optional[bool] = field(default=None)
    stage_cache_cluster_size: Optional[str] = field(default=None)
    stage_cache_status: Optional[str] = field(default=None)
    stage_method_settings: Optional[Dict[str, Dict[str, Union[bool, str, int]]]] = field(default=None)
    stage_variables: Optional[Dict[str, str]] = field(default=None)
    stage_documentation_version: Optional[str] = field(default=None)
    stage_access_log_settings: Optional[Dict[str, str]] = field(default=None)
    stage_canary_settings: Optional[AwsApiGatewayCanarySetting] = field(default=None)
    stage_tracing_enabled: Optional[bool] = field(default=None)
    stage_web_acl_arn: Optional[str] = field(default=None)
    api_link: Optional[str] = field(default=None)

    # TODO add edge to Web Acl when applicable (via stage_web_acl_arn)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-stage",
            result_name=None,
            restApiId=self.api_link,
            stageName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "delete-stage", override_iam_permission="apigateway:DELETE")
        ]


@define(eq=False, slots=False)
class AwsApiGatewayDeployment(AwsResource):
    # collection of deployment resources happens in AwsApiGatewayRestApi.collect()
    kind: ClassVar[str] = "aws_apigateway_deployment"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": None, "arn_tpl": "arn:{partition}:apigateway:{region}:{account}:/restapis/{id}/deployments/{name}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS API Gateway Deployment"
    kind_description: ClassVar[str] = (
        "API Gateway Deployments represents a deployment of an API to an API Gateway stage."
        " This allows the API to be invocable by end-users."
    )
    # edge to aws_apigateway_stage is established in AwsApiGatewayRestApi.collect()
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_apigateway_stage"]}}

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "ctime": S("createdDate"),
        "description": S("description"),
        "deployment_api_summary": S("apiSummary"),
    }
    description: Optional[str] = field(default=None)
    deployment_api_summary: Optional[Dict[str, Dict[str, Dict[str, Union[str, bool]]]]] = field(default=None)
    api_link: Optional[str] = field(default=None)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-deployment",
            result_name=None,
            restApiId=self.api_link,
            deploymentId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "delete-deployment", override_iam_permission="apigateway:DELETE")
        ]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsApiGatewayEndpointConfiguration:
    kind: ClassVar[str] = "aws_apigateway_endpoint_configuration"
    kind_display: ClassVar[str] = "AWS API Gateway Endpoint Configuration"
    kind_description: ClassVar[str] = (
        "API Gateway Endpoint Configuration is a configuration that defines the"
        " settings for an API Gateway endpoint, including the protocol, SSL"
        " certificate, and custom domain name."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "types": S("types", default=[]),
        "vpc_endpoint_ids": S("vpcEndpointIds", default=[]),
    }
    types: List[str] = field(factory=list)
    vpc_endpoint_ids: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsApiGatewayRestApi(ApiGatewayTaggable, AwsResource):
    kind: ClassVar[str] = "aws_apigateway_rest_api"
    kind_display: ClassVar[str] = "AWS API Gateway REST API"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/apigateway/main/apis/{id}/resources?api={id}&experience=rest&region={region}", "arn_tpl": "arn:{partition}:apigateway:{region}:{account}:restapi/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "API Gateway is a fully managed service that makes it easy for developers to"
        " create, publish, and manage APIs at any scale."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "get-rest-apis", "items", override_iam_permission="apigateway:GET"
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "aws_vpc_endpoint",
                "aws_apigateway_deployment",
                "aws_apigateway_authorizer",
                "aws_apigateway_resource",
            ],
            "delete": ["aws_vpc_endpoint"],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "name": S("name"),
        "tags": S("tags", default={}),
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
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "get-deployments", override_iam_permission="apigateway:GET"),
            AwsApiSpec(service_name, "get-stages", override_iam_permission="apigateway:GET"),
            AwsApiSpec(service_name, "get-authorizers", override_iam_permission="apigateway:GET"),
            AwsApiSpec(service_name, "get-resources", override_iam_permission="apigateway:GET"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "delete-rest-api", override_iam_permission="apigateway:DELETE")
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            if api_instance := cls.from_api(js, builder):
                api_instance.set_arn(
                    builder=builder,
                    account="",
                    resource=f"/restapis/{api_instance.id}",
                )
                builder.add_node(api_instance, js)
                for deployment in builder.client.list(
                    service_name, "get-deployments", "items", restApiId=api_instance.id
                ):
                    if deploy_instance := AwsApiGatewayDeployment.from_api(deployment, builder):
                        deploy_instance.set_arn(
                            builder=builder,
                            account="",
                            resource=f"/restapis/{api_instance.id}/deployments/{deploy_instance.id}",
                        )
                        deploy_instance.api_link = api_instance.id
                        builder.add_node(deploy_instance, deployment)
                        builder.add_edge(api_instance, EdgeType.default, node=deploy_instance)
                        for stage in builder.client.list(
                            service_name,
                            "get-stages",
                            "item",
                            restApiId=api_instance.id,
                            deploymentId=deploy_instance.id,
                        ):
                            stage["syntheticId"] = f'{api_instance.id}_{stage["stageName"]}'  # create unique id
                            if stage_instance := AwsApiGatewayStage.from_api(stage, builder):
                                stage_instance.api_link = api_instance.id
                                builder.add_node(stage_instance, stage)
                                # reference kinds for this edge are maintained in AwsApiGatewayDeployment.reference_kinds # noqa: E501
                                builder.add_edge(deploy_instance, EdgeType.default, node=stage_instance)
                for authorizer in builder.client.list(
                    service_name, "get-authorizers", "items", restApiId=api_instance.id
                ):
                    if auth_instance := AwsApiGatewayAuthorizer.from_api(authorizer, builder):
                        auth_instance.api_link = api_instance.id
                        builder.add_node(auth_instance, authorizer)
                        builder.add_edge(api_instance, EdgeType.default, node=auth_instance)
                for resource in builder.client.list(service_name, "get-resources", "items", restApiId=api_instance.id):
                    if resource_instance := AwsApiGatewayResource.from_api(resource, builder):
                        resource_instance.api_link = api_instance.id
                        if resource_instance.resource_methods:
                            for method in resource_instance.resource_methods:
                                mapped = bend(AwsApiGatewayMethod.mapping, resource["resourceMethods"][method])
                                if gm := parse_json(mapped, AwsApiGatewayMethod, builder):
                                    resource_instance.resource_methods[method] = gm
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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-rest-api",
            result_name=None,
            restApiId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsApiGatewayMutualTlsAuthentication:
    kind: ClassVar[str] = "aws_apigateway_mutual_tls_authentication"
    kind_display: ClassVar[str] = "AWS API Gateway Mutual TLS Authentication"
    kind_description: ClassVar[str] = (
        "API Gateway Mutual TLS Authentication enables mutual TLS authentication for"
        " secure communication between clients and API Gateway, providing an"
        " additional layer of security to protect the API endpoints."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "truststore_uri": S("truststoreUri"),
        "truststore_version": S("truststoreVersion"),
        "truststore_warnings": S("truststoreWarnings", default=[]),
    }
    truststore_uri: Optional[str] = field(default=None)
    truststore_version: Optional[str] = field(default=None)
    truststore_warnings: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsApiGatewayDomainName(ApiGatewayTaggable, AwsResource):
    kind: ClassVar[str] = "aws_apigateway_domain_name"
    kind_display: ClassVar[str] = "AWS API Gateway Domain Name"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/apigateway/main/publish/domain-names?api=unselected&domain={name}&&region={region}", "arn_tpl": "arn:aws:apigateway:{region}:{account}:domainname/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "API Gateway Domain Name is a custom domain name that you can associate with"
        " your API in Amazon API Gateway, allowing you to have a more branded and"
        " user-friendly endpoint for your API."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "get-domain-names", "items", override_iam_permission="apigateway:GET"
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_route53_zone"]},
        "successors": {"default": ["aws_route53_zone", "aws_vpc_endpoint"], "delete": ["aws_vpc_endpoint"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("domainName"),
        "tags": S("tags", default={}),
        "name": S("domainName"),
        "domain_certificate_name": S("certificateName"),
        "domain_certificate_arn": S("certificateArn"),
        "domain_certificate_upload_date": S("certificateUploadDate"),
        "domain_regional_domain_name": S("regionalDomainName"),
        "domain_regional_hosted_zone_id": S("regionalHostedZoneId"),
        "domain_regional_certificate_name": S("regionalCertificateName"),
        "domain_regional_certificate_arn": S("regionalCertificateArn"),
        "domain_distribution_domain_name": S("distributionDomainName"),
        "domain_distribution_hosted_zone_id": S("distributionHostedZoneId"),
        "domain_endpoint_configuration": S("endpointConfiguration") >> Bend(AwsApiGatewayEndpointConfiguration.mapping),
        "domain_domain_name_status": S("domainNameStatus"),
        "domain_domain_name_status_message": S("domainNameStatusMessage"),
        "domain_security_policy": S("securityPolicy"),
        "domain_mutual_tls_authentication": S("mutualTlsAuthentication")
        >> Bend(AwsApiGatewayMutualTlsAuthentication.mapping),
        "domain_ownership_verification_certificate_arn": S("ownershipVerificationCertificateArn"),
    }
    domain_certificate_name: Optional[str] = field(default=None)
    domain_certificate_arn: Optional[str] = field(default=None)
    domain_certificate_upload_date: Optional[datetime] = field(default=None)
    domain_regional_domain_name: Optional[str] = field(default=None)
    domain_regional_hosted_zone_id: Optional[str] = field(default=None)
    domain_regional_certificate_name: Optional[str] = field(default=None)
    domain_regional_certificate_arn: Optional[str] = field(default=None)
    domain_distribution_domain_name: Optional[str] = field(default=None)
    domain_distribution_hosted_zone_id: Optional[str] = field(default=None)
    domain_endpoint_configuration: Optional[AwsApiGatewayEndpointConfiguration] = field(default=None)
    domain_domain_name_status: Optional[str] = field(default=None)
    domain_domain_name_status_message: Optional[str] = field(default=None)
    domain_security_policy: Optional[str] = field(default=None)
    domain_mutual_tls_authentication: Optional[AwsApiGatewayMutualTlsAuthentication] = field(default=None)
    domain_ownership_verification_certificate_arn: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if zid := self.domain_regional_hosted_zone_id:
            builder.dependant_node(self, clazz=AwsRoute53Zone, delete_same_as_default=True, id=zid)
        if configuration := self.domain_endpoint_configuration:
            for endpoint in configuration.vpc_endpoint_ids:
                builder.dependant_node(
                    self,
                    clazz=AwsEc2VpcEndpoint,
                    delete_same_as_default=True,
                    id=endpoint,
                )
        # TODO add edge to ACM Certificates when applicable


resources: List[Type[AwsResource]] = [
    AwsApiGatewayRestApi,
    AwsApiGatewayDeployment,
    AwsApiGatewayStage,
    AwsApiGatewayResource,
    AwsApiGatewayAuthorizer,
    AwsApiGatewayDomainName,
]
