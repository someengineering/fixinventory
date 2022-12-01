from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Union

from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2VpcEndpoint
from resoto_plugin_aws.resource.iam import AwsIamRole
from resoto_plugin_aws.resource.route53 import AwsRoute53Zone

from resotolib.baseresources import EdgeType, ModelReference
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, Bend, bend
from resotolib.types import Json


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
            AwsApiSpec("apigateway", "tag-resource", override_iam_permission="apigateway:PATCH"),
            AwsApiSpec("apigateway", "tag-resource", override_iam_permission="apigateway:POST"),
            AwsApiSpec("apigateway", "tag-resource", override_iam_permission="apigateway:PUT"),
            AwsApiSpec("apigateway", "untag-resource", override_iam_permission="apigateway:DELETE"),
        ]


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
    # collection of resource resources happens in AwsApiGatewayRestApi.collect()
    kind: ClassVar[str] = "aws_api_gateway_resource"
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_api_gateway_authorizer"]}}
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
            aws_service="apigateway",
            action="delete-resource",
            result_name=None,
            restApiId=self.api_link,
            resourceId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("apigateway", "delete-resource", override_iam_permission="apigateway:DELETE")]


@define(eq=False, slots=False)
class AwsApiGatewayAuthorizer(AwsResource):
    # collection of authorizer resources happens in AwsApiGatewayRestApi.collect()
    kind: ClassVar[str] = "aws_api_gateway_authorizer"
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="apigateway",
            action="delete-authorizer",
            result_name=None,
            restApiId=self.api_link,
            authorizerId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("apigateway", "delete-authorizer", override_iam_permission="apigateway:DELETE")]


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
    stage_variable_overrides: Optional[Dict[str, str]] = field(default=None)
    use_stage_cache: bool = field(default=None)


@define(eq=False, slots=False)
class AwsApiGatewayStage(ApiGatewayTaggable, AwsResource):
    # collection of stage resources happens in AwsApiGatewayRestApi.collect()
    kind: ClassVar[str] = "aws_api_gateway_stage"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("syntheticId"),  # created by Resoto to avoid collision with duplicate stage names
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
    stage_cache_cluster_enabled: bool = field(default=None)
    stage_cache_cluster_size: Optional[str] = field(default=None)
    stage_cache_status: Optional[str] = field(default=None)
    stage_method_settings: Optional[Dict[str, Dict[str, Union[bool, str, int]]]] = field(default=None)
    stage_variables: Optional[Dict[str, str]] = field(default=None)
    stage_documentation_version: Optional[str] = field(default=None)
    stage_access_log_settings: Optional[Dict[str, str]] = field(default=None)
    stage_canary_settings: Optional[AwsApiGatewayCanarySetting] = field(default=None)
    stage_tracing_enabled: bool = field(default=None)
    stage_web_acl_arn: Optional[str] = field(default=None)
    api_link: str = field(default=None)

    # TODO add edge to Web Acl when applicable (via stage_web_acl_arn)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="apigateway",
            action="delete-stage",
            result_name=None,
            restApiId=self.api_link,
            stageName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec("apigateway", "delete-stage", override_iam_permission="apigateway:DELETE")
        ]


@define(eq=False, slots=False)
class AwsApiGatewayDeployment(AwsResource):
    # collection of deployment resources happens in AwsApiGatewayRestApi.collect()
    kind: ClassVar[str] = "aws_api_gateway_deployment"
    # edge to aws_api_gateway_stage is established in AwsApiGatewayRestApi.collect()
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_api_gateway_stage"]}}

    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "ctime": S("createdDate"),
        "description": S("description"),
        "deployment_api_summary": S("apiSummary"),
    }
    description: Optional[str] = field(default=None)
    deployment_api_summary: Optional[Dict[str, Dict[str, Dict[str, Union[str, bool]]]]] = field(default=None)
    api_link: str = field(default=None)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="apigateway",
            action="delete-deployment",
            result_name=None,
            restApiId=self.api_link,
            deploymentId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec("apigateway", "delete-deployment", override_iam_permission="apigateway:DELETE")
        ]


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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "apigateway", "get-rest-apis", "items", override_iam_permission="apigateway:GET"
    )
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
            AwsApiSpec("apigateway", "get-deployments", override_iam_permission="apigateway:GET"),
            AwsApiSpec("apigateway", "get-stages", override_iam_permission="apigateway:GET"),
            AwsApiSpec("apigateway", "get-authorizers", override_iam_permission="apigateway:GET"),
            AwsApiSpec("apigateway", "get-resources", override_iam_permission="apigateway:GET"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec("apigateway", "delete-rest-api", override_iam_permission="apigateway:DELETE")
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            api_instance = cls.from_api(js)
            api_instance.set_arn(
                builder=builder,
                account="",
                resource=f"/restapis/{api_instance.id}",
            )
            builder.add_node(api_instance, js)
            for deployment in builder.client.list("apigateway", "get-deployments", "items", restApiId=api_instance.id):
                deploy_instance = AwsApiGatewayDeployment.from_api(deployment)
                deploy_instance.set_arn(
                    builder=builder,
                    account="",
                    resource=f"/restapis/{api_instance.id}/deployments/{deploy_instance.id}",
                )
                deploy_instance.api_link = api_instance.id
                builder.add_node(deploy_instance, deployment)
                builder.add_edge(api_instance, EdgeType.default, node=deploy_instance)
                for stage in builder.client.list(
                    "apigateway", "get-stages", "item", restApiId=api_instance.id, deploymentId=deploy_instance.id
                ):
                    stage["syntheticId"] = f'{api_instance.id}_{stage["stageName"]}'  # create unique id
                    stage_instance = AwsApiGatewayStage.from_api(stage)
                    stage_instance.api_link = api_instance.id
                    builder.add_node(stage_instance, stage)
                    # reference kinds for this edge are maintained in AwsApiGatewayDeployment.reference_kinds
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
            aws_service=self.api_spec.service,
            action="delete-rest-api",
            result_name=None,
            restApiId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsApiGatewayMutualTlsAuthentication:
    kind: ClassVar[str] = "aws_api_gateway_mutual_tls_authentication"
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
    kind: ClassVar[str] = "aws_api_gateway_domain_name"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "apigateway", "get-domain-names", "items", override_iam_permission="apigateway:GET"
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
    domain_endpoint_configuration: AwsApiGatewayEndpointConfiguration = field(default=None)
    domain_domain_name_status: Optional[str] = field(default=None)
    domain_domain_name_status_message: Optional[str] = field(default=None)
    domain_security_policy: Optional[str] = field(default=None)
    domain_mutual_tls_authentication: Optional[AwsApiGatewayMutualTlsAuthentication] = field(default=None)
    domain_ownership_verification_certificate_arn: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.domain_regional_hosted_zone_id:
            builder.dependant_node(
                self,
                clazz=AwsRoute53Zone,
                delete_same_as_default=True,
                id=self.domain_regional_hosted_zone_id,
            )
        for endpoint in self.domain_endpoint_configuration.vpc_endpoint_ids:
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
