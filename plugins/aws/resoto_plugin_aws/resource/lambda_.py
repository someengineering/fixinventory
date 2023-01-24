import json as json_p
import re
from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.apigateway import AwsApiGatewayRestApi, AwsApiGatewayResource
from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2Subnet, AwsEc2SecurityGroup, AwsEc2Vpc
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resotolib.baseresources import (
    BaseServerlessFunction,
    ModelReference,
)
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, Bend, ForallBend, F, bend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsLambdaPolicyStatement:
    kind: ClassVar[str] = "aws_lambda_policy_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "sid": S("Sid"),
        "effect": S("Effect"),
        "principal": S("Principal"),
        "action": S("Action"),
        "resource": S("Resource"),
        "condition": S("Condition"),
    }
    sid: Optional[str] = field(default=None)
    effect: Optional[str] = field(default=None)
    principal: Optional[Dict[str, str]] = field(default=None)
    action: Optional[str] = field(default=None)
    resource: Optional[str] = field(default=None)
    condition: Optional[Json] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaPolicy:
    kind: ClassVar[str] = "aws_lambda_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "version": S("Version"),
        "statement": S("Statement") >> ForallBend(AwsLambdaPolicyStatement.mapping),
    }
    id: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)
    statement: Optional[List[AwsLambdaPolicyStatement]] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaEnvironmentError:
    kind: ClassVar[str] = "aws_lambda_environment_error"
    mapping: ClassVar[Dict[str, Bender]] = {"error_code": S("ErrorCode"), "message": S("Message")}
    error_code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaEnvironmentResponse:
    kind: ClassVar[str] = "aws_lambda_environment_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "variables": S("Variables"),
        "error": S("Error") >> Bend(AwsLambdaEnvironmentError.mapping),
    }
    variables: Optional[Dict[str, str]] = field(default=None)
    error: Optional[AwsLambdaEnvironmentError] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaLayer:
    kind: ClassVar[str] = "aws_lambda_layer"
    mapping: ClassVar[Dict[str, Bender]] = {
        "arn": S("Arn"),
        "code_size": S("CodeSize"),
        "signing_profile_version_arn": S("SigningProfileVersionArn"),
        "signing_job_arn": S("SigningJobArn"),
    }
    arn: Optional[str] = field(default=None)
    code_size: Optional[int] = field(default=None)
    signing_profile_version_arn: Optional[str] = field(default=None)
    signing_job_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaFileSystemConfig:
    kind: ClassVar[str] = "aws_lambda_file_system_config"
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "local_mount_source_arn": S("LocalMountsource_arn")}
    arn: Optional[str] = field(default=None)
    local_mount_source_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaImageConfig:
    kind: ClassVar[str] = "aws_lambda_image_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "entry_point": S("EntryPoint", default=[]),
        "command": S("Command", default=[]),
        "working_directory": S("WorkingDirectory"),
    }
    entry_point: Optional[List[str]] = field(default=None)
    command: Optional[List[str]] = field(default=None)
    working_directory: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaImageConfigError:
    kind: ClassVar[str] = "aws_lambda_image_config_error"
    mapping: ClassVar[Dict[str, Bender]] = {"error_code": S("ErrorCode"), "message": S("Message")}
    error_code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaImageConfigResponse:
    kind: ClassVar[str] = "aws_lambda_image_config_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "image_config": S("ImageConfig") >> Bend(AwsLambdaImageConfig.mapping),
        "error": S("Error") >> Bend(AwsLambdaImageConfigError.mapping),
    }
    image_config: Optional[AwsLambdaImageConfig] = field(default=None)
    error: Optional[AwsLambdaImageConfigError] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaCors:
    kind: ClassVar[str] = "aws_lambda_cors"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_credentials": S("AllowCredentials"),
        "allow_headers": S("AllowHeaders", default=[]),
        "allow_methods": S("AllowMethods", default=[]),
        "allow_origins": S("AllowOrigins", default=[]),
        "expose_headers": S("ExposeHeaders", default=[]),
        "max_age": S("MaxAge"),
    }
    allow_credentials: Optional[bool] = field(default=None)
    allow_headers: List[str] = field(factory=list)
    allow_methods: List[str] = field(factory=list)
    allow_origins: List[str] = field(factory=list)
    expose_headers: List[str] = field(factory=list)
    max_age: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaFunctionUrlConfig:
    kind: ClassVar[str] = "aws_lambda_function_url_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "function_url": S("FunctionUrl"),
        "function_arn": S("FunctionArn"),
        "auth_type": S("AuthType"),
        "cors": S("Cors") >> Bend(AwsLambdaCors.mapping),
        "creation_time": S("CreationTime"),
        "last_modified_time": S("LastModifiedTime"),
    }
    function_url: Optional[str] = field(default=None)
    function_arn: Optional[str] = field(default=None)
    auth_type: Optional[str] = field(default=None)
    cors: Optional[AwsLambdaCors] = field(default=None)
    creation_time: Optional[str] = field(default=None)
    last_modified_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaFunction(AwsResource, BaseServerlessFunction):
    kind: ClassVar[str] = "aws_lambda_function"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("lambda", "list-functions", "Functions")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_vpc",
                "aws_ec2_subnet",
                "aws_ec2_security_group",
                "aws_api_gateway_rest_api",
                "aws_api_gateway_resource",
            ],
            "delete": ["aws_vpc", "aws_ec2_subnet", "aws_kms_key"],
        },
        "successors": {"default": ["aws_kms_key"], "delete": ["aws_api_gateway_rest_api", "aws_api_gateway_resource"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("FunctionName"),
        "name": S("FunctionName"),
        "mtime": S("LastModified") >> F(lambda x: re.sub(r"(\d\d)(\d\d)$", "\\1:\\2", x)),  # time zone is without colon
        "arn": S("FunctionArn"),
        "function_runtime": S("Runtime"),
        "function_role": S("Role"),
        "function_handler": S("Handler"),
        "function_code_size": S("CodeSize"),
        "function_description": S("Description"),
        "function_timeout": S("Timeout"),
        "function_memory_size": S("MemorySize"),
        "function_code_sha256": S("CodeSha256"),
        "function_version": S("Version"),
        "function_dead_letter_config": S("DeadLetterConfig", "TargetArn"),
        "function_environment": S("Environment") >> Bend(AwsLambdaEnvironmentResponse.mapping),
        "function_kms_key_arn": S("KMSKeyArn"),
        "function_tracing_config": S("TracingConfig", "Mode"),
        "function_master_arn": S("MasterArn"),
        "function_revision_id": S("RevisionId"),
        "function_layers": S("Layers", default=[]) >> ForallBend(AwsLambdaLayer.mapping),
        "function_state": S("State"),
        "function_state_reason": S("StateReason"),
        "function_state_reason_code": S("StateReasonCode"),
        "function_last_update_status": S("LastUpdateStatus"),
        "function_last_update_status_reason": S("LastUpdateStatusReason"),
        "function_last_update_status_reason_code": S("LastUpdateStatusReasonCode"),
        "function_file_system_configs": S("FileSystemConfigs", default=[])
        >> ForallBend(AwsLambdaFileSystemConfig.mapping),
        "function_package_type": S("PackageType"),
        "function_image_config_response": S("ImageConfigResponse") >> Bend(AwsLambdaImageConfigResponse.mapping),
        "function_signing_profile_version_arn": S("SigningProfileVersionArn"),
        "function_signing_job_arn": S("SigningJobArn"),
        "function_architectures": S("Architectures", default=[]),
        "function_ephemeral_storage": S("EphemeralStorage", "Size"),
    }
    function_runtime: Optional[str] = field(default=None)
    function_role: Optional[str] = field(default=None)
    function_handler: Optional[str] = field(default=None)
    function_code_size: Optional[int] = field(default=None)
    function_description: Optional[str] = field(default=None)
    function_timeout: Optional[int] = field(default=None)
    function_memory_size: Optional[int] = field(default=None)
    function_code_sha256: Optional[str] = field(default=None)
    function_version: Optional[str] = field(default=None)
    function_dead_letter_config: Optional[str] = field(default=None)
    function_environment: Optional[AwsLambdaEnvironmentResponse] = field(default=None)
    function_kms_key_arn: Optional[str] = field(default=None)
    function_tracing_config: Optional[str] = field(default=None)
    function_master_arn: Optional[str] = field(default=None)
    function_revision_id: Optional[str] = field(default=None)
    function_layers: List[AwsLambdaLayer] = field(factory=list)
    function_state: Optional[str] = field(default=None)
    function_state_reason: Optional[str] = field(default=None)
    function_state_reason_code: Optional[str] = field(default=None)
    function_last_update_status: Optional[str] = field(default=None)
    function_last_update_status_reason: Optional[str] = field(default=None)
    function_last_update_status_reason_code: Optional[str] = field(default=None)
    function_file_system_configs: List[AwsLambdaFileSystemConfig] = field(factory=list)
    function_package_type: Optional[str] = field(default=None)
    function_image_config_response: Optional[AwsLambdaImageConfigResponse] = field(default=None)
    function_signing_profile_version_arn: Optional[str] = field(default=None)
    function_signing_job_arn: Optional[str] = field(default=None)
    function_architectures: List[str] = field(factory=list)
    function_ephemeral_storage: Optional[int] = field(default=None)
    function_policy: Optional[AwsLambdaPolicy] = field(default=None)
    function_url_config: Optional[AwsLambdaFunctionUrlConfig] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec("lambda", "get-function-url-config"),
            AwsApiSpec("lambda", "get-policy"),
            AwsApiSpec("lambda", "list-tags"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(function: AwsLambdaFunction) -> None:
            tags = builder.client.get("lambda", "list-tags", "Tags", Resource=function.arn)
            if tags:
                function.tags = tags

        def get_policy(function: AwsLambdaFunction) -> None:
            if policy := builder.client.get(
                "lambda",
                "get-policy",
                expected_errors=["ResourceNotFoundException"],  # policy is optional
                FunctionName=function.name,
                result_name="Policy",
            ):
                # policy is defined as string, but it is actually a json object
                mapped = bend(AwsLambdaPolicy.mapping, json_p.loads(policy))  # type: ignore
                policy_instance = from_json(mapped, AwsLambdaPolicy)
                function.function_policy = policy_instance
                for statement in policy_instance.statement or []:
                    if (
                        statement.principal
                        and statement.condition
                        and statement.principal["Service"] == "apigateway.amazonaws.com"
                        and (arn_like := statement.condition.get("ArnLike")) is not None
                        and (source := arn_like.get("AWS:SourceArn")) is not None
                    ):
                        source_arn = source.rsplit(":")[-1]
                        rest_api_id = source_arn.split("/")[0]
                        builder.dependant_node(
                            function,
                            reverse=True,
                            clazz=AwsApiGatewayRestApi,
                            id=rest_api_id,
                        )
                        builder.dependant_node(
                            function,
                            reverse=True,
                            clazz=AwsApiGatewayResource,
                            api_link=rest_api_id,
                            resource_path="/" + source_arn.split("/")[-1],
                        )

        def get_url_config(function: AwsLambdaFunction) -> None:
            if config := builder.client.get(
                "lambda",
                "get-function-url-config",
                result_name=None,
                expected_errors=["ResourceNotFoundException"],
                FunctionName=function.name,
            ):
                mapped = bend(AwsLambdaFunctionUrlConfig.mapping, config)
                url_config = from_json(mapped, AwsLambdaFunctionUrlConfig)
                function.function_url_config = url_config

        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)
            builder.submit_work(add_tags, instance)
            builder.submit_work(get_policy, instance)
            builder.submit_work(get_url_config, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vpc_config := source.get("VpcConfig"):
            if vpc_id := vpc_config.get("VpcId"):
                builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
            for subnet_id in vpc_config.get("SubnetIds", []):
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet_id
                )
            for security_group_id in vpc_config.get("SecurityGroupIds", []):
                builder.add_edge(self, reverse=True, clazz=AwsEc2SecurityGroup, id=security_group_id)
        if self.function_kms_key_arn:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                arn=self.function_kms_key_arn,
            )

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="tag-resource",
            result_name=None,
            Resource=self.arn,
            Tags={key: value},
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="untag-resource",
            result_name=None,
            Resource=self.arn,
            TagKeys=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-function", result_name=None, FunctionName=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("lambda", "tag-resource"),
            AwsApiSpec("lambda", "untag-resource"),
            AwsApiSpec("lambda", "delete-function"),
        ]


resources: List[Type[AwsResource]] = [AwsLambdaFunction]
