from datetime import timedelta
import json as json_p
import logging
import re
from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.apigateway import AwsApiGatewayRestApi, AwsApiGatewayResource
from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec, parse_json
from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchMetricData,
    AwsCloudwatchQuery,
    calculate_min_max_avg,
    update_resource_metrics,
)
from fix_plugin_aws.resource.ec2 import AwsEc2Subnet, AwsEc2SecurityGroup, AwsEc2Vpc
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.utils import MetricNormalization
from fixlib.baseresources import (
    BaseServerlessFunction,
    MetricName,
    MetricUnit,
    ModelReference,
)
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend, F, bend
from fixlib.types import Json

log = logging.getLogger("fix.plugins.aws")

service_name = "lambda"


@define(eq=False, slots=False)
class AwsLambdaPolicyStatement:
    kind: ClassVar[str] = "aws_lambda_policy_statement"
    kind_display: ClassVar[str] = "AWS Lambda Policy Statement"
    kind_description: ClassVar[str] = (
        "Lambda Policy Statements are used to define permissions for AWS Lambda"
        " functions, specifying what actions can be performed and by whom."
    )
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
    principal: Optional[Any] = field(default=None)
    action: Optional[Any] = field(default=None)
    resource: Optional[Any] = field(default=None)
    condition: Optional[Any] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaPolicy:
    kind: ClassVar[str] = "aws_lambda_policy"
    kind_display: ClassVar[str] = "AWS Lambda Policy"
    kind_description: ClassVar[str] = (
        "AWS Lambda Policies are permissions policies that determine what actions a"
        " Lambda function can take and what resources it can access within the AWS"
        " environment."
    )
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
    kind_display: ClassVar[str] = "AWS Lambda Environment Error"
    kind_description: ClassVar[str] = (
        "An error occurring in the environment setup or configuration of an AWS Lambda function."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"error_code": S("ErrorCode"), "message": S("Message")}
    error_code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaEnvironment:
    kind: ClassVar[str] = "aws_lambda_environment"
    kind_display: ClassVar[str] = "AWS Lambda Environment Response"
    kind_description: ClassVar[str] = (
        "The AWS Lambda Environment Response provides information about the environment variables configured"
        " for a Lambda function, including their values and any errors associated with retrieving them."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "variables": S("Variables"),
        "error": S("Error") >> Bend(AwsLambdaEnvironmentError.mapping),
    }
    variables: Optional[Dict[str, str]] = field(default=None)
    error: Optional[AwsLambdaEnvironmentError] = field(default=None, metadata=dict(ignore_history=True))


@define(eq=False, slots=False)
class AwsLambdaLayer:
    kind: ClassVar[str] = "aws_lambda_layer"
    kind_display: ClassVar[str] = "AWS Lambda Layer"
    kind_description: ClassVar[str] = (
        "Lambda Layers are a distribution mechanism for libraries, custom runtimes,"
        " or other function dependencies used by Lambda functions."
    )
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
    kind_display: ClassVar[str] = "AWS Lambda File System Config"
    kind_description: ClassVar[str] = (
        "AWS Lambda File System Config allows you to configure file systems for your"
        " Lambda functions, enabling them to access and store data in a file system"
        " outside of the Lambda execution environment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "local_mount_source_arn": S("LocalMountsource_arn")}
    arn: Optional[str] = field(default=None)
    local_mount_source_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaImageConfig:
    kind: ClassVar[str] = "aws_lambda_image_config"
    kind_display: ClassVar[str] = "AWS Lambda Image Configuration"
    kind_description: ClassVar[str] = (
        "Lambda Image Configuration is a feature of AWS Lambda that allows you to"
        " build and deploy container images as Lambda function packages."
    )
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
    kind_display: ClassVar[str] = "AWS Lambda Image Config Error"
    kind_description: ClassVar[str] = (
        "AWS Lambda Image Config Error refers to an error that occurs when there is a"
        " configuration issue with an AWS Lambda function using container image. This"
        " error usually happens when there is an incorrect setup or mismatch in the"
        " configuration settings for the Lambda function's container image."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"error_code": S("ErrorCode"), "message": S("Message")}
    error_code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaImageConfigResponse:
    kind: ClassVar[str] = "aws_lambda_image_config_response"
    kind_display: ClassVar[str] = "AWS Lambda Image Configuration Response"
    kind_description: ClassVar[str] = (
        "The AWS Lambda Image Configuration Response provides information about the container image"
        " configuration for a Lambda function and any errors if the configuration failed to apply."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "image_config": S("ImageConfig") >> Bend(AwsLambdaImageConfig.mapping),
        "error": S("Error") >> Bend(AwsLambdaImageConfigError.mapping),
    }
    image_config: Optional[AwsLambdaImageConfig] = field(default=None)
    error: Optional[AwsLambdaImageConfigError] = field(default=None)


@define(eq=False, slots=False)
class AwsLambdaCors:
    kind: ClassVar[str] = "aws_lambda_cors"
    kind_display: ClassVar[str] = "AWS Lambda CORS"
    kind_description: ClassVar[str] = (
        "AWS Lambda CORS refers to the Cross-Origin Resource Sharing (CORS)"
        " configuration for AWS Lambda functions. CORS allows a server to indicate"
        " which origins have permissions to access its resources, helping to protect"
        " against cross-origin vulnerabilities."
    )
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
    kind_display: ClassVar[str] = "AWS Lambda Function URL Config"
    kind_description: ClassVar[str] = (
        "The AWS Lambda Function URL Config enables direct invocation of Lambda functions over"
        " the web using HTTP(S) endpoints, with customizable authentication and cross-origin access."
    )
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
    kind_display: ClassVar[str] = "AWS Lambda Function"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/lambda/home?region={region}#/functions/{FunctionName}", "arn_tpl": "arn:{partition}:lambda:{region}:{account}:function/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS Lambda is a serverless computing service that lets you run your code"
        " without provisioning or managing servers. Lambda functions are the compute"
        " units that run your code in response to events."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-functions", "Functions")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_vpc",
                "aws_ec2_subnet",
                "aws_ec2_security_group",
                "aws_apigateway_rest_api",
                "aws_apigateway_resource",
            ],
            "delete": ["aws_vpc", "aws_ec2_subnet", "aws_ec2_security_group", "aws_kms_key"],
        },
        "successors": {"default": ["aws_kms_key"], "delete": ["aws_apigateway_rest_api", "aws_apigateway_resource"]},
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
        "function_environment": S("Environment") >> Bend(AwsLambdaEnvironment.mapping),
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
    function_environment: Optional[AwsLambdaEnvironment] = field(default=None)
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
            AwsApiSpec(service_name, "get-function-url-config"),
            AwsApiSpec(service_name, "get-policy"),
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(function: AwsLambdaFunction) -> None:
            tags = builder.client.get(
                service_name, "list-tags", "Tags", Resource=function.arn, expected_errors=["ResourceNotFoundException"]
            )
            if tags:
                function.tags = tags

        def get_policy(function: AwsLambdaFunction) -> None:
            if policy := builder.client.get(
                service_name,
                "get-policy",
                expected_errors=["ResourceNotFoundException"],  # policy is optional
                FunctionName=function.name,
                result_name="Policy",
            ):
                # policy is defined as string, but it is actually a json object
                mapped = bend(AwsLambdaPolicy.mapping, json_p.loads(policy))  # type: ignore
                if policy_instance := parse_json(mapped, AwsLambdaPolicy, builder):
                    function.function_policy = policy_instance
                    for statement in policy_instance.statement or []:
                        if (
                            statement.principal
                            and statement.condition
                            and isinstance(statement.principal, dict)
                            and statement.principal.get("Service") == "apigateway.amazonaws.com"
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
                service_name,
                "get-function-url-config",
                result_name=None,
                expected_errors=["ResourceNotFoundException"],
                FunctionName=function.name,
            ):
                mapped = bend(AwsLambdaFunctionUrlConfig.mapping, config)
                url_config = parse_json(mapped, AwsLambdaFunctionUrlConfig, builder)
                function.function_url_config = url_config

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)
                builder.submit_work(service_name, get_policy, instance)
                builder.submit_work(service_name, get_url_config, instance)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        lambdas = {
            function.id: function
            for function in builder.nodes(clazz=AwsLambdaFunction)
            if function.region().id == builder.region.id
        }
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at
        period = min(timedelta(minutes=5), delta)

        for lambda_id, lambda_instance in lambdas.items():
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric_name,
                        namespace="AWS/Lambda",
                        period=period,
                        ref_id=lambda_id,
                        stat="Sum",
                        unit="Count",
                        FunctionName=lambda_instance.name or lambda_instance.safe_name,
                    )
                    for metric_name in ["Invocations", "Errors", "Throttles", "ConcurrentExecutions"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="Duration",
                        namespace="AWS/Lambda",
                        period=delta,
                        ref_id=lambda_id,
                        stat=stat,
                        unit="Milliseconds",
                        FunctionName=lambda_instance.name or lambda_instance.safe_name,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )

        metric_normalizers = {
            "Invocations": MetricNormalization(
                metric_name=MetricName.Invocations,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "Errors": MetricNormalization(
                metric_name=MetricName.Errors,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "Throttles": MetricNormalization(
                metric_name=MetricName.Throttles,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "Duration": MetricNormalization(
                metric_name=MetricName.Duration,
                unit=MetricUnit.Milliseconds,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ConcurrentExecutions": MetricNormalization(
                metric_name=MetricName.ConcurrentExecutions,
                unit=MetricUnit.Count,
                compute_stats=calculate_min_max_avg,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(lambdas, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vpc_config := source.get("VpcConfig"):
            if vpc_id := vpc_config.get("VpcId"):
                builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
            for subnet_id in vpc_config.get("SubnetIds", []):
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet_id
                )
            for security_group_id in vpc_config.get("SecurityGroupIds", []):
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group_id
                )
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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-function", result_name=None, FunctionName=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-function"),
        ]


resources: List[Type[AwsResource]] = [AwsLambdaFunction]
