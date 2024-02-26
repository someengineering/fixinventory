from attrs import define, field
from typing import ClassVar, Dict, List, Optional, Type, Tuple, Any
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.iam import AwsIamRole
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction
from fixlib.baseresources import BaseUser, EdgeType, ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import S, Bend, Bender, ForallBend, K
from fixlib.types import Json

service_name = "cognito-idp"


@define(eq=False, slots=False)
class AwsCognitoGroup(AwsResource):
    # collection of group resources happens in AwsCognitoUserPool.collect()
    kind: ClassVar[str] = "aws_cognito_group"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cognito/v2/idp/user-pools/{UserPoolId}/groups/details/{name}?region={region}", "arn_tpl": "arn:{partition}:cognito-idp:{region}:{account}:group/{id}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS Cognito Group"
    kind_description: ClassVar[str] = (
        "Cognito Groups are a way to manage and organize users in AWS Cognito, a"
        " fully managed service for user authentication, registration, and access"
        " control."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_iam_role"], "delete": ["aws_iam_role"]}
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("UserPoolId") + K(":") + S("GroupName"),
        "name": S("GroupName"),
        "ctime": S("CreationDate"),
        "mtime": S("LastModifiedDate"),
        "user_pool_id": S("UserPoolId"),
        "description": S("Description"),
        "role_arn": S("RoleArn"),
        "precedence": S("Precedence"),
    }
    user_pool_id: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    role_arn: Optional[str] = field(default=None)
    precedence: Optional[int] = field(default=None)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "delete-group")]

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.role_arn:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=self.role_arn)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name, action="delete-group", result_name=None, GroupName=self.name, UserPoolId=self.id
        )
        return True

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsCognitoAttributeType:
    kind: ClassVar[str] = "aws_cognito_attribute_type"
    kind_display: ClassVar[str] = "AWS Cognito Attribute Type"
    kind_description: ClassVar[str] = (
        "Cognito Attribute Type is used in AWS Cognito to define the type of user"
        " attribute, such as string, number, or boolean."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "value": S("Value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCognitoMFAOptionType:
    kind: ClassVar[str] = "aws_cognito_mfa_option_type"
    kind_display: ClassVar[str] = "AWS Cognito MFA Option Type"
    kind_description: ClassVar[str] = (
        "AWS Cognito MFA (Multi-Factor Authentication) Option Type refers to the methods of multi-factor"
        " authentication available in Amazon Cognito for user accounts."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "delivery_medium": S("DeliveryMedium"),
        "attribute_name": S("AttributeName"),
    }
    delivery_medium: Optional[str] = field(default=None)
    attribute_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCognitoUser(AwsResource, BaseUser):
    # collection of user resources happens in AwsCognitoUserPool.collect()
    kind: ClassVar[str] = "aws_cognito_user"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cognito/v2/idp/user-pools/{_pool_id}/users/details/{id}?region={region}", "arn_tpl": "arn:{partition}:cognito-idp:{region}:{account}:user/{id}"}  # fmt: skip

    kind_display: ClassVar[str] = "AWS Cognito User"
    kind_description: ClassVar[str] = (
        "AWS Cognito User represents a user account in the AWS Cognito service, which"
        " provides secure user authentication and authorization for web and mobile"
        " applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Username"),
        "name": S("Username"),
        "ctime": S("UserCreateDate"),
        "mtime": S("UserLastModifiedDate"),
        "user_attributes": S("Attributes", default=[]) >> ForallBend(AwsCognitoAttributeType.mapping),
        "enabled": S("Enabled"),
        "user_status": S("UserStatus"),
        "mfa_options": S("MFAOptions", default=[]) >> ForallBend(AwsCognitoMFAOptionType.mapping),
    }
    user_attributes: List[AwsCognitoAttributeType] = field(factory=list)
    enabled: Optional[bool] = field(default=None)
    user_status: Optional[str] = field(default=None)
    mfa_options: List[AwsCognitoMFAOptionType] = field(factory=list)
    pool_name: Optional[str] = None
    _pool_id: Optional[str] = None

    def _keys(self) -> Tuple[Any, ...]:
        # in case different user pools include the same user: we add the pool name to the keys
        if self.pool_name is not None:
            return tuple(list(super()._keys()) + [self.pool_name])
        return super()._keys()

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsCognitoCustomSMSLambdaVersionConfigType:
    kind: ClassVar[str] = "aws_cognito_custom_sms_lambda_version_config_type"
    kind_display: ClassVar[str] = "AWS Cognito Custom SMS Lambda Version Config Type"
    kind_description: ClassVar[str] = (
        "AWS Cognito Custom SMS Lambda Version Config Type defines the configuration"
        " for a custom SMS Lambda version in AWS Cognito, allowing users to customize"
        " the behavior of SMS messages sent during user authentication."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"lambda_version": S("LambdaVersion"), "lambda_arn": S("LambdaArn")}
    lambda_version: Optional[str] = field(default=None)
    lambda_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCognitoCustomEmailLambdaVersionConfigType:
    kind: ClassVar[str] = "aws_cognito_custom_email_lambda_version_config_type"
    kind_display: ClassVar[str] = "AWS Cognito Custom Email Lambda Version Config Type"
    kind_description: ClassVar[str] = (
        "This resource represents the configuration type for a custom email lambda"
        " version in AWS Cognito. It allows you to customize the email delivery"
        " process for user verification and notification emails in Cognito."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"lambda_version": S("LambdaVersion"), "lambda_arn": S("LambdaArn")}
    lambda_version: Optional[str] = field(default=None)
    lambda_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCognitoLambdaConfigType:
    kind: ClassVar[str] = "aws_cognito_lambda_config_type"
    kind_display: ClassVar[str] = "AWS Cognito Lambda Config Type"
    kind_description: ClassVar[str] = (
        "The AWS Cognito Lambda Config Type refers to the configuration for Lambda"
        " functions used with AWS Cognito, which allows developers to customize user"
        " sign-in and sign-up experiences in their applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "pre_sign_up": S("PreSignUp"),
        "custom_message": S("CustomMessage"),
        "post_confirmation": S("PostConfirmation"),
        "pre_authentication": S("PreAuthentication"),
        "post_authentication": S("PostAuthentication"),
        "define_auth_challenge": S("DefineAuthChallenge"),
        "create_auth_challenge": S("CreateAuthChallenge"),
        "verify_auth_challenge_response": S("VerifyAuthChallengeResponse"),
        "pre_token_generation": S("PreTokenGeneration"),
        "user_migration": S("UserMigration"),
        "custom_sms_sender": S("CustomSMSSender") >> Bend(AwsCognitoCustomSMSLambdaVersionConfigType.mapping),
        "custom_email_sender": S("CustomEmailSender") >> Bend(AwsCognitoCustomEmailLambdaVersionConfigType.mapping),
        "kms_key_id": S("KMSKeyID"),
    }
    pre_sign_up: Optional[str] = field(default=None)
    custom_message: Optional[str] = field(default=None)
    post_confirmation: Optional[str] = field(default=None)
    pre_authentication: Optional[str] = field(default=None)
    post_authentication: Optional[str] = field(default=None)
    define_auth_challenge: Optional[str] = field(default=None)
    create_auth_challenge: Optional[str] = field(default=None)
    verify_auth_challenge_response: Optional[str] = field(default=None)
    pre_token_generation: Optional[str] = field(default=None)
    user_migration: Optional[str] = field(default=None)
    custom_sms_sender: Optional[AwsCognitoCustomSMSLambdaVersionConfigType] = field(default=None)
    custom_email_sender: Optional[AwsCognitoCustomEmailLambdaVersionConfigType] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCognitoUserPool(AwsResource):
    kind: ClassVar[str] = "aws_cognito_user_pool"
    kind_display: ClassVar[str] = "AWS Cognito User Pool"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cognito/v2/idp/user-pools/{id}/users?region={region}", "arn_tpl": "arn:{partition}:cognito-idp:{region}:{account}:userpool/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An AWS Cognito User Pool is a managed user directory that enables user"
        " registration, authentication, and access control for your web and mobile"
        " apps."
    )
    # this call requires the MaxResult parameter, 60 is the maximum valid input
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-user-pools", "UserPools", {"MaxResults": 60})
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_cognito_user", "aws_cognito_group", "aws_lambda_function", "aws_kms_key"]},
        "predecessors": {"delete": ["aws_lambda_function", "aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "name": S("Name"),
        "lambda_config": S("LambdaConfig") >> Bend(AwsCognitoLambdaConfigType.mapping),
        "status": S("Status"),
        "mtime": S("LastModifiedDate"),
        "ctime": S("CreationDate"),
    }
    lambda_config: Optional[AwsCognitoLambdaConfigType] = field(default=None)
    status: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-tags-for-resource"),
            AwsApiSpec(service_name, "list-users"),
            AwsApiSpec(service_name, "list-groups"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-user-pool"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(pool: AwsCognitoUserPool) -> None:
            tags = builder.client.get(service_name, "list-tags-for-resource", "Tags", ResourceArn=pool.arn)
            if tags:
                pool.tags = tags

        for pool in json:
            if pool_instance := cls.from_api(pool, builder):
                pool_instance.set_arn(builder=builder, resource=f"userpool/{pool_instance.id}")
                builder.add_node(pool_instance, pool)
                builder.submit_work(service_name, add_tags, pool_instance)
                for user in builder.client.list(service_name, "list-users", "Users", UserPoolId=pool_instance.id):
                    if user_instance := AwsCognitoUser.from_api(user, builder):
                        user_instance.pool_name = pool_instance.name
                        user_instance._pool_id = pool_instance.id
                        builder.add_node(user_instance, user)
                        builder.add_edge(from_node=pool_instance, edge_type=EdgeType.default, node=user_instance)
                for group in builder.client.list(service_name, "list-groups", "Groups", UserPoolId=pool_instance.id):
                    if group_instance := AwsCognitoGroup.from_api(group, builder):
                        builder.add_node(group_instance, group)
                        builder.add_edge(from_node=pool_instance, edge_type=EdgeType.default, node=group_instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.lambda_config:
            if self.lambda_config.custom_sms_sender:
                builder.dependant_node(
                    self,
                    clazz=AwsLambdaFunction,
                    arn=self.lambda_config.custom_sms_sender.lambda_arn,
                )
            if self.lambda_config.custom_email_sender:
                builder.dependant_node(
                    self,
                    clazz=AwsLambdaFunction,
                    arn=self.lambda_config.custom_email_sender.lambda_arn,
                )
            if self.lambda_config.kms_key_id:
                builder.dependant_node(
                    self,
                    clazz=AwsKmsKey,
                    id=AwsKmsKey.normalise_id(self.lambda_config.kms_key_id),
                )

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name, action="tag-resource", result_name=None, ResourceArn=self.arn, Tags={key: value}
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=service_name, action="untag-resource", result_name=None, ResourceArn=self.arn, TagKeys=[key]
        )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="delete-user-pool", result_name=None, UserPoolId=self.id)
        return True


resources: List[Type[AwsResource]] = [AwsCognitoUserPool, AwsCognitoUser, AwsCognitoGroup]
