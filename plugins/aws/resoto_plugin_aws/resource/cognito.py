from attrs import define, field
from typing import ClassVar, Dict, List, Optional, Type
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.iam import AwsIamRole
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.resource.lambda_ import AwsLambdaFunction
from resotolib.baseresources import BaseUser, EdgeType, ModelReference
from resotolib.json_bender import S, Bend, Bender, ForallBend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsCognitoGroup(AwsResource):
    # collection of group resources happens in AwsCognitoUserPool.collect()
    kind: ClassVar[str] = "aws_cognito_group"
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_iam_role"], "delete": ["aws_iam_role"]}
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("GroupName"),
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
        return [AwsApiSpec("cognito-idp", "delete-group")]

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.role_arn:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=self.role_arn)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="cognito-idp", action="delete-group", result_name=None, GroupName=self.name, UserPoolId=self.id
        )
        return True


@define(eq=False, slots=False)
class AwsCognitoAttributeType:
    kind: ClassVar[str] = "aws_cognito_attribute_type"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "value": S("Value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCognitoMFAOptionType:
    kind: ClassVar[str] = "aws_cognito_mfa_option_type"
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


@define(eq=False, slots=False)
class AwsCognitoCustomSMSLambdaVersionConfigType:
    kind: ClassVar[str] = "aws_cognito_custom_sms_lambda_version_config_type"
    mapping: ClassVar[Dict[str, Bender]] = {"lambda_version": S("LambdaVersion"), "lambda_arn": S("LambdaArn")}
    lambda_version: str = field(default=None)
    lambda_arn: str = field(default=None)


@define(eq=False, slots=False)
class AwsCognitoCustomEmailLambdaVersionConfigType:
    kind: ClassVar[str] = "aws_cognito_custom_email_lambda_version_config_type"
    mapping: ClassVar[Dict[str, Bender]] = {"lambda_version": S("LambdaVersion"), "lambda_arn": S("LambdaArn")}
    lambda_version: str = field(default=None)
    lambda_arn: str = field(default=None)


@define(eq=False, slots=False)
class AwsCognitoLambdaConfigType:
    kind: ClassVar[str] = "aws_cognito_lambda_config_type"
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
    # this call requires the MaxResult parameter, 60 is the maximum valid input
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cognito-idp", "list-user-pools", "UserPools", {"MaxResults": 60})
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
            AwsApiSpec("cognito-idp", "list-tags-for-resource"),
            AwsApiSpec("cognito-idp", "list-users"),
            AwsApiSpec("cognito-idp", "list-groups"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("cognito-idp", "tag-resource"),
            AwsApiSpec("cognito-idp", "untag-resource"),
            AwsApiSpec("cognito-idp", "delete-user-pool"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(pool: AwsCognitoUserPool) -> None:
            tags = builder.client.get("cognito-idp", "list-tags-for-resource", "Tags", ResourceArn=pool.arn)
            if tags:
                pool.tags = tags

        for pool in json:
            pool_instance = cls.from_api(pool)
            pool_instance.set_arn(builder=builder, resource=f"userpool/{pool_instance.id}")
            builder.add_node(pool_instance, pool)
            builder.submit_work(add_tags, pool_instance)
            for user in builder.client.list("cognito-idp", "list-users", "Users", UserPoolId=pool_instance.id):
                user_instance = AwsCognitoUser.from_api(user)
                builder.add_node(user_instance, user)
                builder.add_edge(from_node=pool_instance, edge_type=EdgeType.default, node=user_instance)
            for group in builder.client.list("cognito-idp", "list-groups", "Groups", UserPoolId=pool_instance.id):
                group_instance = AwsCognitoGroup.from_api(group)
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
            aws_service="cognito-idp", action="tag-resource", result_name=None, ResourceArn=self.arn, Tags={key: value}
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service="cognito-idp", action="untag-resource", result_name=None, ResourceArn=self.arn, TagKeys=[key]
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="cognito-idp", action="delete-user-pool", result_name=None, UserPoolId=self.id)
        return True


resources: List[Type[AwsResource]] = [AwsCognitoUserPool, AwsCognitoUser, AwsCognitoGroup]
