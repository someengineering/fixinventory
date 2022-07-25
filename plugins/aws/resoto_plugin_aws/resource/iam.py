from datetime import datetime
from typing import ClassVar, Dict, Optional, Type, List, Any

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2IamInstanceProfile
from resoto_plugin_aws.utils import ToDict

from resotolib.baseresources import (  # noqa: F401
    BaseCertificate,
    BasePolicy,
    BaseGroup,
    BaseAccount,
    BaseAccessKey,
    BaseUser,
    BaseInstanceProfile,
    EdgeType,
    ModelReference,
)
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, Bend, AsDate, Sort, bend, ForallBend
from resotolib.types import Json
from resoto_plugin_aws.aws_client import AwsClient


def iam_update_tag(resource: AwsResource, client: AwsClient, action: str, key: str, value: str, **kwargs: Any) -> bool:
    if spec := resource.api_spec:
        client.call(
            service=spec.service,
            action=action,
            result_name=None,
            Tags=[{"Key": key, "Value": value}],
            **kwargs,
        )
        return True
    return False


def iam_delete_tag(resource: AwsResource, client: AwsClient, action: str, key: str, **kwargs: Any) -> bool:
    if spec := resource.api_spec:
        client.call(
            service=spec.service,
            action=action,
            result_name=None,
            TagKeys=[key],
            **kwargs,
        )
        return True
    return False


@define(eq=False, slots=False)
class AwsIamPolicyDetail:
    kind: ClassVar[str] = "aws_iam_policy_detail"
    mapping: ClassVar[Dict[str, Bender]] = {"policy_name": S("PolicyName"), "policy_document": S("PolicyDocument")}
    policy_name: Optional[str] = field(default=None)
    policy_document: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsIamAttachedPermissionsBoundary:
    kind: ClassVar[str] = "aws_iam_attached_permissions_boundary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "permissions_boundary_type": S("PermissionsBoundaryType"),
        "permissions_boundary_arn": S("PermissionsBoundaryArn"),
    }
    permissions_boundary_type: Optional[str] = field(default=None)
    permissions_boundary_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsIamRoleLastUsed:
    kind: ClassVar[str] = "aws_iam_role_last_used"
    mapping: ClassVar[Dict[str, Bender]] = {"last_used_date": S("LastUsedDate"), "region": S("Region")}
    last_used_date: Optional[datetime] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsIamRole(AwsResource):
    # Note: this resource is collected via AwsIamUser.collect.
    kind: ClassVar[str] = "aws_iam_role"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_iam_policy", "aws_iam_instance_profile"],
            "delete": ["aws_iam_policy", "aws_iam_instance_profile"],
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("RoleId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("RoleName"),
        "ctime": S("CreateDate"),
        "atime": (S("RoleLastUsed") >> Sort(S("LastUsedDate") >> AsDate()))[-1]["LastUsedDate"],
        "path": S("Path"),
        "arn": S("Arn"),
        "role_assume_role_policy_document": S("AssumeRolePolicyDocument"),
        "description": S("Description"),
        "role_max_session_duration": S("MaxSessionDuration"),
        "role_permissions_boundary": S("PermissionsBoundary") >> Bend(AwsIamAttachedPermissionsBoundary.mapping),
        "role_last_used": S("RoleLastUsed") >> Bend(AwsIamRoleLastUsed.mapping),
        "role_policies": S("RolePolicyList", default=[]) >> ForallBend(AwsIamPolicyDetail.mapping),
    }
    path: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    role_assume_role_policy_document: Optional[Any] = field(default=None)
    role_max_session_duration: Optional[int] = field(default=None)
    role_permissions_boundary: Optional[AwsIamAttachedPermissionsBoundary] = field(default=None)
    role_last_used: Optional[AwsIamRoleLastUsed] = field(default=None)
    role_policies: List[AwsIamPolicyDetail] = field(factory=list)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # connect to instance profiles for this role
        for profile in bend(S("InstanceProfileList", default=[]), source):
            builder.dependant_node(
                self, clazz=AwsEc2IamInstanceProfile, delete_same_as_default=True, arn=profile["Arn"]
            )
        # connect to attached policies for this role
        for profile in bend(S("AttachedManagedPolicies", default=[]), source):
            builder.dependant_node(self, clazz=AwsIamPolicy, delete_same_as_default=True, arn=profile["PolicyArn"])

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return iam_update_tag(
            resource=self,
            client=client,
            action="tag_role",
            key=key,
            value=value,
            RoleName=self.name,
        )

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(
            resource=self,
            client=client,
            action="untag_role",
            key=key,
            RoleName=self.name,
        )


@define(eq=False, slots=False)
class AwsIamServerCertificate(AwsResource, BaseCertificate):
    kind: ClassVar[str] = "aws_iam_server_certificate"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("iam", "list-server-certificates", "ServerCertificateMetadataList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ServerCertificateId"),
        "arn": S("Arn"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("ServerCertificateName"),
        "ctime": S("UploadDate"),
        "path": S("Path"),
        "expires": S("Expiration"),
    }
    path: Optional[str] = field(default=None)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return iam_update_tag(
            resource=self,
            client=client,
            action="tag_server_certificate",
            key=key,
            value=value,
            ServerCertificateName=self.name,
        )

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(
            resource=self,
            client=client,
            action="untag_server_certificate",
            key=key,
            ServerCertificateName=self.name,
        )


@define(eq=False, slots=False)
class AwsIamPolicy(AwsResource, BasePolicy):
    # Note: this resource is collected via AwsIamUser.collect.
    kind: ClassVar[str] = "aws_iam_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("PolicyId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("PolicyName"),
        "ctime": S("CreateDate"),
        "mtime": S("UpdateDate"),
        "arn": S("Arn"),
        "path": S("Path"),
        "policy_default_version_id": S("DefaultVersionId"),
        "policy_attachment_count": S("AttachmentCount"),
        "policy_permissions_boundary_usage_count": S("PermissionsBoundaryUsageCount"),
        "policy_is_attachable": S("IsAttachable"),
        "policy_description": S("Description"),
    }
    path: Optional[str] = field(default=None)
    policy_default_version_id: Optional[str] = field(default=None)
    policy_attachment_count: Optional[int] = field(default=None)
    policy_permissions_boundary_usage_count: Optional[int] = field(default=None)
    policy_is_attachable: Optional[bool] = field(default=None)
    policy_description: Optional[str] = field(default=None)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return iam_update_tag(
            resource=self,
            client=client,
            action="tag_policy",
            key=key,
            value=value,
            PolicyArn=self.arn,
        )

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(
            resource=self,
            client=client,
            action="untag_policy",
            key=key,
            PolicyArn=self.arn,
        )


@define(eq=False, slots=False)
class AwsIamGroup(AwsResource, BaseGroup):
    # Note: this resource is collected via AwsIamUser.collect.
    kind: ClassVar[str] = "aws_iam_group"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_iam_policy"], "delete": ["aws_iam_policy"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("GroupId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("GroupName"),
        "ctime": S("CreateDate"),
        "path": S("Path"),
        "arn": S("Arn"),
        "group_policies": S("GroupPolicyList", default=[]) >> ForallBend(AwsIamPolicyDetail.mapping),
    }
    path: Optional[str] = field(default=None)
    group_policies: List[AwsIamPolicyDetail] = field(factory=list)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for policy in bend(S("AttachedManagedPolicies", default=[]), source):
            builder.dependant_node(self, clazz=AwsIamPolicy, delete_same_as_default=True, arn=policy.get("PolicyArn"))


@define(eq=False, slots=False)
class AwsIamAccessKeyLastUsed:
    kind: ClassVar[str] = "aws_iam_access_key_last_used"
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_used_date": S("LastUsedDate"),
        "service_name": S("ServiceName"),
        "region": S("Region"),
    }
    last_used_date: Optional[datetime] = field(default=None)
    service_name: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)

    @staticmethod
    def from_api(js: Json) -> "AwsIamAccessKeyLastUsed":
        mapped = bend(AwsIamAccessKeyLastUsed.mapping, js)
        return from_json(mapped, AwsIamAccessKeyLastUsed)


@define(eq=False, slots=False)
class AwsIamAccessKey(AwsResource, BaseAccessKey):
    # Note: this resource is collected via AwsIamUser.collect.
    kind: ClassVar[str] = "aws_iam_access_key"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AccessKeyId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("UserName"),
        "ctime": S("CreateDate"),
        "access_key_status": S("Status"),
    }
    access_key_last_used: Optional[AwsIamAccessKeyLastUsed] = field(default=None)


@define(eq=False, slots=False)
class AwsIamUser(AwsResource, BaseUser):
    kind: ClassVar[str] = "aws_iam_user"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("iam", "get-account-authorization-details")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_iam_group"]},
        "successors": {"default": ["aws_iam_policy"], "delete": ["aws_iam_policy"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("UserId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("UserName"),
        "ctime": S("CreateDate"),
        "atime": S("PasswordLastUsed"),
        "path": S("Path"),
        "arn": S("Arn"),
        "user_policies": S("UserPolicyList", default=[]) >> ForallBend(AwsIamPolicyDetail.mapping),
        "user_permissions_boundary": S("PermissionsBoundary") >> Bend(AwsIamAttachedPermissionsBoundary.mapping),
    }
    path: Optional[str] = field(default=None)
    user_policies: List[AwsIamPolicyDetail] = field(factory=list)
    user_permissions_boundary: Optional[AwsIamAttachedPermissionsBoundary] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json_list: List[Json], builder: GraphBuilder) -> None:
        for json in json_list:
            for js in json.get("GroupDetailList", []):
                builder.add_node(AwsIamGroup.from_api(js), js)

            for js in json.get("RoleDetailList", []):
                builder.add_node(AwsIamRole.from_api(js), js)

            for js in json.get("Policies", []):
                builder.add_node(AwsIamPolicy.from_api(js), js)

            for js in json.get("UserDetailList", []):
                user = AwsIamUser.from_api(js)
                builder.add_node(user, js)
                # add all iam access keys for this user
                for ak in builder.client.list("iam", "list-access-keys", "AccessKeyMetadata", UserName=user.name):
                    key = AwsIamAccessKey.from_api(ak)
                    # get last used date for this key
                    if lu := builder.client.get(
                        "iam", "get-access-key-last-used", "AccessKeyLastUsed", AccessKeyId=key.id
                    ):
                        key.access_key_last_used = AwsIamAccessKeyLastUsed.from_api(lu)
                        key.atime = key.access_key_last_used.last_used_date if key.access_key_last_used else None
                    builder.add_node(key, ak)
                    builder.dependant_node(user, node=key)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for p in bend(S("AttachedManagedPolicies", default=[]), source):
            builder.dependant_node(self, clazz=AwsIamPolicy, delete_same_as_default=True, arn=p.get("PolicyArn"))

        for arn in bend(S("GroupList", default=[]), source):
            builder.add_edge(self, reverse=True, clazz=AwsIamGroup, arn=arn)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return iam_update_tag(resource=self, client=client, action="tag_user", key=key, value=value, UserName=self.name)

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(resource=self, client=client, action="untag_user", key=key, UserName=self.name)


@define(eq=False, slots=False)
class AwsIamInstanceProfile(AwsResource, BaseInstanceProfile):
    kind: ClassVar[str] = "aws_iam_instance_profile"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("iam", "list-instance-profiles", "InstanceProfiles")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("InstanceProfileId"),
        "name": S("InstanceProfileName"),
        "ctime": S("CreateDate"),
        "arn": S("Arn"),
        "instance_profile_path": S("Path"),
    }
    instance_profile_path: Optional[str] = field(default=None)


resources: List[Type[AwsResource]] = [
    AwsIamServerCertificate,
    AwsIamPolicy,
    AwsIamGroup,
    AwsIamRole,
    AwsIamUser,
    AwsIamInstanceProfile,
]
