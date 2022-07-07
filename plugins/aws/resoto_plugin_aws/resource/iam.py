from contextlib import suppress
from attrs import define, field
from datetime import datetime
from typing import ClassVar, Dict, Optional, Type, List, cast

from botocore.exceptions import ClientError

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.utils import TagsToDict

# noinspection PyUnresolvedReferences
from resotolib.baseresources import (  # noqa: F401
    BaseCertificate,
    BasePolicy,
    BaseGroup,
    BaseAccount,
    BaseAccessKey,
    BaseUser,
)
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, Bend, AsDate, Sort, bend
from resotolib.types import Json


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
    kind: ClassVar[str] = "aws_iam_role"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("iam", "list-roles", "Roles")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("RoleId"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
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
    }
    path: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    role_assume_role_policy_document: Optional[str] = field(default=None)
    role_max_session_duration: Optional[int] = field(default=None)
    role_permissions_boundary: Optional[AwsIamAttachedPermissionsBoundary] = field(default=None)
    role_last_used: Optional[AwsIamRoleLastUsed] = field(default=None)
    role_policies: List[str] = field(factory=list)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            instance = cast(AwsIamRole, cls.from_api(js))
            instance.role_policies = builder.client.list(
                "iam", "list-role-policies", "PolicyNames", RoleName=instance.name
            )
            builder.add_node(instance, js)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # connect to instance profiles for this role
        for profile in builder.client.list(
            "iam", "list-instance-profiles-for-role", "InstanceProfiles", RoleName=self.name
        ):
            builder.dependant_node(self, arn=profile["Arn"])
        # connect to attached policies for this role
        for profile in builder.client.list(
            "iam", "list-attached-role-policies", "AttachedPolicies", RoleName=self.name
        ):
            builder.dependant_node(self, arn=profile["PolicyArn"])


@define(eq=False, slots=False)
class AwsIamServerCertificate(AwsResource, BaseCertificate):
    kind: ClassVar[str] = "aws_iam_server_certificate"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("iam", "list-server-certificates", "ServerCertificateMetadataList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ServerCertificateId"),
        "arn": S("Arn"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
        "name": S("ServerCertificateName"),
        "ctime": S("UploadDate"),
        "path": S("Path"),
        "expires": S("Expiration"),
    }
    path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsIamPolicy(AwsResource, BasePolicy):
    kind: ClassVar[str] = "aws_iam_policy"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("iam", "list-policies", "Policies")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("PolicyId"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
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


@define(eq=False, slots=False)
class AwsIamGroup(AwsResource, BaseGroup):
    kind: ClassVar[str] = "aws_iam_group"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("iam", "list-groups", "Groups")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("GroupId"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
        "name": S("GroupName"),
        "ctime": S("CreateDate"),
        "path": S("Path"),
        "arn": S("Arn"),
    }
    path: Optional[str] = field(default=None)
    group_policies: Optional[List[str]] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            group = cast(AwsIamGroup, cls.from_api(js))
            group.group_policies = builder.client.list(
                "iam", "list-group-policies", "PolicyNames", GroupName=group.name
            )
            builder.add_node(group, js)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        with suppress(ClientError):  # group might not exist any longer
            for policy in builder.client.list(
                "iam", "list-attached-group-policies", "AttachedPolicies", GroupName=self.name
            ):
                builder.dependant_node(self, clazz=AwsIamPolicy, arn=policy.get("PolicyArn"))


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
    kind: ClassVar[str] = "aws_iam_access_key_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AccessKeyId"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
        "name": S("UserName"),
        "ctime": S("CreateDate"),
        "access_key_status": S("Status"),
    }
    access_key_last_used: Optional[AwsIamAccessKeyLastUsed] = field(default=None)


@define(eq=False, slots=False)
class AwsIamUser(AwsResource, BaseUser):
    kind: ClassVar[str] = "aws_iam_user"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("iam", "list-users", "Users")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("UserId"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
        "name": S("UserName"),
        "ctime": S("CreateDate"),
        "atime": S("PasswordLastUsed"),
        "path": S("Path"),
        "arn": S("Arn"),
        "user_permissions_boundary": S("PermissionsBoundary") >> Bend(AwsIamAttachedPermissionsBoundary.mapping),
    }
    path: Optional[str] = field(default=None)
    user_permissions_boundary: Optional[AwsIamAttachedPermissionsBoundary] = field(default=None)
    user_policies: List[str] = field(factory=list)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            user = cast(AwsIamUser, cls.from_api(js))
            user.user_policies = builder.client.list("iam", "list-user-policies", "PolicyNames", UserName=user.name)
            builder.add_node(user, js)
            # add all iam access keys for this user
            for ak in builder.client.list("iam", "list-access-keys", "AccessKeyMetadata", UserName=user.name):
                key = AwsIamAccessKey.from_api(ak)
                # get last used date for this key
                if lu := builder.client.get("iam", "get-access-key-last-used", "AccessKeyLastUsed", AccessKeyId=key.id):
                    key.access_key_last_used = AwsIamAccessKeyLastUsed.from_api(lu)
                    key.atime = key.access_key_last_used.last_used_date if key.access_key_last_used else None
                builder.add_node(key, ak)
                builder.dependant_node(user, node=key)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for p in builder.client.list("iam", "list-attached-user-policies", "AttachedPolicies", UserName=self.name):
            builder.dependant_node(self, clazz=AwsIamPolicy, arn=p.get("PolicyArn"))

        for g in builder.client.list("iam", "list-groups-for-user", "Groups", UserName=self.name):
            builder.dependant_node(self, clazz=AwsIamGroup, arn=g.get("Arn"))


resources: List[Type[AwsResource]] = [AwsIamServerCertificate, AwsIamPolicy, AwsIamGroup, AwsIamRole, AwsIamUser]
