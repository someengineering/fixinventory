from datetime import datetime
from typing import ClassVar, Dict, Optional, Type, List, Any

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2IamInstanceProfile
from resoto_plugin_aws.utils import ToDict

from resotolib.baseresources import (
    BaseCertificate,
    BasePolicy,
    BaseGroup,
    BaseAccessKey,
    BaseUser,
    BaseInstanceProfile,
    EdgeType,
    ModelReference,
)
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, Bend, AsDate, Sort, bend, ForallBend, F
from resotolib.types import Json
from resotolib.graph import Graph
from resoto_plugin_aws.aws_client import AwsClient


def iam_update_tag(resource: AwsResource, client: AwsClient, action: str, key: str, value: str, **kwargs: Any) -> bool:
    if spec := resource.api_spec:
        client.call(
            aws_service=spec.service,
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
            aws_service=spec.service,
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
    policy_document: Optional[Json] = field(default=None)


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
            action="tag-role",
            key=key,
            value=value,
            RoleName=self.name,
        )

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(
            resource=self,
            client=client,
            action="untag-role",
            key=key,
            RoleName=self.name,
        )

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:

        for successor in self.successors(graph, edge_type=EdgeType.delete):
            if isinstance(successor, AwsIamPolicy):
                log_msg = f"Detaching {successor.rtdname}"
                self.log(log_msg)
                client.call(
                    aws_service="iam",
                    action="detach-role-policy",
                    result_name=None,
                    PolicyArn=successor.arn,
                    RoleName=self.name,
                )

        for role_policy in self.role_policies:
            log_msg = f"Deleting inline policy {role_policy}"
            self.log(log_msg)
            client.call(
                aws_service="iam",
                action="delete-role-policy",
                result_name=None,
                PolicyName=role_policy.policy_name,
                RoleName=self.name,
            )

        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="iam", action="delete-role", result_name=None, RoleName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("iam", "tag-role"),
            AwsApiSpec("iam", "untag-role"),
            AwsApiSpec("iam", "detach-role-policy"),
            AwsApiSpec("iam", "delete-role-policy"),
            AwsApiSpec("iam", "delete-role"),
        ]


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
            action="tag-server-certificate",
            key=key,
            value=value,
            ServerCertificateName=self.name,
        )

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(
            resource=self,
            client=client,
            action="untag-server-certificate",
            key=key,
            ServerCertificateName=self.name,
        )

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-server-certificate",
            result_name=None,
            ServerCertificateName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("iam", "tag-server-certificate"),
            AwsApiSpec("iam", "untag-server-certificate"),
            AwsApiSpec("iam", "delete-server-certificate"),
        ]


@define(eq=False, slots=False)
class AwsIamPolicyVersion:
    kind: ClassVar[str] = "aws_iam_policy_version"
    mapping: ClassVar[Dict[str, Bender]] = {
        "document": S("Document"),
        "version_id": S("VersionId"),
        "is_default_version": S("IsDefaultVersion"),
        "create_date": S("CreateDate"),
    }
    document: Optional[Json] = field(default=None)
    version_id: Optional[str] = field(default=None)
    is_default_version: Optional[bool] = field(default=None)
    create_date: Optional[datetime] = field(default=None)


def default_policy_document(policy: Json) -> Optional[AwsIamPolicyVersion]:
    default_version = policy.get("DefaultVersionId")
    # select the default policy from the version list
    for p in policy.get("PolicyVersionList", []):
        if p.get("VersionId") == default_version:
            return bend(AwsIamPolicyVersion.mapping, p)  # type: ignore
    return None


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
        "policy_document": F(default_policy_document),
    }
    path: Optional[str] = field(default=None)
    policy_default_version_id: Optional[str] = field(default=None)
    policy_attachment_count: Optional[int] = field(default=None)
    policy_permissions_boundary_usage_count: Optional[int] = field(default=None)
    policy_is_attachable: Optional[bool] = field(default=None)
    policy_description: Optional[str] = field(default=None)
    policy_document: Optional[AwsIamPolicyVersion] = field(default=None)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return iam_update_tag(
            resource=self,
            client=client,
            action="tag-policy",
            key=key,
            value=value,
            PolicyArn=self.arn,
        )

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(
            resource=self,
            client=client,
            action="untag-policy",
            key=key,
            PolicyArn=self.arn,
        )

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="iam",
            action="delete-policy",
            result_name=None,
            PolicyArn=self.arn,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("iam", "tag-policy"),
            AwsApiSpec("iam", "untag-policy"),
            AwsApiSpec("iam", "delete-policy"),
        ]


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

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:

        for successor in self.successors(graph, edge_type=EdgeType.delete):
            if isinstance(successor, AwsIamPolicy):
                log_msg = f"Detaching {successor.rtdname}"
                self.log(log_msg)
                client.call(
                    aws_service="iam",
                    action="detach-group-policy",
                    result_name=None,
                    GroupName=self.name,
                    PolicyArn=successor.arn,
                )

        for group_policy in self.group_policies:
            log_msg = f"Deleting inline policy {group_policy}"
            self.log(log_msg)
            client.call(
                aws_service="iam",
                action="delete-group-policy",
                result_name=None,
                GroupName=self.name,
                PolicyName=group_policy,
            )

        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="iam",
            action="delete-group",
            result_name=None,
            GroupName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("iam", "detach-group-policy"),
            AwsApiSpec("iam", "delete-group-policy"),
            AwsApiSpec("iam", "delete-group"),
        ]


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
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec("iam", "list-access-keys"),
            AwsApiSpec("iam", "get-access-key-last-used"),
            AwsApiSpec("iam", "list-users"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json_list: List[Json], builder: GraphBuilder) -> None:
        name_password_last_used_map: Dict[str, str] = {}
        for user in builder.client.list("iam", "list-users", "Users"):
            if "PasswordLastUsed" in user and "UserId" in user:
                name_password_last_used_map[user["UserId"]] = user["PasswordLastUsed"]
        for json in json_list:
            for js in json.get("GroupDetailList", []):
                builder.add_node(AwsIamGroup.from_api(js), js)

            for js in json.get("RoleDetailList", []):
                builder.add_node(AwsIamRole.from_api(js), js)

            for js in json.get("Policies", []):
                builder.add_node(AwsIamPolicy.from_api(js), js)

            for js in json.get("UserDetailList", []):
                js["PasswordLastUsed"] = name_password_last_used_map.get(js["UserId"])
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
        return iam_update_tag(resource=self, client=client, action="tag-user", key=key, value=value, UserName=self.name)

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(resource=self, client=client, action="untag-user", key=key, UserName=self.name)

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        for successor in self.successors(graph, edge_type=EdgeType.delete):
            if isinstance(successor, AwsIamPolicy):
                log_msg = f"Detaching {successor.rtdname}"
                self.log(log_msg)
                client.call(
                    aws_service="iam",
                    action="detach-user-policy",
                    result_name=None,
                    UserName=self.name,
                    PolicyArn=successor.arn,
                )

        for user_policy in self.user_policies:
            log_msg = f"Deleting inline policy {user_policy}"
            self.log(log_msg)
            client.call(
                aws_service="iam",
                action="delete-user-policy",
                result_name=None,
                UserName=self.name,
                PolicyName=user_policy.policy_name,
            )

        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="iam", action="delete-user", result_name=None, UserName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("iam", "tag-user"),
            AwsApiSpec("iam", "untag-user"),
            AwsApiSpec("iam", "detach-user-policy"),
            AwsApiSpec("iam", "delete-user-policy"),
            AwsApiSpec("iam", "delete-user"),
        ]


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

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return iam_update_tag(
            resource=self,
            client=client,
            action="tag-instance-profile",
            key=key,
            value=value,
            InstanceProfileName=self.name,
        )

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return iam_delete_tag(
            resource=self, client=client, action="untag-instance-profile", key=key, InstanceProfileName=self.name
        )

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        for predecessor in self.predecessors(graph, edge_type=EdgeType.delete):
            if isinstance(predecessor, AwsIamRole):
                log_msg = f"Detaching {predecessor.rtdname}"
                self.log(log_msg)
                client.call(
                    aws_service="iam",
                    action="remove-role-from-instance-profile",
                    result_name=None,
                    RoleName=predecessor.name,
                    InstanceProfileName=self.name,
                )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="iam", action="delete-instance-profile", result_name=None, InstanceProfileName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("iam", "tag-instance-profile"),
            AwsApiSpec("iam", "untag-instance-profile"),
            AwsApiSpec("iam", "remove-role-from-instance-profile"),
            AwsApiSpec("iam", "delete-instance-profile"),
        ]


resources: List[Type[AwsResource]] = [
    AwsIamServerCertificate,
    AwsIamPolicy,
    AwsIamGroup,
    AwsIamRole,
    AwsIamUser,
    AwsIamInstanceProfile,
]
