import csv
import time
from datetime import datetime, timedelta
from typing import ClassVar, Dict, Optional, Type, List, Any, Callable

from attrs import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec, parse_json
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import (
    BaseCertificate,
    BasePolicy,
    BaseGroup,
    BaseAccessKey,
    BaseUser,
    BaseInstanceProfile,
    EdgeType,
    ModelReference,
)
from fixlib.graph import Graph
from fixlib.json import value_in_path
from fixlib.json_bender import Bender, S, Bend, AsDate, Sort, bend, ForallBend, F, Sorted
from fixlib.types import Json
from fixlib.utils import parse_utc, utc

service_name = "iam"


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
    kind_display: ClassVar[str] = "AWS IAM Policy Detail"
    kind_description: ClassVar[str] = (
        "IAM Policy Detail provides information about the permissions and access"
        " control settings defined in an IAM policy."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "policy_name": S("PolicyName"),
        "policy_document": S("PolicyDocument") >> Sorted(sort_list=True),
    }
    policy_name: Optional[str] = field(default=None)
    policy_document: Optional[Json] = field(default=None)


@define(eq=False, slots=False)
class AwsIamAttachedPermissionsBoundary:
    kind: ClassVar[str] = "aws_iam_attached_permissions_boundary"
    kind_display: ClassVar[str] = "AWS IAM Attached Permissions Boundary"
    kind_description: ClassVar[str] = (
        "IAM Attached Permissions Boundary is a feature in AWS Identity and Access"
        " Management (IAM) that allows you to set a permissions boundary for an IAM"
        " entity (user or role), limiting the maximum permissions that the entity can"
        " have. This helps to enforce least privilege access for IAM entities within"
        " AWS."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "permissions_boundary_type": S("PermissionsBoundaryType"),
        "permissions_boundary_arn": S("PermissionsBoundaryArn"),
    }
    permissions_boundary_type: Optional[str] = field(default=None)
    permissions_boundary_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsIamRoleLastUsed:
    kind: ClassVar[str] = "aws_iam_role_last_used"
    kind_display: ClassVar[str] = "AWS IAM Role Last Used"
    kind_description: ClassVar[str] = (
        "IAM Role Last Used is a feature in AWS Identity and Access Management (IAM)"
        " that provides information on when an IAM role was last used to access"
        " resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"last_used": S("LastUsedDate"), "region": S("Region")}
    last_used: Optional[datetime] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsIamRole(AwsResource):
    # Note: this resource is collected via AwsIamUser.collect.
    kind: ClassVar[str] = "aws_iam_role"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/iam/home?region={region}#/roles/details/{RoleName}", "arn_tpl": "arn:{partition}:iam:{region}:{account}:role/{name}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS IAM Role"
    kind_description: ClassVar[str] = (
        "IAM Roles are a way to delegate permissions to entities that you trust. IAM"
        " roles are similar to users, in that they are both AWS identity types."
        " However, instead of being uniquely associated with one person, IAM roles are"
        " intended to be assumable by anyone who needs it."
    )
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
        "role_assume_role_policy_document": S("AssumeRolePolicyDocument") >> Sorted(sort_list=True),
        "description": S("Description"),
        "role_max_session_duration": S("MaxSessionDuration"),
        "role_permissions_boundary": S("PermissionsBoundary") >> Bend(AwsIamAttachedPermissionsBoundary.mapping),
        "role_last_used": S("RoleLastUsed") >> Bend(AwsIamRoleLastUsed.mapping),
        "role_policies": S("RolePolicyList", default=[]) >> ForallBend(AwsIamPolicyDetail.mapping),
    }
    path: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    role_assume_role_policy_document: Optional[Json] = field(default=None)
    role_max_session_duration: Optional[int] = field(default=None)
    role_permissions_boundary: Optional[AwsIamAttachedPermissionsBoundary] = field(default=None)
    role_last_used: Optional[AwsIamRoleLastUsed] = field(default=None, metadata=dict(ignore_history=True))
    role_policies: List[AwsIamPolicyDetail] = field(factory=list)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # connect to instance profiles for this role
        for profile in bend(S("InstanceProfileList", default=[]), source):
            builder.dependant_node(self, clazz=AwsIamInstanceProfile, delete_same_as_default=True, arn=profile["Arn"])
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
                    aws_service=service_name,
                    action="detach-role-policy",
                    result_name=None,
                    PolicyArn=successor.arn,
                    RoleName=self.name,
                )

        for role_policy in self.role_policies:
            log_msg = f"Deleting inline policy {role_policy}"
            self.log(log_msg)
            client.call(
                aws_service=service_name,
                action="delete-role-policy",
                result_name=None,
                PolicyName=role_policy.policy_name,
                RoleName=self.name,
            )

        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="delete-role", result_name=None, RoleName=self.name)
        return True

    @classmethod
    def service_name(cls) -> str:
        return service_name

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-role"),
            AwsApiSpec(service_name, "untag-role"),
            AwsApiSpec(service_name, "detach-role-policy"),
            AwsApiSpec(service_name, "delete-role-policy"),
            AwsApiSpec(service_name, "delete-role"),
        ]


@define(eq=False, slots=False)
class AwsIamServerCertificate(AwsResource, BaseCertificate):
    kind: ClassVar[str] = "aws_iam_server_certificate"
    kind_display: ClassVar[str] = "AWS IAM Server Certificate"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:iam:{region}:{account}:server-certificate/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS IAM Server Certificate is a digital certificate that AWS Identity and"
        " Access Management (IAM) uses to verify the identity of a resource like an"
        " HTTPS server. It enables secure communication between the server and AWS"
        " services."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-server-certificates", "ServerCertificateMetadataList"
    )
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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
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
            AwsApiSpec(service_name, "tag-server-certificate"),
            AwsApiSpec(service_name, "untag-server-certificate"),
            AwsApiSpec(service_name, "delete-server-certificate"),
        ]


@define(eq=False, slots=False)
class AwsIamPolicyVersion:
    kind: ClassVar[str] = "aws_iam_policy_version"
    kind_display: ClassVar[str] = "AWS IAM Policy Version"
    kind_description: ClassVar[str] = (
        "IAM Policy Version represents a specific version of an IAM policy definition"
        " in AWS Identity and Access Management service, which defines permissions and"
        " access control for AWS resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "document": S("Document") >> Sorted(sort_list=True),
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
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/iamv2/home?region={region}#/policies/details/{arn}?section=permissions", "arn_tpl": "arn:{partition}:iam::{account}:policy/{name}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS IAM Policy"
    kind_description: ClassVar[str] = (
        "IAM Policies in AWS are used to define permissions and access controls for"
        " users, groups, and roles within the AWS ecosystem."
    )
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
        "managed": S("Arn") >> F(lambda arn: arn.startswith("arn:aws:iam::aws:policy/")),
    }
    path: Optional[str] = field(default=None)
    policy_default_version_id: Optional[str] = field(default=None)
    policy_attachment_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    policy_permissions_boundary_usage_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    policy_is_attachable: Optional[bool] = field(default=None)
    policy_description: Optional[str] = field(default=None)
    policy_document: Optional[AwsIamPolicyVersion] = field(default=None)
    managed: Optional[bool] = field(default=None, metadata=dict(ignore_history=True, desciption="Indicates if this policy is managed by AWS or custom."))  # fmt: skip

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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-policy",
            result_name=None,
            PolicyArn=self.arn,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-policy"),
            AwsApiSpec(service_name, "untag-policy"),
            AwsApiSpec(service_name, "delete-policy"),
        ]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsIamGroup(AwsResource, BaseGroup):
    # Note: this resource is collected via AwsIamUser.collect.
    kind: ClassVar[str] = "aws_iam_group"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/iam/home?region={region}#/groups/details/{name}", "arn_tpl": "arn:{partition}:iam::{account}:group/{name}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS IAM Group"
    kind_description: ClassVar[str] = (
        "IAM Groups are collections of IAM users. They allow you to manage"
        " permissions collectively for multiple users, making it easier to manage"
        " access to AWS resources."
    )
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

    @classmethod
    def service_name(cls) -> str:
        return service_name

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for policy in bend(S("AttachedManagedPolicies", default=[]), source):
            builder.dependant_node(self, clazz=AwsIamPolicy, delete_same_as_default=True, arn=policy.get("PolicyArn"))

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        for successor in self.successors(graph, edge_type=EdgeType.delete):
            if isinstance(successor, AwsIamPolicy):
                log_msg = f"Detaching {successor.rtdname}"
                self.log(log_msg)
                client.call(
                    aws_service=service_name,
                    action="detach-group-policy",
                    result_name=None,
                    GroupName=self.name,
                    PolicyArn=successor.arn,
                )

        for group_policy in self.group_policies:
            log_msg = f"Deleting inline policy {group_policy}"
            self.log(log_msg)
            client.call(
                aws_service=service_name,
                action="delete-group-policy",
                result_name=None,
                GroupName=self.name,
                PolicyName=group_policy,
            )

        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-group",
            result_name=None,
            GroupName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "detach-group-policy"),
            AwsApiSpec(service_name, "delete-group-policy"),
            AwsApiSpec(service_name, "delete-group"),
        ]


@define(eq=False, slots=False)
class AwsIamAccessKeyLastUsed:
    kind: ClassVar[str] = "aws_iam_access_key_last_used"
    kind_display: ClassVar[str] = "AWS IAM Access Key Last Used"
    kind_description: ClassVar[str] = (
        "IAM Access Key Last Used is a feature in Amazon's Identity and Access"
        " Management (IAM) service that allows you to view the last time an IAM access"
        " key was used and the region from which the key was used. This helps you"
        " monitor the usage of access keys and detect any potential unauthorized"
        " access."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_used": S("LastUsedDate"),
        "last_rotated": S("LastRotated"),
        "service_name": S("ServiceName"),
        "region": S("Region"),
    }
    last_used: Optional[datetime] = field(default=None)
    last_rotated: Optional[datetime] = field(default=None)
    service_name: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsIamAccessKey(AwsResource, BaseAccessKey):
    # Note: this resource is collected via AwsIamUser.collect.
    kind: ClassVar[str] = "aws_iam_access_key"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/iam/home?region={region}#/users/{UserName}?section=security_credentials&display=access_key&accessKeyID={AccessKeyId}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS IAM Access Key"
    kind_description: ClassVar[str] = (
        "An AWS IAM Access Key is used to securely access AWS services and resources using API operations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AccessKeyId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("UserName"),
        "ctime": S("CreateDate"),
        "access_key_status": S("Status"),
    }
    access_key_last_used: Optional[AwsIamAccessKeyLastUsed] = field(default=None, metadata=dict(ignore_history=True))


class CredentialReportLine:
    undefined = {"not_supported", "N/A"}

    def __init__(self, line: Dict[str, str]) -> None:
        self.line = line

    def add_root_user(self, builder: GraphBuilder) -> None:
        user = AwsRootUser(
            id="root",
            name="root",
            arn=self.value_of("arn"),
            ctime=self.value_of("user_creation_time", parse_utc),
            password_enabled=self.password_enabled(),
            password_last_used=self.password_last_used(),
            password_last_changed=self.password_last_changed(),
            password_next_rotation=self.password_next_rotation(),
            mfa_active=self.mfa_active(),
        )
        builder.add_node(user)
        for key in self.access_keys():
            if key.access_key_status == "Active" or key.access_key_last_used is not None:
                builder.add_node(key)
                builder.add_edge(user, node=key)

    def access_keys(self) -> List[AwsIamAccessKey]:
        def by_index(i: int) -> AwsIamAccessKey:
            last_used = self.value_of(f"access_key_{i}_last_used_date", parse_utc)
            service_name = self.value_of(f"access_key_{i}_last_used_service")
            region = self.value_of(f"access_key_{i}_last_used_region")
            last_rotated = self.value_of(f"access_key_{i}_last_rotated", parse_utc)
            ak_last_used = (
                None
                if last_used is None and service_name is None and region is None and last_rotated is None
                else AwsIamAccessKeyLastUsed(
                    last_used=last_used, last_rotated=last_rotated, service_name=service_name, region=region
                )
            )
            return AwsIamAccessKey(
                id=f"root_key_{i}",
                name=f"root_key_{i}",
                access_key_status="Active" if self.value_of(f"access_key_{i}_active") == "true" else "Inactive",
                atime=last_used,
                access_key_last_used=ak_last_used,
            )

        # the report holds 2 entries
        return [by_index(idx) for idx in range(1, 3)]

    def value_of(self, k: str, fn: Optional[Callable[[str], Any]] = None) -> Any:
        try:
            v = self.line.get(k)
            return None if v is None or v in self.undefined else (fn(v) if fn else v)
        except Exception:
            return None

    def password_enabled(self) -> bool:
        return self.value_of("password_enabled") == "true"  # type: ignore

    def password_last_used(self) -> Optional[datetime]:
        # can also have a value of "no_information" or "N/A" or similar
        return self.value_of("password_last_used", parse_utc)  # type: ignore

    def password_last_changed(self) -> Optional[datetime]:
        return self.value_of("password_last_changed", parse_utc)  # type: ignore

    def password_next_rotation(self) -> Optional[datetime]:
        return self.value_of("password_next_rotation", parse_utc)  # type: ignore

    def mfa_active(self) -> bool:
        return self.value_of("mfa_active") == "true"  # type: ignore

    @staticmethod
    def user_lines(builder: GraphBuilder) -> Dict[str, "CredentialReportLine"]:
        started_at = utc()
        # wait for the report to be done
        while (
            # in case of access denied, res will be None
            (res := builder.client.get(service_name, "generate-credential-report"))
            # res is defined, but the report is not ready yet
            and res.get("State") != "COMPLETE"
            # give up after 5 minutes
            and (utc() - started_at) < timedelta(minutes=5)
        ):
            time.sleep(1)
        # fetch the report
        if res and res.get("State") == "COMPLETE":
            report = builder.client.get(service_name, "get-credential-report", expected_errors=["ReportNotPresent"])
            return CredentialReportLine.from_str(report["Content"]) if report else {}
        else:
            return {}

    @staticmethod
    def from_str(lines: str) -> Dict[str, "CredentialReportLine"]:
        # noinspection PyTypeChecker
        return {i["user"]: CredentialReportLine(i) for i in csv.DictReader(lines.splitlines(), delimiter=",")}


@define(eq=False, slots=False)
class AwsIamVirtualMfaDevice:
    kind: ClassVar[str] = "aws_iam_virtual_mfa_device"
    kind_display: ClassVar[str] = "AWS IAM Virtual MFA Device"
    kind_description: ClassVar[str] = (
        "AWS IAM Virtual MFA Device is a virtual multi-factor authentication device"
        " that generates time-based one-time passwords (TOTP) for login use cases in"
        " AWS."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "serial_number": S("SerialNumber"),
        "enable_date": S("EnableDate"),
    }
    serial_number: Optional[str] = field(default=None)
    enable_date: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsRootUser(AwsResource, BaseUser):
    kind: ClassVar[str] = "aws_root_user"
    kind_display: ClassVar[str] = "AWS Root User"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:None:{region}:{account}:resource/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "The AWS Root User is the initial user created when setting up an AWS account"
        " and has unrestricted access to all resources in the account."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_account"]},
    }
    password_enabled: Optional[bool] = field(default=None)
    password_last_used: Optional[datetime] = field(default=None)
    password_last_changed: Optional[datetime] = field(default=None)
    password_next_rotation: Optional[datetime] = field(default=None)
    mfa_active: Optional[bool] = field(default=None)
    user_virtual_mfa_devices: Optional[List[AwsIamVirtualMfaDevice]] = field(default=None)


@define(eq=False, slots=False)
class AwsIamUser(AwsResource, BaseUser):
    kind: ClassVar[str] = "aws_iam_user"
    kind_display: ClassVar[str] = "AWS IAM User"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/iam/home?region={region}#/users/details/{name}", "arn_tpl": "arn:{partition}:iam::{account}:user/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "IAM Users are identities created within AWS Identity and Access Management"
        " (IAM) that can be assigned permissions to access and manage AWS resources."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "get-account-authorization-details")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_iam_group"]},
        "successors": {"default": ["aws_iam_policy"], "delete": ["aws_iam_policy"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("UserId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("UserName"),
        "ctime": S("CreateDate"),
        "path": S("Path"),
        "arn": S("Arn"),
        "user_policies": S("UserPolicyList", default=[]) >> ForallBend(AwsIamPolicyDetail.mapping),
        "user_permissions_boundary": S("PermissionsBoundary") >> Bend(AwsIamAttachedPermissionsBoundary.mapping),
    }
    path: Optional[str] = field(default=None)
    user_policies: List[AwsIamPolicyDetail] = field(factory=list)
    user_permissions_boundary: Optional[AwsIamAttachedPermissionsBoundary] = field(default=None)
    password_enabled: Optional[bool] = field(default=None)
    password_last_used: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    password_last_changed: Optional[datetime] = field(default=None)
    password_next_rotation: Optional[datetime] = field(default=None)
    mfa_active: Optional[bool] = field(default=None)
    user_virtual_mfa_devices: Optional[List[AwsIamVirtualMfaDevice]] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-access-keys"),
            AwsApiSpec(service_name, "get-access-key-last-used"),
            AwsApiSpec(service_name, "generate-credential-report"),
            AwsApiSpec(service_name, "get-credential-report"),
        ]

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        # start generation of the credentials resport and pick it up later
        builder.client.get(service_name, "generate-credential-report")
        # let super handle the rest (this will take some time for the report to be done)
        super().collect_resources(builder)  # type: ignore # mypy bug: https://github.com/python/mypy/issues/12885

    @classmethod
    def collect(cls: Type[AwsResource], json_list: List[Json], builder: GraphBuilder) -> None:
        # retrieve the created report
        report = CredentialReportLine.user_lines(builder)

        # the root user is not listed in IAM users, so we need to add it manually
        if root_user := report.get("<root_account>"):
            root_user.add_root_user(builder)

        for json in json_list:
            for js in json.get("GroupDetailList", []):
                if gd := AwsIamGroup.from_api(js, builder):
                    builder.add_node(gd, js)

            for js in json.get("RoleDetailList", []):
                if rd := AwsIamRole.from_api(js, builder):
                    builder.add_node(rd, js)

            for js in json.get("Policies", []):
                if p := AwsIamPolicy.from_api(js, builder):
                    builder.add_node(p, js)

            for js in json.get("UserDetailList", []):
                if user := AwsIamUser.from_api(js, builder):
                    builder.add_node(user, js)
                    line = report.get(user.name or user.id)
                    line_keys: List[AwsIamAccessKey] = []
                    if line:
                        user.password_enabled = line.password_enabled()
                        user.password_last_used = line.password_last_used()
                        user.atime = user.password_last_used
                        user.password_last_changed = line.password_last_changed()
                        user.password_next_rotation = line.password_next_rotation()
                        user.mfa_active = line.mfa_active()
                        line_keys = line.access_keys()
                    # add all iam access keys for this user
                    for idx, ak in enumerate(
                        builder.client.list(service_name, "list-access-keys", "AccessKeyMetadata", UserName=user.name)
                    ):
                        if key := AwsIamAccessKey.from_api(ak, builder):
                            if line and idx < len(line_keys):
                                lk = line_keys[idx]
                                key.access_key_last_used = lk.access_key_last_used
                                key.atime = lk.atime
                            builder.add_node(key, ak)
                            builder.dependant_node(user, node=key)

        def add_virtual_mfa_devices() -> None:
            for vjs in builder.client.list(service_name, "list-virtual-mfa-devices", "VirtualMFADevices"):
                if arn := value_in_path(vjs, "User.Arn"):
                    if isinstance(usr := builder.node(arn=arn), (AwsIamUser, AwsRootUser)):
                        mapped = bend(AwsIamVirtualMfaDevice.mapping, vjs)
                        if node := parse_json(mapped, AwsIamVirtualMfaDevice, builder):
                            if usr.user_virtual_mfa_devices is None:
                                usr.user_virtual_mfa_devices = []
                            usr.user_virtual_mfa_devices.append(node)

        if builder.account.mfa_devices is not None and builder.account.mfa_devices > 0:
            builder.submit_work(service_name, add_virtual_mfa_devices)

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
                    aws_service=service_name,
                    action="detach-user-policy",
                    result_name=None,
                    UserName=self.name,
                    PolicyArn=successor.arn,
                )

        for user_policy in self.user_policies:
            log_msg = f"Deleting inline policy {user_policy}"
            self.log(log_msg)
            client.call(
                aws_service=service_name,
                action="delete-user-policy",
                result_name=None,
                UserName=self.name,
                PolicyName=user_policy.policy_name,
            )

        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="delete-user", result_name=None, UserName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-user"),
            AwsApiSpec(service_name, "untag-user"),
            AwsApiSpec(service_name, "detach-user-policy"),
            AwsApiSpec(service_name, "delete-user-policy"),
            AwsApiSpec(service_name, "delete-user"),
        ]


@define(eq=False, slots=False)
class AwsIamInstanceProfile(AwsResource, BaseInstanceProfile):
    kind: ClassVar[str] = "aws_iam_instance_profile"
    kind_display: ClassVar[str] = "AWS IAM Instance Profile"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:iam:{region}:{account}:instance-profile/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "IAM Instance Profiles are used to associate IAM roles with EC2 instances,"
        " allowing the instances to securely access AWS services and resources."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-instance-profiles", "InstanceProfiles")
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
                    aws_service=service_name,
                    action="remove-role-from-instance-profile",
                    result_name=None,
                    RoleName=predecessor.name,
                    InstanceProfileName=self.name,
                )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name, action="delete-instance-profile", result_name=None, InstanceProfileName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-instance-profile"),
            AwsApiSpec(service_name, "untag-instance-profile"),
            AwsApiSpec(service_name, "remove-role-from-instance-profile"),
            AwsApiSpec(service_name, "delete-instance-profile"),
        ]


resources: List[Type[AwsResource]] = [
    AwsIamServerCertificate,
    AwsIamPolicy,
    AwsIamGroup,
    AwsIamRole,
    AwsIamUser,
    AwsIamInstanceProfile,
]
