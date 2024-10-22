from concurrent.futures import as_completed
from datetime import datetime, timezone
from typing import ClassVar, Dict, List, Optional, Tuple, Type, Any
import logging

from attrs import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder

from fixlib.baseresources import Assessment, Finding, PhantomBaseResource, Severity
from fixlib.json_bender import F, S, AsInt, Bend, Bender, ForallBend
from fixlib.types import Json
from fixlib.utils import chunks, utc_str

log = logging.getLogger("fix.plugins.aws")
service_name = "guardduty"


@define(eq=False, slots=False)
class AwsGuardDutyAccessKeyDetails:
    kind: ClassVar[str] = "aws_guard_duty_access_key_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_key_id": S("AccessKeyId"),
        "principal_id": S("PrincipalId"),
        "user_name": S("UserName"),
        "user_type": S("UserType"),
    }
    access_key_id: Optional[str] = field(default=None, metadata={"description": "The access key ID of the user."})  # fmt: skip
    principal_id: Optional[str] = field(default=None, metadata={"description": "The principal ID of the user."})  # fmt: skip
    user_name: Optional[str] = field(default=None, metadata={"description": "The name of the user."})  # fmt: skip
    user_type: Optional[str] = field(default=None, metadata={"description": "The type of the user."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyDefaultServerSideEncryption:
    kind: ClassVar[str] = "aws_guard_duty_default_server_side_encryption"
    mapping: ClassVar[Dict[str, Bender]] = {
        "encryption_type": S("EncryptionType"),
        "kms_master_key_arn": S("KmsMasterKeyArn"),
    }
    encryption_type: Optional[str] = field(default=None, metadata={"description": "The type of encryption used for objects within the S3 bucket."})  # fmt: skip
    kms_master_key_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the KMS encryption key. Only available if the bucket EncryptionType is aws:kms."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyAccessControlList:
    kind: ClassVar[str] = "aws_guard_duty_access_control_list"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allows_public_read_access": S("AllowsPublicReadAccess"),
        "allows_public_write_access": S("AllowsPublicWriteAccess"),
    }
    allows_public_read_access: Optional[bool] = field(default=None, metadata={"description": "A value that indicates whether public read access for the bucket is enabled through an Access Control List (ACL)."})  # fmt: skip
    allows_public_write_access: Optional[bool] = field(default=None, metadata={"description": "A value that indicates whether public write access for the bucket is enabled through an Access Control List (ACL)."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyBucketPolicy:
    kind: ClassVar[str] = "aws_guard_duty_bucket_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allows_public_read_access": S("AllowsPublicReadAccess"),
        "allows_public_write_access": S("AllowsPublicWriteAccess"),
    }
    allows_public_read_access: Optional[bool] = field(default=None, metadata={"description": "A value that indicates whether public read access for the bucket is enabled through a bucket policy."})  # fmt: skip
    allows_public_write_access: Optional[bool] = field(default=None, metadata={"description": "A value that indicates whether public write access for the bucket is enabled through a bucket policy."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyBlockPublicAccess:
    kind: ClassVar[str] = "aws_guard_duty_block_public_access"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ignore_public_acls": S("IgnorePublicAcls"),
        "restrict_public_buckets": S("RestrictPublicBuckets"),
        "block_public_acls": S("BlockPublicAcls"),
        "block_public_policy": S("BlockPublicPolicy"),
    }
    ignore_public_acls: Optional[bool] = field(default=None, metadata={"description": "Indicates if S3 Block Public Access is set to IgnorePublicAcls."})  # fmt: skip
    restrict_public_buckets: Optional[bool] = field(default=None, metadata={"description": "Indicates if S3 Block Public Access is set to RestrictPublicBuckets."})  # fmt: skip
    block_public_acls: Optional[bool] = field(default=None, metadata={"description": "Indicates if S3 Block Public Access is set to BlockPublicAcls."})  # fmt: skip
    block_public_policy: Optional[bool] = field(default=None, metadata={"description": "Indicates if S3 Block Public Access is set to BlockPublicPolicy."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyBucketLevelPermissions:
    kind: ClassVar[str] = "aws_guard_duty_bucket_level_permissions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_control_list": S("AccessControlList") >> Bend(AwsGuardDutyAccessControlList.mapping),
        "bucket_policy": S("BucketPolicy") >> Bend(AwsGuardDutyBucketPolicy.mapping),
        "block_public_access": S("BlockPublicAccess") >> Bend(AwsGuardDutyBlockPublicAccess.mapping),
    }
    access_control_list: Optional[AwsGuardDutyAccessControlList] = field(default=None, metadata={"description": "Contains information on how Access Control Policies are applied to the bucket."})  # fmt: skip
    bucket_policy: Optional[AwsGuardDutyBucketPolicy] = field(default=None, metadata={"description": "Contains information on the bucket policies for the S3 bucket."})  # fmt: skip
    block_public_access: Optional[AwsGuardDutyBlockPublicAccess] = field(default=None, metadata={"description": "Contains information on which account level S3 Block Public Access settings are applied to the S3 bucket."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyAccountLevelPermissions:
    kind: ClassVar[str] = "aws_guard_duty_account_level_permissions"
    mapping: ClassVar[Dict[str, Bender]] = {
        "block_public_access": S("BlockPublicAccess") >> Bend(AwsGuardDutyBlockPublicAccess.mapping)
    }
    block_public_access: Optional[AwsGuardDutyBlockPublicAccess] = field(default=None, metadata={"description": "Describes the S3 Block Public Access settings of the bucket's parent account."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyPermissionConfiguration:
    kind: ClassVar[str] = "aws_guard_duty_permission_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bucket_level_permissions": S("BucketLevelPermissions") >> Bend(AwsGuardDutyBucketLevelPermissions.mapping),
        "account_level_permissions": S("AccountLevelPermissions") >> Bend(AwsGuardDutyAccountLevelPermissions.mapping),
    }
    bucket_level_permissions: Optional[AwsGuardDutyBucketLevelPermissions] = field(default=None, metadata={"description": "Contains information about the bucket level permissions for the S3 bucket."})  # fmt: skip
    account_level_permissions: Optional[AwsGuardDutyAccountLevelPermissions] = field(default=None, metadata={"description": "Contains information about the account level permissions on the S3 bucket."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyPublicAccess:
    kind: ClassVar[str] = "aws_guard_duty_public_access"
    mapping: ClassVar[Dict[str, Bender]] = {
        "permission_configuration": S("PermissionConfiguration") >> Bend(AwsGuardDutyPermissionConfiguration.mapping),
        "effective_permission": S("EffectivePermission"),
    }
    permission_configuration: Optional[AwsGuardDutyPermissionConfiguration] = field(default=None, metadata={"description": "Contains information about how permissions are configured for the S3 bucket."})  # fmt: skip
    effective_permission: Optional[str] = field(default=None, metadata={"description": "Describes the effective permission on this bucket after factoring all attached policies."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyS3ObjectDetail:
    kind: ClassVar[str] = "aws_guard_duty_s3_object_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "object_arn": S("ObjectArn"),
        "key": S("Key"),
        "e_tag": S("ETag"),
        "hash": S("Hash"),
        "version_id": S("VersionId"),
    }
    object_arn: Optional[str] = field(default=None, metadata={"description": "Amazon Resource Name (ARN) of the S3 object."})  # fmt: skip
    key: Optional[str] = field(default=None, metadata={"description": "Key of the S3 object."})  # fmt: skip
    e_tag: Optional[str] = field(default=None, metadata={"description": "The entity tag is a hash of the S3 object. The ETag reflects changes only to the contents of an object, and not its metadata."})  # fmt: skip
    hash: Optional[str] = field(default=None, metadata={"description": "Hash of the threat detected in this finding."})  # fmt: skip
    version_id: Optional[str] = field(default=None, metadata={"description": "Version ID of the object."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyS3BucketDetail:
    kind: ClassVar[str] = "aws_guard_duty_s3_bucket_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "arn": S("Arn"),
        "name": S("Name"),
        "type": S("Type"),
        "created_at": S("CreatedAt"),
        "owner": S("Owner", "Id"),
        "default_server_side_encryption": S("DefaultServerSideEncryption")
        >> Bend(AwsGuardDutyDefaultServerSideEncryption.mapping),
        "public_access": S("PublicAccess") >> Bend(AwsGuardDutyPublicAccess.mapping),
        "s3_object_details": S("S3ObjectDetails", default=[]) >> ForallBend(AwsGuardDutyS3ObjectDetail.mapping),
    }
    arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the S3 bucket."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the S3 bucket."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Describes whether the bucket is a source or destination bucket."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the bucket was created at."})  # fmt: skip
    owner: Optional[str] = field(default=None, metadata={"description": "The owner of the S3 bucket."})  # fmt: skip
    default_server_side_encryption: Optional[AwsGuardDutyDefaultServerSideEncryption] = field(default=None, metadata={"description": "Describes the server side encryption method used in the S3 bucket."})  # fmt: skip
    public_access: Optional[AwsGuardDutyPublicAccess] = field(default=None, metadata={"description": "Describes the public access policies that apply to the S3 bucket."})  # fmt: skip
    s3_object_details: Optional[List[AwsGuardDutyS3ObjectDetail]] = field(factory=list, metadata={"description": "Information about the S3 object that was scanned."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyIamInstanceProfile:
    kind: ClassVar[str] = "aws_guard_duty_iam_instance_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "id": S("Id")}
    arn: Optional[str] = field(default=None, metadata={"description": "The profile ARN of the EC2 instance."})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "The profile ID of the EC2 instance."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyPrivateIpAddressDetails:
    kind: ClassVar[str] = "aws_guard_duty_private_ip_address_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "private_dns_name": S("PrivateDnsName"),
        "private_ip_address": S("PrivateIpAddress"),
    }
    private_dns_name: Optional[str] = field(default=None, metadata={"description": "The private DNS name of the EC2 instance."})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={"description": "The private IP address of the EC2 instance."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutySecurityGroup:
    kind: ClassVar[str] = "aws_guard_duty_security_group"
    mapping: ClassVar[Dict[str, Bender]] = {"group_id": S("GroupId"), "group_name": S("GroupName")}
    group_id: Optional[str] = field(default=None, metadata={"description": "The security group ID of the EC2 instance."})  # fmt: skip
    group_name: Optional[str] = field(default=None, metadata={"description": "The security group name of the EC2 instance."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyNetworkInterface:
    kind: ClassVar[str] = "aws_guard_duty_network_interface"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ipv6_addresses": S("Ipv6Addresses", default=[]),
        "network_interface_id": S("NetworkInterfaceId"),
        "private_dns_name": S("PrivateDnsName"),
        "private_ip_address": S("PrivateIpAddress"),
        "private_ip_addresses": S("PrivateIpAddresses", default=[])
        >> ForallBend(AwsGuardDutyPrivateIpAddressDetails.mapping),
        "public_dns_name": S("PublicDnsName"),
        "public_ip": S("PublicIp"),
        "security_groups": S("SecurityGroups", default=[]) >> ForallBend(AwsGuardDutySecurityGroup.mapping),
        "subnet_id": S("SubnetId"),
        "vpc_id": S("VpcId"),
    }
    ipv6_addresses: Optional[List[str]] = field(factory=list, metadata={"description": "A list of IPv6 addresses for the EC2 instance."})  # fmt: skip
    network_interface_id: Optional[str] = field(default=None, metadata={"description": "The ID of the network interface."})  # fmt: skip
    private_dns_name: Optional[str] = field(default=None, metadata={"description": "The private DNS name of the EC2 instance."})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={"description": "The private IP address of the EC2 instance."})  # fmt: skip
    private_ip_addresses: Optional[List[AwsGuardDutyPrivateIpAddressDetails]] = field(factory=list, metadata={"description": "Other private IP address information of the EC2 instance."})  # fmt: skip
    public_dns_name: Optional[str] = field(default=None, metadata={"description": "The public DNS name of the EC2 instance."})  # fmt: skip
    public_ip: Optional[str] = field(default=None, metadata={"description": "The public IP address of the EC2 instance."})  # fmt: skip
    security_groups: Optional[List[AwsGuardDutySecurityGroup]] = field(factory=list, metadata={"description": "The security groups associated with the EC2 instance."})  # fmt: skip
    subnet_id: Optional[str] = field(default=None, metadata={"description": "The subnet ID of the EC2 instance."})  # fmt: skip
    vpc_id: Optional[str] = field(default=None, metadata={"description": "The VPC ID of the EC2 instance."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyProductCode:
    kind: ClassVar[str] = "aws_guard_duty_product_code"
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "product_type": S("ProductType")}
    code: Optional[str] = field(default=None, metadata={"description": "The product code information."})  # fmt: skip
    product_type: Optional[str] = field(default=None, metadata={"description": "The product code type."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyInstanceDetails:
    kind: ClassVar[str] = "aws_guard_duty_instance_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "availability_zone": S("AvailabilityZone"),
        "iam_instance_profile": S("IamInstanceProfile") >> Bend(AwsGuardDutyIamInstanceProfile.mapping),
        "image_description": S("ImageDescription"),
        "image_id": S("ImageId"),
        "instance_id": S("InstanceId"),
        "instance_state": S("InstanceState"),
        "instance_type": S("InstanceType"),
        "outpost_arn": S("OutpostArn"),
        "launch_time": S("LaunchTime"),
        "network_interfaces": S("NetworkInterfaces", default=[]) >> ForallBend(AwsGuardDutyNetworkInterface.mapping),
        "platform": S("Platform"),
        "product_codes": S("ProductCodes", default=[]) >> ForallBend(AwsGuardDutyProductCode.mapping),
    }
    availability_zone: Optional[str] = field(default=None, metadata={"description": "The Availability Zone of the EC2 instance."})  # fmt: skip
    iam_instance_profile: Optional[AwsGuardDutyIamInstanceProfile] = field(default=None, metadata={"description": "The profile information of the EC2 instance."})  # fmt: skip
    image_description: Optional[str] = field(default=None, metadata={"description": "The image description of the EC2 instance."})  # fmt: skip
    image_id: Optional[str] = field(default=None, metadata={"description": "The image ID of the EC2 instance."})  # fmt: skip
    instance_id: Optional[str] = field(default=None, metadata={"description": "The ID of the EC2 instance."})  # fmt: skip
    instance_state: Optional[str] = field(default=None, metadata={"description": "The state of the EC2 instance."})  # fmt: skip
    instance_type: Optional[str] = field(default=None, metadata={"description": "The type of the EC2 instance."})  # fmt: skip
    outpost_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the Amazon Web Services Outpost. Only applicable to Amazon Web Services Outposts instances."})  # fmt: skip
    launch_time: Optional[str] = field(default=None, metadata={"description": "The launch time of the EC2 instance."})  # fmt: skip
    network_interfaces: Optional[List[AwsGuardDutyNetworkInterface]] = field(factory=list, metadata={"description": "The elastic network interface information of the EC2 instance."})  # fmt: skip
    platform: Optional[str] = field(default=None, metadata={"description": "The platform of the EC2 instance."})  # fmt: skip
    product_codes: Optional[List[AwsGuardDutyProductCode]] = field(factory=list, metadata={"description": "The product code of the EC2 instance."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyEksClusterDetails:
    kind: ClassVar[str] = "aws_guard_duty_eks_cluster_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "arn": S("Arn"),
        "vpc_id": S("VpcId"),
        "status": S("Status"),
        "created_at": S("CreatedAt"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "EKS cluster name."})  # fmt: skip
    arn: Optional[str] = field(default=None, metadata={"description": "EKS cluster ARN."})  # fmt: skip
    vpc_id: Optional[str] = field(default=None, metadata={"description": "The VPC ID to which the EKS cluster is attached."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The EKS cluster status."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The timestamp when the EKS cluster was created."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyImpersonatedUser:
    kind: ClassVar[str] = "aws_guard_duty_impersonated_user"
    mapping: ClassVar[Dict[str, Bender]] = {"username": S("Username"), "groups": S("Groups", default=[])}
    username: Optional[str] = field(default=None, metadata={"description": "Information about the username that was being impersonated."})  # fmt: skip
    groups: Optional[List[str]] = field(factory=list, metadata={"description": "The group to which the user name belongs."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyKubernetesUserDetails:
    kind: ClassVar[str] = "aws_guard_duty_kubernetes_user_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "username": S("Username"),
        "uid": S("Uid"),
        "groups": S("Groups", default=[]),
        "session_name": S("SessionName", default=[]),
        "impersonated_user": S("ImpersonatedUser") >> Bend(AwsGuardDutyImpersonatedUser.mapping),
    }
    username: Optional[str] = field(default=None, metadata={"description": "The username of the user who called the Kubernetes API."})  # fmt: skip
    uid: Optional[str] = field(default=None, metadata={"description": "The user ID of the user who called the Kubernetes API."})  # fmt: skip
    groups: Optional[List[str]] = field(factory=list, metadata={"description": "The groups that include the user who called the Kubernetes API."})  # fmt: skip
    session_name: Optional[List[str]] = field(factory=list, metadata={"description": "Entity that assumes the IAM role when Kubernetes RBAC permissions are assigned to that role."})  # fmt: skip
    impersonated_user: Optional[AwsGuardDutyImpersonatedUser] = field(default=None, metadata={"description": "Information about the impersonated user."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyVolumeMount:
    kind: ClassVar[str] = "aws_guard_duty_volume_mount"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "mount_path": S("MountPath")}
    name: Optional[str] = field(default=None, metadata={"description": "Volume mount name."})  # fmt: skip
    mount_path: Optional[str] = field(default=None, metadata={"description": "Volume mount path."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutySecurityContext:
    kind: ClassVar[str] = "aws_guard_duty_security_context"
    mapping: ClassVar[Dict[str, Bender]] = {
        "privileged": S("Privileged"),
        "allow_privilege_escalation": S("AllowPrivilegeEscalation"),
    }
    privileged: Optional[bool] = field(default=None, metadata={"description": "Whether the container is privileged."})  # fmt: skip
    allow_privilege_escalation: Optional[bool] = field(default=None, metadata={"description": "Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyContainer:
    kind: ClassVar[str] = "aws_guard_duty_container"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_runtime": S("ContainerRuntime"),
        "id": S("Id"),
        "name": S("Name"),
        "image": S("Image"),
        "image_prefix": S("ImagePrefix"),
        "volume_mounts": S("VolumeMounts", default=[]) >> ForallBend(AwsGuardDutyVolumeMount.mapping),
        "security_context": S("SecurityContext") >> Bend(AwsGuardDutySecurityContext.mapping),
    }
    container_runtime: Optional[str] = field(default=None, metadata={"description": "The container runtime (such as, Docker or containerd) used to run the container."})  # fmt: skip
    id: Optional[str] = field(default=None, metadata={"description": "Container ID."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "Container name."})  # fmt: skip
    image: Optional[str] = field(default=None, metadata={"description": "Container image."})  # fmt: skip
    image_prefix: Optional[str] = field(default=None, metadata={"description": "Part of the image name before the last slash. For example, imagePrefix for public.ecr.aws/amazonlinux/amazonlinux:latest would be public.ecr.aws/amazonlinux. If the image name is relative and does not have a slash, this field is empty."})  # fmt: skip
    volume_mounts: Optional[List[AwsGuardDutyVolumeMount]] = field(factory=list, metadata={"description": "Container volume mounts."})  # fmt: skip
    security_context: Optional[AwsGuardDutySecurityContext] = field(default=None, metadata={"description": "Container security context."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyVolume:
    kind: ClassVar[str] = "aws_guard_duty_volume"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "host_path": S("HostPath", "Path")}
    name: Optional[str] = field(default=None, metadata={"description": "Volume name."})  # fmt: skip
    host_path: Optional[str] = field(default=None, metadata={"description": "Represents a pre-existing file or directory on the host machine that the volume maps to."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyKubernetesWorkloadDetails:
    kind: ClassVar[str] = "aws_guard_duty_kubernetes_workload_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "type": S("Type"),
        "uid": S("Uid"),
        "namespace": S("Namespace"),
        "host_network": S("HostNetwork"),
        "containers": S("Containers", default=[]) >> ForallBend(AwsGuardDutyContainer.mapping),
        "volumes": S("Volumes", default=[]) >> ForallBend(AwsGuardDutyVolume.mapping),
        "service_account_name": S("ServiceAccountName"),
        "host_ipc": S("HostIPC"),
        "host_pid": S("HostPID"),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Kubernetes workload name."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Kubernetes workload type (e.g. Pod, Deployment, etc.)."})  # fmt: skip
    uid: Optional[str] = field(default=None, metadata={"description": "Kubernetes workload ID."})  # fmt: skip
    namespace: Optional[str] = field(default=None, metadata={"description": "Kubernetes namespace that the workload is part of."})  # fmt: skip
    host_network: Optional[bool] = field(default=None, metadata={"description": "Whether the hostNetwork flag is enabled for the pods included in the workload."})  # fmt: skip
    containers: Optional[List[AwsGuardDutyContainer]] = field(factory=list, metadata={"description": "Containers running as part of the Kubernetes workload."})  # fmt: skip
    volumes: Optional[List[AwsGuardDutyVolume]] = field(factory=list, metadata={"description": "Volumes used by the Kubernetes workload."})  # fmt: skip
    service_account_name: Optional[str] = field(default=None, metadata={"description": "The service account name that is associated with a Kubernetes workload."})  # fmt: skip
    host_ipc: Optional[bool] = field(default=None, metadata={"description": "Whether the host IPC flag is enabled for the pods in the workload."})  # fmt: skip
    host_pid: Optional[bool] = field(default=None, metadata={"description": "Whether the host PID flag is enabled for the pods in the workload."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyKubernetesDetails:
    kind: ClassVar[str] = "aws_guard_duty_kubernetes_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "kubernetes_user_details": S("KubernetesUserDetails") >> Bend(AwsGuardDutyKubernetesUserDetails.mapping),
        "kubernetes_workload_details": S("KubernetesWorkloadDetails")
        >> Bend(AwsGuardDutyKubernetesWorkloadDetails.mapping),
    }
    kubernetes_user_details: Optional[AwsGuardDutyKubernetesUserDetails] = field(default=None, metadata={"description": "Details about the Kubernetes user involved in a Kubernetes finding."})  # fmt: skip
    kubernetes_workload_details: Optional[AwsGuardDutyKubernetesWorkloadDetails] = field(default=None, metadata={"description": "Details about the Kubernetes workload involved in a Kubernetes finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyVolumeDetail:
    kind: ClassVar[str] = "aws_guard_duty_volume_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "volume_arn": S("VolumeArn"),
        "volume_type": S("VolumeType"),
        "device_name": S("DeviceName"),
        "volume_size_in_gb": S("VolumeSizeInGB"),
        "encryption_type": S("EncryptionType"),
        "snapshot_arn": S("SnapshotArn"),
        "kms_key_arn": S("KmsKeyArn"),
    }
    volume_arn: Optional[str] = field(default=None, metadata={"description": "EBS volume ARN information."})  # fmt: skip
    volume_type: Optional[str] = field(default=None, metadata={"description": "The EBS volume type."})  # fmt: skip
    device_name: Optional[str] = field(default=None, metadata={"description": "The device name for the EBS volume."})  # fmt: skip
    volume_size_in_gb: Optional[int] = field(default=None, metadata={"description": "EBS volume size in GB."})  # fmt: skip
    encryption_type: Optional[str] = field(default=None, metadata={"description": "EBS volume encryption type."})  # fmt: skip
    snapshot_arn: Optional[str] = field(default=None, metadata={"description": "Snapshot ARN of the EBS volume."})  # fmt: skip
    kms_key_arn: Optional[str] = field(default=None, metadata={"description": "KMS key ARN used to encrypt the EBS volume."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyEbsVolumeDetails:
    kind: ClassVar[str] = "aws_guard_duty_ebs_volume_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "scanned_volume_details": S("ScannedVolumeDetails", default=[]) >> ForallBend(AwsGuardDutyVolumeDetail.mapping),
        "skipped_volume_details": S("SkippedVolumeDetails", default=[]) >> ForallBend(AwsGuardDutyVolumeDetail.mapping),
    }
    scanned_volume_details: Optional[List[AwsGuardDutyVolumeDetail]] = field(factory=list, metadata={"description": "List of EBS volumes that were scanned."})  # fmt: skip
    skipped_volume_details: Optional[List[AwsGuardDutyVolumeDetail]] = field(factory=list, metadata={"description": "List of EBS volumes that were skipped from the malware scan."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyEcsTaskDetails:
    kind: ClassVar[str] = "aws_guard_duty_ecs_task_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "arn": S("Arn"),
        "definition_arn": S("DefinitionArn"),
        "version": S("Version"),
        "task_created_at": S("TaskCreatedAt"),
        "started_at": S("StartedAt"),
        "started_by": S("StartedBy"),
        "volumes": S("Volumes", default=[]) >> ForallBend(AwsGuardDutyVolume.mapping),
        "containers": S("Containers", default=[]) >> ForallBend(AwsGuardDutyContainer.mapping),
        "group": S("Group"),
    }
    arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the task."})  # fmt: skip
    definition_arn: Optional[str] = field(default=None, metadata={"description": "The ARN of the task definition that creates the task."})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The version counter for the task."})  # fmt: skip
    task_created_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp for the time when the task was created."})  # fmt: skip
    started_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp for the time when the task started."})  # fmt: skip
    started_by: Optional[str] = field(default=None, metadata={"description": "Contains the tag specified when a task is started."})  # fmt: skip
    volumes: Optional[List[AwsGuardDutyVolume]] = field(factory=list, metadata={"description": "The list of data volume definitions for the task."})  # fmt: skip
    containers: Optional[List[AwsGuardDutyContainer]] = field(factory=list, metadata={"description": "The containers that's associated with the task."})  # fmt: skip
    group: Optional[str] = field(default=None, metadata={"description": "The name of the task group that's associated with the task."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyEcsClusterDetails:
    kind: ClassVar[str] = "aws_guard_duty_ecs_cluster_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "arn": S("Arn"),
        "status": S("Status"),
        "active_services_count": S("ActiveServicesCount"),
        "registered_container_instances_count": S("RegisteredContainerInstancesCount"),
        "running_tasks_count": S("RunningTasksCount"),
        "task_details": S("TaskDetails") >> Bend(AwsGuardDutyEcsTaskDetails.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the ECS Cluster."})  # fmt: skip
    arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) that identifies the cluster."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the ECS cluster."})  # fmt: skip
    active_services_count: Optional[int] = field(default=None, metadata={"description": "The number of services that are running on the cluster in an ACTIVE state."})  # fmt: skip
    registered_container_instances_count: Optional[int] = field(default=None, metadata={"description": "The number of container instances registered into the cluster."})  # fmt: skip
    running_tasks_count: Optional[int] = field(default=None, metadata={"description": "The number of tasks in the cluster that are in the RUNNING state."})  # fmt: skip
    task_details: Optional[AwsGuardDutyEcsTaskDetails] = field(default=None, metadata={"description": "Contains information about the details of the ECS Task."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyRdsDbInstanceDetails:
    kind: ClassVar[str] = "aws_guard_duty_rds_db_instance_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "db_instance_identifier": S("DbInstanceIdentifier"),
        "engine": S("Engine"),
        "engine_version": S("EngineVersion"),
        "db_cluster_identifier": S("DbClusterIdentifier"),
        "db_instance_arn": S("DbInstanceArn"),
    }
    db_instance_identifier: Optional[str] = field(default=None, metadata={"description": "The identifier associated to the database instance that was involved in the finding."})  # fmt: skip
    engine: Optional[str] = field(default=None, metadata={"description": "The database engine of the database instance involved in the finding."})  # fmt: skip
    engine_version: Optional[str] = field(default=None, metadata={"description": "The version of the database engine that was involved in the finding."})  # fmt: skip
    db_cluster_identifier: Optional[str] = field(default=None, metadata={"description": "The identifier of the database cluster that contains the database instance ID involved in the finding."})  # fmt: skip
    db_instance_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) that identifies the database instance involved in the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyRdsDbUserDetails:
    kind: ClassVar[str] = "aws_guard_duty_rds_db_user_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "user": S("User"),
        "application": S("Application"),
        "database": S("Database"),
        "ssl": S("Ssl"),
        "auth_method": S("AuthMethod"),
    }
    user: Optional[str] = field(default=None, metadata={"description": "The user name used in the anomalous login attempt."})  # fmt: skip
    application: Optional[str] = field(default=None, metadata={"description": "The application name used in the anomalous login attempt."})  # fmt: skip
    database: Optional[str] = field(default=None, metadata={"description": "The name of the database instance involved in the anomalous login attempt."})  # fmt: skip
    ssl: Optional[str] = field(default=None, metadata={"description": "The version of the Secure Socket Layer (SSL) used for the network."})  # fmt: skip
    auth_method: Optional[str] = field(default=None, metadata={"description": "The authentication method used by the user involved in the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyVpcConfig:
    kind: ClassVar[str] = "aws_guard_duty_vpc_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "subnet_ids": S("SubnetIds", default=[]),
        "vpc_id": S("VpcId"),
        "security_groups": S("SecurityGroups", default=[]) >> ForallBend(AwsGuardDutySecurityGroup.mapping),
    }
    subnet_ids: Optional[List[str]] = field(factory=list, metadata={"description": "The identifiers of the subnets that are associated with your Lambda function."})  # fmt: skip
    vpc_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Virtual Private Cloud."})  # fmt: skip
    security_groups: Optional[List[AwsGuardDutySecurityGroup]] = field(factory=list, metadata={"description": "The identifier of the security group attached to the Lambda function."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyLambdaDetails:
    kind: ClassVar[str] = "aws_guard_duty_lambda_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "function_arn": S("FunctionArn"),
        "function_name": S("FunctionName"),
        "description": S("Description"),
        "last_modified_at": S("LastModifiedAt"),
        "revision_id": S("RevisionId"),
        "function_version": S("FunctionVersion"),
        "role": S("Role"),
        "vpc_config": S("VpcConfig") >> Bend(AwsGuardDutyVpcConfig.mapping),
    }
    function_arn: Optional[str] = field(default=None, metadata={"description": "Amazon Resource Name (ARN) of the Lambda function."})  # fmt: skip
    function_name: Optional[str] = field(default=None, metadata={"description": "Name of the Lambda function."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "Description of the Lambda function."})  # fmt: skip
    last_modified_at: Optional[datetime] = field(default=None, metadata={"description": "The timestamp when the Lambda function was last modified. This field is in the UTC date string format (2023-03-22T19:37:20.168Z)."})  # fmt: skip
    revision_id: Optional[str] = field(default=None, metadata={"description": "The revision ID of the Lambda function version."})  # fmt: skip
    function_version: Optional[str] = field(default=None, metadata={"description": "The version of the Lambda function."})  # fmt: skip
    role: Optional[str] = field(default=None, metadata={"description": "The execution role of the Lambda function."})  # fmt: skip
    vpc_config: Optional[AwsGuardDutyVpcConfig] = field(default=None, metadata={"description": "Amazon Virtual Private Cloud configuration details associated with your Lambda function."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyResource:
    kind: ClassVar[str] = "aws_guard_duty_resource"
    mapping: ClassVar[Dict[str, Bender]] = {
        "access_key_details": S("AccessKeyDetails") >> Bend(AwsGuardDutyAccessKeyDetails.mapping),
        "s3_bucket_details": S("S3BucketDetails", default=[]) >> ForallBend(AwsGuardDutyS3BucketDetail.mapping),
        "instance_details": S("InstanceDetails") >> Bend(AwsGuardDutyInstanceDetails.mapping),
        "eks_cluster_details": S("EksClusterDetails") >> Bend(AwsGuardDutyEksClusterDetails.mapping),
        "kubernetes_details": S("KubernetesDetails") >> Bend(AwsGuardDutyKubernetesDetails.mapping),
        "resource_type": S("ResourceType"),
        "ebs_volume_details": S("EbsVolumeDetails") >> Bend(AwsGuardDutyEbsVolumeDetails.mapping),
        "ecs_cluster_details": S("EcsClusterDetails") >> Bend(AwsGuardDutyEcsClusterDetails.mapping),
        "container_details": S("ContainerDetails") >> Bend(AwsGuardDutyContainer.mapping),
        "rds_db_instance_details": S("RdsDbInstanceDetails") >> Bend(AwsGuardDutyRdsDbInstanceDetails.mapping),
        "rds_db_user_details": S("RdsDbUserDetails") >> Bend(AwsGuardDutyRdsDbUserDetails.mapping),
        "lambda_details": S("LambdaDetails") >> Bend(AwsGuardDutyLambdaDetails.mapping),
    }
    access_key_details: Optional[AwsGuardDutyAccessKeyDetails] = field(default=None, metadata={"description": "The IAM access key details (user information) of a user that engaged in the activity that prompted GuardDuty to generate a finding."})  # fmt: skip
    s3_bucket_details: Optional[List[AwsGuardDutyS3BucketDetail]] = field(factory=list, metadata={"description": "Contains information on the S3 bucket."})  # fmt: skip
    instance_details: Optional[AwsGuardDutyInstanceDetails] = field(default=None, metadata={"description": "The information about the EC2 instance associated with the activity that prompted GuardDuty to generate a finding."})  # fmt: skip
    eks_cluster_details: Optional[AwsGuardDutyEksClusterDetails] = field(default=None, metadata={"description": "Details about the EKS cluster involved in a Kubernetes finding."})  # fmt: skip
    kubernetes_details: Optional[AwsGuardDutyKubernetesDetails] = field(default=None, metadata={"description": "Details about the Kubernetes user and workload involved in a Kubernetes finding."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of Amazon Web Services resource."})  # fmt: skip
    ebs_volume_details: Optional[AwsGuardDutyEbsVolumeDetails] = field(default=None, metadata={"description": "Contains list of scanned and skipped EBS volumes with details."})  # fmt: skip
    ecs_cluster_details: Optional[AwsGuardDutyEcsClusterDetails] = field(default=None, metadata={"description": "Contains information about the details of the ECS Cluster."})  # fmt: skip
    container_details: Optional[AwsGuardDutyContainer] = field(default=None, metadata={"description": "Details of a container."})  # fmt: skip
    rds_db_instance_details: Optional[AwsGuardDutyRdsDbInstanceDetails] = field(default=None, metadata={"description": "Contains information about the database instance to which an anomalous login attempt was made."})  # fmt: skip
    rds_db_user_details: Optional[AwsGuardDutyRdsDbUserDetails] = field(default=None, metadata={"description": "Contains information about the user details through which anomalous login attempt was made."})  # fmt: skip
    lambda_details: Optional[AwsGuardDutyLambdaDetails] = field(default=None, metadata={"description": "Contains information about the Lambda function that was involved in a finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyCountry:
    kind: ClassVar[str] = "aws_guard_duty_country"
    mapping: ClassVar[Dict[str, Bender]] = {"country_code": S("CountryCode"), "country_name": S("CountryName")}
    country_code: Optional[str] = field(default=None, metadata={"description": "The country code of the remote IP address."})  # fmt: skip
    country_name: Optional[str] = field(default=None, metadata={"description": "The country name of the remote IP address."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyGeoLocation:
    kind: ClassVar[str] = "aws_guard_duty_geo_location"
    mapping: ClassVar[Dict[str, Bender]] = {"lat": S("Lat"), "lon": S("Lon")}
    lat: Optional[float] = field(default=None, metadata={"description": "The latitude information of the remote IP address."})  # fmt: skip
    lon: Optional[float] = field(default=None, metadata={"description": "The longitude information of the remote IP address."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyOrganization:
    kind: ClassVar[str] = "aws_guard_duty_organization"
    mapping: ClassVar[Dict[str, Bender]] = {"asn": S("Asn"), "asn_org": S("AsnOrg"), "isp": S("Isp"), "org": S("Org")}
    asn: Optional[str] = field(default=None, metadata={"description": "The Autonomous System Number (ASN) of the internet provider of the remote IP address."})  # fmt: skip
    asn_org: Optional[str] = field(default=None, metadata={"description": "The organization that registered this ASN."})  # fmt: skip
    isp: Optional[str] = field(default=None, metadata={"description": "The ISP information for the internet provider."})  # fmt: skip
    org: Optional[str] = field(default=None, metadata={"description": "The name of the internet provider."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyRemoteIpDetails:
    kind: ClassVar[str] = "aws_guard_duty_remote_ip_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "city": S("City", "CityName"),
        "country": S("Country") >> Bend(AwsGuardDutyCountry.mapping),
        "geo_location": S("GeoLocation") >> Bend(AwsGuardDutyGeoLocation.mapping),
        "ip_address_v4": S("IpAddressV4"),
        "ip_address_v6": S("IpAddressV6"),
        "organization": S("Organization") >> Bend(AwsGuardDutyOrganization.mapping),
    }
    city: Optional[str] = field(default=None, metadata={"description": "The city information of the remote IP address."})  # fmt: skip
    country: Optional[AwsGuardDutyCountry] = field(default=None, metadata={"description": "The country code of the remote IP address."})  # fmt: skip
    geo_location: Optional[AwsGuardDutyGeoLocation] = field(default=None, metadata={"description": "The location information of the remote IP address."})  # fmt: skip
    ip_address_v4: Optional[str] = field(default=None, metadata={"description": "The IPv4 remote address of the connection."})  # fmt: skip
    ip_address_v6: Optional[str] = field(default=None, metadata={"description": "The IPv6 remote address of the connection."})  # fmt: skip
    organization: Optional[AwsGuardDutyOrganization] = field(default=None, metadata={"description": "The ISP organization information of the remote IP address."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyRemoteAccountDetails:
    kind: ClassVar[str] = "aws_guard_duty_remote_account_details"
    mapping: ClassVar[Dict[str, Bender]] = {"account_id": S("AccountId"), "affiliated": S("Affiliated")}
    account_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account ID of the remote API caller."})  # fmt: skip
    affiliated: Optional[bool] = field(default=None, metadata={"description": "Details on whether the Amazon Web Services account of the remote API caller is related to your GuardDuty environment. If this value is True the API caller is affiliated to your account in some way. If it is False the API caller is from outside your environment."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyAwsApiCallAction:
    kind: ClassVar[str] = "aws_guard_duty_aws_api_call_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "api": S("Api"),
        "caller_type": S("CallerType"),
        "domain_details": S("DomainDetails", "Domain"),
        "error_code": S("ErrorCode"),
        "user_agent": S("UserAgent"),
        "remote_ip_details": S("RemoteIpDetails") >> Bend(AwsGuardDutyRemoteIpDetails.mapping),
        "service_name": S("ServiceName"),
        "remote_account_details": S("RemoteAccountDetails") >> Bend(AwsGuardDutyRemoteAccountDetails.mapping),
        "affected_resources": S("AffectedResources"),
    }
    api: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services API name."})  # fmt: skip
    caller_type: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services API caller type."})  # fmt: skip
    domain_details: Optional[str] = field(default=None, metadata={"description": "The domain information for the Amazon Web Services API call."})  # fmt: skip
    error_code: Optional[str] = field(default=None, metadata={"description": "The error code of the failed Amazon Web Services API action."})  # fmt: skip
    user_agent: Optional[str] = field(default=None, metadata={"description": "The agent through which the API request was made."})  # fmt: skip
    remote_ip_details: Optional[AwsGuardDutyRemoteIpDetails] = field(default=None, metadata={"description": "The remote IP information of the connection that initiated the Amazon Web Services API call."})  # fmt: skip
    service_name: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services service name whose API was invoked."})  # fmt: skip
    remote_account_details: Optional[AwsGuardDutyRemoteAccountDetails] = field(default=None, metadata={"description": "The details of the Amazon Web Services account that made the API call. This field appears if the call was made from outside your account."})  # fmt: skip
    affected_resources: Optional[Dict[str, str]] = field(default=None, metadata={"description": "The details of the Amazon Web Services account that made the API call. This field identifies the resources that were affected by this API call."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyDnsRequestAction:
    kind: ClassVar[str] = "aws_guard_duty_dns_request_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain": S("Domain"),
        "protocol": S("Protocol"),
        "blocked": S("Blocked"),
        "domain_with_suffix": S("DomainWithSuffix"),
    }
    domain: Optional[str] = field(default=None, metadata={"description": "The domain information for the DNS query."})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "The network connection protocol observed in the activity that prompted GuardDuty to generate the finding."})  # fmt: skip
    blocked: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the targeted port is blocked."})  # fmt: skip
    domain_with_suffix: Optional[str] = field(default=None, metadata={"description": "The second and top level domain involved in the activity that potentially prompted GuardDuty to generate this finding. For a list of top-level and second-level domains, see public suffix list."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyLocalPortDetails:
    kind: ClassVar[str] = "aws_guard_duty_local_port_details"
    mapping: ClassVar[Dict[str, Bender]] = {"port": S("Port"), "port_name": S("PortName")}
    port: Optional[int] = field(default=None, metadata={"description": "The port number of the local connection."})  # fmt: skip
    port_name: Optional[str] = field(default=None, metadata={"description": "The port name of the local connection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyLocalIpDetails:
    kind: ClassVar[str] = "aws_guard_duty_local_ip_details"
    mapping: ClassVar[Dict[str, Bender]] = {"ip_address_v4": S("IpAddressV4"), "ip_address_v6": S("IpAddressV6")}
    ip_address_v4: Optional[str] = field(default=None, metadata={"description": "The IPv4 local address of the connection."})  # fmt: skip
    ip_address_v6: Optional[str] = field(default=None, metadata={"description": "The IPv6 local address of the connection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyRemotePortDetails:
    kind: ClassVar[str] = "aws_guard_duty_remote_port_details"
    mapping: ClassVar[Dict[str, Bender]] = {"port": S("Port"), "port_name": S("PortName")}
    port: Optional[int] = field(default=None, metadata={"description": "The port number of the remote connection."})  # fmt: skip
    port_name: Optional[str] = field(default=None, metadata={"description": "The port name of the remote connection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyNetworkConnectionAction:
    kind: ClassVar[str] = "aws_guard_duty_network_connection_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blocked": S("Blocked"),
        "connection_direction": S("ConnectionDirection"),
        "local_port_details": S("LocalPortDetails") >> Bend(AwsGuardDutyLocalPortDetails.mapping),
        "protocol": S("Protocol"),
        "local_ip_details": S("LocalIpDetails") >> Bend(AwsGuardDutyLocalIpDetails.mapping),
        "remote_ip_details": S("RemoteIpDetails") >> Bend(AwsGuardDutyRemoteIpDetails.mapping),
        "remote_port_details": S("RemotePortDetails") >> Bend(AwsGuardDutyRemotePortDetails.mapping),
    }
    blocked: Optional[bool] = field(default=None, metadata={"description": "Indicates whether EC2 blocked the network connection to your instance."})  # fmt: skip
    connection_direction: Optional[str] = field(default=None, metadata={"description": "The network connection direction."})  # fmt: skip
    local_port_details: Optional[AwsGuardDutyLocalPortDetails] = field(default=None, metadata={"description": "The local port information of the connection."})  # fmt: skip
    protocol: Optional[str] = field(default=None, metadata={"description": "The network connection protocol."})  # fmt: skip
    local_ip_details: Optional[AwsGuardDutyLocalIpDetails] = field(default=None, metadata={"description": "The local IP information of the connection."})  # fmt: skip
    remote_ip_details: Optional[AwsGuardDutyRemoteIpDetails] = field(default=None, metadata={"description": "The remote IP information of the connection."})  # fmt: skip
    remote_port_details: Optional[AwsGuardDutyRemotePortDetails] = field(default=None, metadata={"description": "The remote port information of the connection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyPortProbeDetail:
    kind: ClassVar[str] = "aws_guard_duty_port_probe_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "local_port_details": S("LocalPortDetails") >> Bend(AwsGuardDutyLocalPortDetails.mapping),
        "local_ip_details": S("LocalIpDetails") >> Bend(AwsGuardDutyLocalIpDetails.mapping),
        "remote_ip_details": S("RemoteIpDetails") >> Bend(AwsGuardDutyRemoteIpDetails.mapping),
    }
    local_port_details: Optional[AwsGuardDutyLocalPortDetails] = field(default=None, metadata={"description": "The local port information of the connection."})  # fmt: skip
    local_ip_details: Optional[AwsGuardDutyLocalIpDetails] = field(default=None, metadata={"description": "The local IP information of the connection."})  # fmt: skip
    remote_ip_details: Optional[AwsGuardDutyRemoteIpDetails] = field(default=None, metadata={"description": "The remote IP information of the connection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyPortProbeAction:
    kind: ClassVar[str] = "aws_guard_duty_port_probe_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blocked": S("Blocked"),
        "port_probe_details": S("PortProbeDetails", default=[]) >> ForallBend(AwsGuardDutyPortProbeDetail.mapping),
    }
    blocked: Optional[bool] = field(default=None, metadata={"description": "Indicates whether EC2 blocked the port probe to the instance, such as with an ACL."})  # fmt: skip
    port_probe_details: Optional[List[AwsGuardDutyPortProbeDetail]] = field(factory=list, metadata={"description": "A list of objects related to port probe details."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyKubernetesApiCallAction:
    kind: ClassVar[str] = "aws_guard_duty_kubernetes_api_call_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "request_uri": S("RequestUri"),
        "verb": S("Verb"),
        "source_ips": S("SourceIps", default=[]),
        "user_agent": S("UserAgent"),
        "remote_ip_details": S("RemoteIpDetails") >> Bend(AwsGuardDutyRemoteIpDetails.mapping),
        "status_code": S("StatusCode"),
        "parameters": S("Parameters"),
        "resource": S("Resource"),
        "subresource": S("Subresource"),
        "namespace": S("Namespace"),
        "resource_name": S("ResourceName"),
    }
    request_uri: Optional[str] = field(default=None, metadata={"description": "The Kubernetes API request URI."})  # fmt: skip
    verb: Optional[str] = field(default=None, metadata={"description": "The Kubernetes API request HTTP verb."})  # fmt: skip
    source_ips: Optional[List[str]] = field(factory=list, metadata={"description": "The IP of the Kubernetes API caller and the IPs of any proxies or load balancers between the caller and the API endpoint."})  # fmt: skip
    user_agent: Optional[str] = field(default=None, metadata={"description": "The user agent of the caller of the Kubernetes API."})  # fmt: skip
    remote_ip_details: Optional[AwsGuardDutyRemoteIpDetails] = field(default=None, metadata={"description": "Contains information about the remote IP address of the connection."})  # fmt: skip
    status_code: Optional[int] = field(default=None, metadata={"description": "The resulting HTTP response code of the Kubernetes API call action."})  # fmt: skip
    parameters: Optional[str] = field(default=None, metadata={"description": "Parameters related to the Kubernetes API call action."})  # fmt: skip
    resource: Optional[str] = field(default=None, metadata={"description": "The resource component in the Kubernetes API call action."})  # fmt: skip
    subresource: Optional[str] = field(default=None, metadata={"description": "The name of the sub-resource in the Kubernetes API call action."})  # fmt: skip
    namespace: Optional[str] = field(default=None, metadata={"description": "The name of the namespace where the Kubernetes API call action takes place."})  # fmt: skip
    resource_name: Optional[str] = field(default=None, metadata={"description": "The name of the resource in the Kubernetes API call action."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyLoginAttribute:
    kind: ClassVar[str] = "aws_guard_duty_login_attribute"
    mapping: ClassVar[Dict[str, Bender]] = {
        "user": S("User"),
        "application": S("Application"),
        "failed_login_attempts": S("FailedLoginAttempts"),
        "successful_login_attempts": S("SuccessfulLoginAttempts"),
    }
    user: Optional[str] = field(default=None, metadata={"description": "Indicates the user name which attempted to log in."})  # fmt: skip
    application: Optional[str] = field(default=None, metadata={"description": "Indicates the application name used to attempt log in."})  # fmt: skip
    failed_login_attempts: Optional[int] = field(default=None, metadata={"description": "Represents the sum of failed (unsuccessful) login attempts made to establish a connection to the database instance."})  # fmt: skip
    successful_login_attempts: Optional[int] = field(default=None, metadata={"description": "Represents the sum of successful connections (a correct combination of login attributes) made to the database instance by the actor."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyRdsLoginAttemptAction:
    kind: ClassVar[str] = "aws_guard_duty_rds_login_attempt_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "remote_ip_details": S("RemoteIpDetails") >> Bend(AwsGuardDutyRemoteIpDetails.mapping),
        "login_attributes": S("LoginAttributes", default=[]) >> ForallBend(AwsGuardDutyLoginAttribute.mapping),
    }
    remote_ip_details: Optional[AwsGuardDutyRemoteIpDetails] = field(default=None, metadata={"description": "Contains information about the remote IP address of the connection."})  # fmt: skip
    login_attributes: Optional[List[AwsGuardDutyLoginAttribute]] = field(factory=list, metadata={"description": "Indicates the login attributes used in the login attempt."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyKubernetesPermissionCheckedDetails:
    kind: ClassVar[str] = "aws_guard_duty_kubernetes_permission_checked_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "verb": S("Verb"),
        "resource": S("Resource"),
        "namespace": S("Namespace"),
        "allowed": S("Allowed"),
    }
    verb: Optional[str] = field(default=None, metadata={"description": "The verb component of the Kubernetes API call. For example, when you check whether or not you have the permission to call the CreatePod API, the verb component will be Create."})  # fmt: skip
    resource: Optional[str] = field(default=None, metadata={"description": "The Kubernetes resource with which your Kubernetes API call will interact."})  # fmt: skip
    namespace: Optional[str] = field(default=None, metadata={"description": "The namespace where the Kubernetes API action will take place."})  # fmt: skip
    allowed: Optional[bool] = field(default=None, metadata={"description": "Information whether the user has the permission to call the Kubernetes API."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyKubernetesRoleBindingDetails:
    kind: ClassVar[str] = "aws_guard_duty_kubernetes_role_binding_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "role_kind": S("Kind"),
        "name": S("Name"),
        "uid": S("Uid"),
        "role_ref_name": S("RoleRefName"),
        "role_ref_kind": S("RoleRefKind"),
    }
    role_kind: Optional[str] = field(default=None, metadata={"description": "The kind of the role. For role binding, this value will be RoleBinding."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the RoleBinding."})  # fmt: skip
    uid: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the role binding."})  # fmt: skip
    role_ref_name: Optional[str] = field(default=None, metadata={"description": "The name of the role being referenced. This must match the name of the Role or ClusterRole that you want to bind to."})  # fmt: skip
    role_ref_kind: Optional[str] = field(default=None, metadata={"description": "The type of the role being referenced. This could be either Role or ClusterRole."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyKubernetesRoleDetails:
    kind: ClassVar[str] = "aws_guard_duty_kubernetes_role_details"
    mapping: ClassVar[Dict[str, Bender]] = {"role_kind": S("Kind"), "name": S("Name"), "uid": S("Uid")}
    role_kind: Optional[str] = field(default=None, metadata={"description": "The kind of role. For this API, the value of kind will be Role."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the Kubernetes role."})  # fmt: skip
    uid: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the Kubernetes role name."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyAction:
    kind: ClassVar[str] = "aws_guard_duty_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_type": S("ActionType"),
        "aws_api_call_action": S("AwsApiCallAction") >> Bend(AwsGuardDutyAwsApiCallAction.mapping),
        "dns_request_action": S("DnsRequestAction") >> Bend(AwsGuardDutyDnsRequestAction.mapping),
        "network_connection_action": S("NetworkConnectionAction") >> Bend(AwsGuardDutyNetworkConnectionAction.mapping),
        "port_probe_action": S("PortProbeAction") >> Bend(AwsGuardDutyPortProbeAction.mapping),
        "kubernetes_api_call_action": S("KubernetesApiCallAction") >> Bend(AwsGuardDutyKubernetesApiCallAction.mapping),
        "rds_login_attempt_action": S("RdsLoginAttemptAction") >> Bend(AwsGuardDutyRdsLoginAttemptAction.mapping),
        "kubernetes_permission_checked_details": S("KubernetesPermissionCheckedDetails")
        >> Bend(AwsGuardDutyKubernetesPermissionCheckedDetails.mapping),
        "kubernetes_role_binding_details": S("KubernetesRoleBindingDetails")
        >> Bend(AwsGuardDutyKubernetesRoleBindingDetails.mapping),
        "kubernetes_role_details": S("KubernetesRoleDetails") >> Bend(AwsGuardDutyKubernetesRoleDetails.mapping),
    }
    action_type: Optional[str] = field(default=None, metadata={"description": "The GuardDuty finding activity type."})  # fmt: skip
    aws_api_call_action: Optional[AwsGuardDutyAwsApiCallAction] = field(default=None, metadata={"description": "Information about the AWS_API_CALL action described in this finding."})  # fmt: skip
    dns_request_action: Optional[AwsGuardDutyDnsRequestAction] = field(default=None, metadata={"description": "Information about the DNS_REQUEST action described in this finding."})  # fmt: skip
    network_connection_action: Optional[AwsGuardDutyNetworkConnectionAction] = field(default=None, metadata={"description": "Information about the NETWORK_CONNECTION action described in this finding."})  # fmt: skip
    port_probe_action: Optional[AwsGuardDutyPortProbeAction] = field(default=None, metadata={"description": "Information about the PORT_PROBE action described in this finding."})  # fmt: skip
    kubernetes_api_call_action: Optional[AwsGuardDutyKubernetesApiCallAction] = field(default=None, metadata={"description": "Information about the Kubernetes API call action described in this finding."})  # fmt: skip
    rds_login_attempt_action: Optional[AwsGuardDutyRdsLoginAttemptAction] = field(default=None, metadata={"description": "Information about RDS_LOGIN_ATTEMPT action described in this finding."})  # fmt: skip
    kubernetes_permission_checked_details: Optional[AwsGuardDutyKubernetesPermissionCheckedDetails] = field(default=None, metadata={"description": "Information whether the user has the permission to use a specific Kubernetes API."})  # fmt: skip
    kubernetes_role_binding_details: Optional[AwsGuardDutyKubernetesRoleBindingDetails] = field(default=None, metadata={"description": "Information about the role binding that grants the permission defined in a Kubernetes role."})  # fmt: skip
    kubernetes_role_details: Optional[AwsGuardDutyKubernetesRoleDetails] = field(default=None, metadata={"description": "Information about the Kubernetes role name and role type."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyThreatIntelligenceDetail:
    kind: ClassVar[str] = "aws_guard_duty_threat_intelligence_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "threat_list_name": S("ThreatListName"),
        "threat_names": S("ThreatNames", default=[]),
        "threat_file_sha256": S("ThreatFileSha256"),
    }
    threat_list_name: Optional[str] = field(default=None, metadata={"description": "The name of the threat intelligence list that triggered the finding."})  # fmt: skip
    threat_names: Optional[List[str]] = field(factory=list, metadata={"description": "A list of names of the threats in the threat intelligence list that triggered the finding."})  # fmt: skip
    threat_file_sha256: Optional[str] = field(default=None, metadata={"description": "SHA256 of the file that generated the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyEvidence:
    kind: ClassVar[str] = "aws_guard_duty_evidence"
    mapping: ClassVar[Dict[str, Bender]] = {
        "threat_intelligence_details": S("ThreatIntelligenceDetails", default=[])
        >> ForallBend(AwsGuardDutyThreatIntelligenceDetail.mapping)
    }
    threat_intelligence_details: Optional[List[AwsGuardDutyThreatIntelligenceDetail]] = field(factory=list, metadata={"description": "A list of threat intelligence details related to the evidence."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyServiceAdditionalInfo:
    kind: ClassVar[str] = "aws_guard_duty_service_additional_info"
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("Value"), "type": S("Type")}
    value: Optional[str] = field(default=None, metadata={"description": "This field specifies the value of the additional information."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "Describes the type of the additional information."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyScannedItemCount:
    kind: ClassVar[str] = "aws_guard_duty_scanned_item_count"
    mapping: ClassVar[Dict[str, Bender]] = {"total_gb": S("TotalGb"), "files": S("Files"), "volumes": S("Volumes")}
    total_gb: Optional[int] = field(default=None, metadata={"description": "Total GB of files scanned for malware."})  # fmt: skip
    files: Optional[int] = field(default=None, metadata={"description": "Number of files scanned."})  # fmt: skip
    volumes: Optional[int] = field(default=None, metadata={"description": "Total number of scanned volumes."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyHighestSeverityThreatDetails:
    kind: ClassVar[str] = "aws_guard_duty_highest_severity_threat_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "severity": S("Severity"),
        "threat_name": S("ThreatName"),
        "count": S("Count"),
    }
    severity: Optional[str] = field(default=None, metadata={"description": "Severity level of the highest severity threat detected."})  # fmt: skip
    threat_name: Optional[str] = field(default=None, metadata={"description": "Threat name of the highest severity threat detected as part of the malware scan."})  # fmt: skip
    count: Optional[int] = field(default=None, metadata={"description": "Total number of infected files with the highest severity threat detected."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyScanFilePath:
    kind: ClassVar[str] = "aws_guard_duty_scan_file_path"
    mapping: ClassVar[Dict[str, Bender]] = {
        "file_path": S("FilePath"),
        "volume_arn": S("VolumeArn"),
        "hash": S("Hash"),
        "file_name": S("FileName"),
    }
    file_path: Optional[str] = field(default=None, metadata={"description": "The file path of the infected file."})  # fmt: skip
    volume_arn: Optional[str] = field(default=None, metadata={"description": "EBS volume ARN details of the infected file."})  # fmt: skip
    hash: Optional[str] = field(default=None, metadata={"description": "The hash value of the infected file."})  # fmt: skip
    file_name: Optional[str] = field(default=None, metadata={"description": "File name of the infected file."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyScanThreatName:
    kind: ClassVar[str] = "aws_guard_duty_scan_threat_name"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "severity": S("Severity"),
        "item_count": S("ItemCount"),
        "file_paths": S("FilePaths", default=[]) >> ForallBend(AwsGuardDutyScanFilePath.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the identified threat."})  # fmt: skip
    severity: Optional[str] = field(default=None, metadata={"description": "Severity of threat identified as part of the malware scan."})  # fmt: skip
    item_count: Optional[int] = field(default=None, metadata={"description": "Total number of files infected with given threat."})  # fmt: skip
    file_paths: Optional[List[AwsGuardDutyScanFilePath]] = field(factory=list, metadata={"description": "List of infected files in EBS volume with details."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyThreatDetectedByName:
    kind: ClassVar[str] = "aws_guard_duty_threat_detected_by_name"
    mapping: ClassVar[Dict[str, Bender]] = {
        "item_count": S("ItemCount"),
        "unique_threat_name_count": S("UniqueThreatNameCount"),
        "shortened": S("Shortened"),
        "threat_names": S("ThreatNames", default=[]) >> ForallBend(AwsGuardDutyScanThreatName.mapping),
    }
    item_count: Optional[int] = field(default=None, metadata={"description": "Total number of infected files identified."})  # fmt: skip
    unique_threat_name_count: Optional[int] = field(default=None, metadata={"description": "Total number of unique threats by name identified, as part of the malware scan."})  # fmt: skip
    shortened: Optional[bool] = field(default=None, metadata={"description": "Flag to determine if the finding contains every single infected file-path and/or every threat."})  # fmt: skip
    threat_names: Optional[List[AwsGuardDutyScanThreatName]] = field(factory=list, metadata={"description": "List of identified threats with details, organized by threat name."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyScanDetections:
    kind: ClassVar[str] = "aws_guard_duty_scan_detections"
    mapping: ClassVar[Dict[str, Bender]] = {
        "scanned_item_count": S("ScannedItemCount") >> Bend(AwsGuardDutyScannedItemCount.mapping),
        "threats_detected_item_count": S("ThreatsDetectedItemCount", "Files"),
        "highest_severity_threat_details": S("HighestSeverityThreatDetails")
        >> Bend(AwsGuardDutyHighestSeverityThreatDetails.mapping),
        "threat_detected_by_name": S("ThreatDetectedByName") >> Bend(AwsGuardDutyThreatDetectedByName.mapping),
    }
    scanned_item_count: Optional[AwsGuardDutyScannedItemCount] = field(default=None, metadata={"description": "Total number of scanned files."})  # fmt: skip
    threats_detected_item_count: Optional[int] = field(default=None, metadata={"description": "Total number of infected files."})  # fmt: skip
    highest_severity_threat_details: Optional[AwsGuardDutyHighestSeverityThreatDetails] = field(default=None, metadata={"description": "Details of the highest severity threat detected during malware scan and number of infected files."})  # fmt: skip
    threat_detected_by_name: Optional[AwsGuardDutyThreatDetectedByName] = field(default=None, metadata={"description": "Contains details about identified threats organized by threat name."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyEbsVolumeScanDetails:
    kind: ClassVar[str] = "aws_guard_duty_ebs_volume_scan_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "scan_id": S("ScanId"),
        "scan_started_at": S("ScanStartedAt"),
        "scan_completed_at": S("ScanCompletedAt"),
        "trigger_finding_id": S("TriggerFindingId"),
        "sources": S("Sources", default=[]),
        "scan_detections": S("ScanDetections") >> Bend(AwsGuardDutyScanDetections.mapping),
        "scan_type": S("ScanType"),
    }
    scan_id: Optional[str] = field(default=None, metadata={"description": "Unique Id of the malware scan that generated the finding."})  # fmt: skip
    scan_started_at: Optional[datetime] = field(default=None, metadata={"description": "Returns the start date and time of the malware scan."})  # fmt: skip
    scan_completed_at: Optional[datetime] = field(default=None, metadata={"description": "Returns the completion date and time of the malware scan."})  # fmt: skip
    trigger_finding_id: Optional[str] = field(default=None, metadata={"description": "GuardDuty finding ID that triggered a malware scan."})  # fmt: skip
    sources: Optional[List[str]] = field(factory=list, metadata={"description": "Contains list of threat intelligence sources used to detect threats."})  # fmt: skip
    scan_detections: Optional[AwsGuardDutyScanDetections] = field(default=None, metadata={"description": "Contains a complete view providing malware scan result details."})  # fmt: skip
    scan_type: Optional[str] = field(default=None, metadata={"description": "Specifies the scan type that invoked the malware scan."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyLineageObject:
    kind: ClassVar[str] = "aws_guard_duty_lineage_object"
    mapping: ClassVar[Dict[str, Bender]] = {
        "start_time": S("StartTime"),
        "namespace_pid": S("NamespacePid"),
        "user_id": S("UserId"),
        "name": S("Name"),
        "pid": S("Pid"),
        "uuid": S("Uuid"),
        "executable_path": S("ExecutablePath"),
        "euid": S("Euid"),
        "parent_uuid": S("ParentUuid"),
    }
    start_time: Optional[datetime] = field(default=None, metadata={"description": "The time when the process started. This is in UTC format."})  # fmt: skip
    namespace_pid: Optional[int] = field(default=None, metadata={"description": "The process ID of the child process."})  # fmt: skip
    user_id: Optional[int] = field(default=None, metadata={"description": "The user ID of the user that executed the process."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the process."})  # fmt: skip
    pid: Optional[int] = field(default=None, metadata={"description": "The ID of the process."})  # fmt: skip
    uuid: Optional[str] = field(default=None, metadata={"description": "The unique ID assigned to the process by GuardDuty."})  # fmt: skip
    executable_path: Optional[str] = field(default=None, metadata={"description": "The absolute path of the process executable file."})  # fmt: skip
    euid: Optional[int] = field(default=None, metadata={"description": "The effective user ID that was used to execute the process."})  # fmt: skip
    parent_uuid: Optional[str] = field(default=None, metadata={"description": "The unique ID of the parent process. This ID is assigned to the parent process by GuardDuty."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyProcessDetails:
    kind: ClassVar[str] = "aws_guard_duty_process_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "executable_path": S("ExecutablePath"),
        "executable_sha256": S("ExecutableSha256"),
        "namespace_pid": S("NamespacePid"),
        "pwd": S("Pwd"),
        "pid": S("Pid"),
        "start_time": S("StartTime"),
        "uuid": S("Uuid"),
        "parent_uuid": S("ParentUuid"),
        "user": S("User"),
        "user_id": S("UserId"),
        "euid": S("Euid"),
        "lineage": S("Lineage", default=[]) >> ForallBend(AwsGuardDutyLineageObject.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the process."})  # fmt: skip
    executable_path: Optional[str] = field(default=None, metadata={"description": "The absolute path of the process executable file."})  # fmt: skip
    executable_sha256: Optional[str] = field(default=None, metadata={"description": "The SHA256 hash of the process executable."})  # fmt: skip
    namespace_pid: Optional[int] = field(default=None, metadata={"description": "The ID of the child process."})  # fmt: skip
    pwd: Optional[str] = field(default=None, metadata={"description": "The present working directory of the process."})  # fmt: skip
    pid: Optional[int] = field(default=None, metadata={"description": "The ID of the process."})  # fmt: skip
    start_time: Optional[datetime] = field(default=None, metadata={"description": "The time when the process started. This is in UTC format."})  # fmt: skip
    uuid: Optional[str] = field(default=None, metadata={"description": "The unique ID assigned to the process by GuardDuty."})  # fmt: skip
    parent_uuid: Optional[str] = field(default=None, metadata={"description": "The unique ID of the parent process. This ID is assigned to the parent process by GuardDuty."})  # fmt: skip
    user: Optional[str] = field(default=None, metadata={"description": "The user that executed the process."})  # fmt: skip
    user_id: Optional[int] = field(default=None, metadata={"description": "The unique ID of the user that executed the process."})  # fmt: skip
    euid: Optional[int] = field(default=None, metadata={"description": "The effective user ID of the user that executed the process."})  # fmt: skip
    lineage: Optional[List[AwsGuardDutyLineageObject]] = field(factory=list, metadata={"description": "Information about the process's lineage."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyRuntimeContext:
    kind: ClassVar[str] = "aws_guard_duty_runtime_context"
    mapping: ClassVar[Dict[str, Bender]] = {
        "modifying_process": S("ModifyingProcess") >> Bend(AwsGuardDutyProcessDetails.mapping),
        "modified_at": S("ModifiedAt"),
        "script_path": S("ScriptPath"),
        "library_path": S("LibraryPath"),
        "ld_preload_value": S("LdPreloadValue"),
        "socket_path": S("SocketPath"),
        "runc_binary_path": S("RuncBinaryPath"),
        "release_agent_path": S("ReleaseAgentPath"),
        "mount_source": S("MountSource"),
        "mount_target": S("MountTarget"),
        "file_system_type": S("FileSystemType"),
        "flags": S("Flags", default=[]),
        "module_name": S("ModuleName"),
        "module_file_path": S("ModuleFilePath"),
        "module_sha256": S("ModuleSha256"),
        "shell_history_file_path": S("ShellHistoryFilePath"),
        "target_process": S("TargetProcess") >> Bend(AwsGuardDutyProcessDetails.mapping),
        "address_family": S("AddressFamily"),
        "iana_protocol_number": S("IanaProtocolNumber"),
        "memory_regions": S("MemoryRegions", default=[]),
        "tool_name": S("ToolName"),
        "tool_category": S("ToolCategory"),
        "service_name": S("ServiceName"),
        "command_line_example": S("CommandLineExample"),
        "threat_file_path": S("ThreatFilePath"),
    }
    modifying_process: Optional[AwsGuardDutyProcessDetails] = field(default=None, metadata={"description": "Information about the process that modified the current process. This is available for multiple finding types."})  # fmt: skip
    modified_at: Optional[datetime] = field(default=None, metadata={"description": "The timestamp at which the process modified the current process. The timestamp is in UTC date string format."})  # fmt: skip
    script_path: Optional[str] = field(default=None, metadata={"description": "The path to the script that was executed."})  # fmt: skip
    library_path: Optional[str] = field(default=None, metadata={"description": "The path to the new library that was loaded."})  # fmt: skip
    ld_preload_value: Optional[str] = field(default=None, metadata={"description": "The value of the LD_PRELOAD environment variable."})  # fmt: skip
    socket_path: Optional[str] = field(default=None, metadata={"description": "The path to the docket socket that was accessed."})  # fmt: skip
    runc_binary_path: Optional[str] = field(default=None, metadata={"description": "The path to the leveraged runc implementation."})  # fmt: skip
    release_agent_path: Optional[str] = field(default=None, metadata={"description": "The path in the container that modified the release agent file."})  # fmt: skip
    mount_source: Optional[str] = field(default=None, metadata={"description": "The path on the host that is mounted by the container."})  # fmt: skip
    mount_target: Optional[str] = field(default=None, metadata={"description": "The path in the container that is mapped to the host directory."})  # fmt: skip
    file_system_type: Optional[str] = field(default=None, metadata={"description": "Represents the type of mounted fileSystem."})  # fmt: skip
    flags: Optional[List[str]] = field(factory=list, metadata={"description": "Represents options that control the behavior of a runtime operation or action. For example, a filesystem mount operation may contain a read-only flag."})  # fmt: skip
    module_name: Optional[str] = field(default=None, metadata={"description": "The name of the module loaded into the kernel."})  # fmt: skip
    module_file_path: Optional[str] = field(default=None, metadata={"description": "The path to the module loaded into the kernel."})  # fmt: skip
    module_sha256: Optional[str] = field(default=None, metadata={"description": "The SHA256 hash of the module."})  # fmt: skip
    shell_history_file_path: Optional[str] = field(default=None, metadata={"description": "The path to the modified shell history file."})  # fmt: skip
    target_process: Optional[AwsGuardDutyProcessDetails] = field(default=None, metadata={"description": "Information about the process that had its memory overwritten by the current process."})  # fmt: skip
    address_family: Optional[str] = field(default=None, metadata={"description": "Represents the communication protocol associated with the address. For example, the address family AF_INET is used for IP version of 4 protocol."})  # fmt: skip
    iana_protocol_number: Optional[int] = field(default=None, metadata={"description": "Specifies a particular protocol within the address family. Usually there is a single protocol in address families. For example, the address family AF_INET only has the IP protocol."})  # fmt: skip
    memory_regions: Optional[List[str]] = field(factory=list, metadata={"description": "Specifies the Region of a process's address space such as stack and heap."})  # fmt: skip
    tool_name: Optional[str] = field(default=None, metadata={"description": "Name of the potentially suspicious tool."})  # fmt: skip
    tool_category: Optional[str] = field(default=None, metadata={"description": "Category that the tool belongs to. Some of the examples are Backdoor Tool, Pentest Tool, Network Scanner, and Network Sniffer."})  # fmt: skip
    service_name: Optional[str] = field(default=None, metadata={"description": "Name of the security service that has been potentially disabled."})  # fmt: skip
    command_line_example: Optional[str] = field(default=None, metadata={"description": "Example of the command line involved in the suspicious activity."})  # fmt: skip
    threat_file_path: Optional[str] = field(default=None, metadata={"description": "The suspicious file path for which the threat intelligence details were found."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyRuntimeDetails:
    kind: ClassVar[str] = "aws_guard_duty_runtime_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "process": S("Process") >> Bend(AwsGuardDutyProcessDetails.mapping),
        "context": S("Context") >> Bend(AwsGuardDutyRuntimeContext.mapping),
    }
    process: Optional[AwsGuardDutyProcessDetails] = field(default=None, metadata={"description": "Information about the observed process."})  # fmt: skip
    context: Optional[AwsGuardDutyRuntimeContext] = field(default=None, metadata={"description": "Additional information about the suspicious activity."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyAnomalyUnusual:
    kind: ClassVar[str] = "aws_guard_duty_anomaly_unusual"
    mapping: ClassVar[Dict[str, Bender]] = {"behavior": S("Behavior")}
    behavior: Optional[Dict[str, Any]] = field(default=None, metadata={"description": "The behavior of the anomalous activity that caused GuardDuty to generate the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyAnomaly:
    kind: ClassVar[str] = "aws_guard_duty_anomaly"
    mapping: ClassVar[Dict[str, Bender]] = {
        "profiles": S("Profiles"),
        "unusual": S("Unusual") >> Bend(AwsGuardDutyAnomalyUnusual.mapping),
    }
    profiles: Optional[Dict[str, Any]] = field(default=None, metadata={"description": "Information about the types of profiles."})  # fmt: skip
    unusual: Optional[AwsGuardDutyAnomalyUnusual] = field(default=None, metadata={"description": "Information about the behavior of the anomalies."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyDetection:
    kind: ClassVar[str] = "aws_guard_duty_detection"
    mapping: ClassVar[Dict[str, Bender]] = {"anomaly": S("Anomaly") >> Bend(AwsGuardDutyAnomaly.mapping)}
    anomaly: Optional[AwsGuardDutyAnomaly] = field(default=None, metadata={"description": "The details about the anomalous activity that caused GuardDuty to generate the finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyItemPath:
    kind: ClassVar[str] = "aws_guard_duty_item_path"
    mapping: ClassVar[Dict[str, Bender]] = {"nested_item_path": S("NestedItemPath"), "hash": S("Hash")}
    nested_item_path: Optional[str] = field(default=None, metadata={"description": "The nested item path where the infected file was found."})  # fmt: skip
    hash: Optional[str] = field(default=None, metadata={"description": "The hash value of the infected resource."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyThreat:
    kind: ClassVar[str] = "aws_guard_duty_threat"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "source": S("Source"),
        "item_paths": S("ItemPaths", default=[]) >> ForallBend(AwsGuardDutyItemPath.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "Name of the detected threat that caused GuardDuty to generate this finding."})  # fmt: skip
    source: Optional[str] = field(default=None, metadata={"description": "Source of the threat that generated this finding."})  # fmt: skip
    item_paths: Optional[List[AwsGuardDutyItemPath]] = field(factory=list, metadata={"description": "Information about the nested item path and hash of the protected resource."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyMalwareScanDetails:
    kind: ClassVar[str] = "aws_guard_duty_malware_scan_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "threats": S("Threats", default=[]) >> ForallBend(AwsGuardDutyThreat.mapping)
    }
    threats: Optional[List[AwsGuardDutyThreat]] = field(factory=list, metadata={"description": "Information about the detected threats associated with the generated GuardDuty finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyService:
    kind: ClassVar[str] = "aws_guard_duty_service"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action": S("Action") >> Bend(AwsGuardDutyAction.mapping),
        "evidence": S("Evidence") >> Bend(AwsGuardDutyEvidence.mapping),
        "archived": S("Archived"),
        "count": S("Count"),
        "detector_id": S("DetectorId"),
        "event_first_seen": S("EventFirstSeen"),
        "event_last_seen": S("EventLastSeen"),
        "resource_role": S("ResourceRole"),
        "service_name": S("ServiceName"),
        "user_feedback": S("UserFeedback"),
        "additional_info": S("AdditionalInfo") >> Bend(AwsGuardDutyServiceAdditionalInfo.mapping),
        "feature_name": S("FeatureName"),
        "ebs_volume_scan_details": S("EbsVolumeScanDetails") >> Bend(AwsGuardDutyEbsVolumeScanDetails.mapping),
        "runtime_details": S("RuntimeDetails") >> Bend(AwsGuardDutyRuntimeDetails.mapping),
        "detection": S("Detection") >> Bend(AwsGuardDutyDetection.mapping),
        "malware_scan_details": S("MalwareScanDetails") >> Bend(AwsGuardDutyMalwareScanDetails.mapping),
    }
    action: Optional[AwsGuardDutyAction] = field(default=None, metadata={"description": "Information about the activity that is described in a finding."})  # fmt: skip
    evidence: Optional[AwsGuardDutyEvidence] = field(default=None, metadata={"description": "An evidence object associated with the service."})  # fmt: skip
    archived: Optional[bool] = field(default=None, metadata={"description": "Indicates whether this finding is archived."})  # fmt: skip
    count: Optional[int] = field(default=None, metadata={"description": "The total count of the occurrences of this finding type."})  # fmt: skip
    detector_id: Optional[str] = field(default=None, metadata={"description": "The detector ID for the GuardDuty service."})  # fmt: skip
    event_first_seen: Optional[str] = field(default=None, metadata={"description": "The first-seen timestamp of the activity that prompted GuardDuty to generate this finding."})  # fmt: skip
    event_last_seen: Optional[str] = field(default=None, metadata={"description": "The last-seen timestamp of the activity that prompted GuardDuty to generate this finding."})  # fmt: skip
    resource_role: Optional[str] = field(default=None, metadata={"description": "The resource role information for this finding."})  # fmt: skip
    service_name: Optional[str] = field(default=None, metadata={"description": "The name of the Amazon Web Services service (GuardDuty) that generated a finding."})  # fmt: skip
    user_feedback: Optional[str] = field(default=None, metadata={"description": "Feedback that was submitted about the finding."})  # fmt: skip
    additional_info: Optional[AwsGuardDutyServiceAdditionalInfo] = field(default=None, metadata={"description": "Contains additional information about the generated finding."})  # fmt: skip
    feature_name: Optional[str] = field(default=None, metadata={"description": "The name of the feature that generated a finding."})  # fmt: skip
    ebs_volume_scan_details: Optional[AwsGuardDutyEbsVolumeScanDetails] = field(default=None, metadata={"description": "Returns details from the malware scan that created a finding."})  # fmt: skip
    runtime_details: Optional[AwsGuardDutyRuntimeDetails] = field(default=None, metadata={"description": "Information about the process and any required context values for a specific finding"})  # fmt: skip
    detection: Optional[AwsGuardDutyDetection] = field(default=None, metadata={"description": "Contains information about the detected unusual behavior."})  # fmt: skip
    malware_scan_details: Optional[AwsGuardDutyMalwareScanDetails] = field(default=None, metadata={"description": "Returns details from the malware scan that generated a GuardDuty finding."})  # fmt: skip


@define(eq=False, slots=False)
class AwsGuardDutyFinding(AwsResource, PhantomBaseResource):
    kind: ClassVar[str] = "aws_guard_duty_finding"
    _kind_display: ClassVar[str] = "AWS GuardDuty Finding"
    _kind_description: ClassVar[str] = (
        "AWS GuardDuty Finding represents a potential security issue identified by Amazon GuardDuty. "
        "GuardDuty uses machine learning, anomaly detection, and integrated threat intelligence to detect and "
        "alert on suspicious activity in your AWS environment. Findings highlight possible attacks or vulnerabilities "
        "that may require further investigation."
    )
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "log", "group": "management"}
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html"
    _aws_metadata: ClassVar[Dict[str, Any]] = {
        "provider_link_tpl": "https://{region_id}.console.aws.amazon.com/guardduty/home?region={region_id}#/findings?fId={id}&macros=current",
    }
    # api spec defined in `collect_resources`
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "name": S("Title"),
        "mtime": S("UpdatedAt") >> AsInt() >> F(lambda x: utc_str(datetime.fromtimestamp(x, timezone.utc))),
        "ctime": S("CreatedAt") >> AsInt() >> F(lambda x: utc_str(datetime.fromtimestamp(x, timezone.utc))),
        "account_id": S("AccountId"),
        "arn": S("Arn"),
        "confidence": S("Confidence"),
        "description": S("Description"),
        "partition": S("Partition"),
        "finding_region": S("Region"),
        "finding_resource": S("Resource") >> Bend(AwsGuardDutyResource.mapping),
        "schema_version": S("SchemaVersion"),
        "finding_service": S("Service") >> Bend(AwsGuardDutyService.mapping),
        "finding_severity": S("Severity"),
        "title": S("Title"),
        "type": S("Type"),
    }
    account_id: Optional[str] = field(default=None, metadata={"description": "The ID of the account in which the finding was generated."})  # fmt: skip
    confidence: Optional[float] = field(default=None, metadata={"description": "The confidence score for the finding."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of the finding."})  # fmt: skip
    partition: Optional[str] = field(default=None, metadata={"description": "The partition associated with the finding."})  # fmt: skip
    finding_region: Optional[str] = field(default=None, metadata={"description": "The Region where the finding was generated."})  # fmt: skip
    finding_resource: Optional[AwsGuardDutyResource] = field(default=None, metadata={"description": "Contains information about the Amazon Web Services resource associated with the activity that prompted GuardDuty to generate a finding."})  # fmt: skip
    schema_version: Optional[str] = field(default=None, metadata={"description": "The version of the schema used for the finding."})  # fmt: skip
    finding_service: Optional[AwsGuardDutyService] = field(default=None, metadata={"description": "Contains additional information about the generated finding."})  # fmt: skip
    finding_severity: Optional[float] = field(default=None, metadata={"description": "The severity of the finding."})  # fmt: skip
    title: Optional[str] = field(default=None, metadata={"description": "The title of the finding."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of finding."})  # fmt: skip

    @classmethod
    def service_name(cls) -> str:
        return service_name

    @staticmethod
    def set_findings(builder: GraphBuilder, resource_to_set: AwsResource, to_check: str = "id") -> None:
        """
        Set the assessment findings for the resource based on its ID or ARN.
        """
        id_or_arn_or_name = ""

        if to_check == "arn":
            if not resource_to_set.arn:
                return
            id_or_arn_or_name = resource_to_set.arn
        elif to_check == "id":
            id_or_arn_or_name = resource_to_set.id
        elif to_check == "name":
            id_or_arn_or_name = resource_to_set.safe_name
        else:
            return
        provider_findings = builder._assessment_findings.get(
            ("guard_duty", resource_to_set.region().id, resource_to_set.__class__.__name__), {}
        ).get(id_or_arn_or_name, [])
        if provider_findings:
            # Set the findings in the resource's _assessments dictionary
            resource_to_set._assessments.append(Assessment("guard_duty", provider_findings))

    def parse_finding(self, source: Json) -> Finding:
        def get_severity() -> Severity:
            if not self.finding_severity:
                return Severity.medium
            if self.finding_severity <= 2:
                return Severity.info
            elif self.finding_severity <= 4:
                return Severity.low
            elif self.finding_severity <= 6:
                return Severity.medium
            elif self.finding_severity <= 8:
                return Severity.high
            else:
                return Severity.critical

        finding_title = self.safe_name
        if not self.finding_severity:
            finding_severity = Severity.medium
        else:
            finding_severity = get_severity()
        description = self.description
        updated_at = self.mtime
        details = source.get("Service", {})
        return Finding(finding_title, finding_severity, description, None, updated_at, details)

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:

        def check_type_and_adjust_id(
            finding_resource: AwsGuardDutyResource,
        ) -> List[Tuple[str, str]]:
            # To avoid circular imports, defined here
            from fix_plugin_aws.resource.ec2 import AwsEc2Instance, AwsEc2Volume
            from fix_plugin_aws.resource.ecs import AwsEcsCluster
            from fix_plugin_aws.resource.eks import AwsEksCluster
            from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction
            from fix_plugin_aws.resource.rds import AwsRdsCluster, AwsRdsInstance
            from fix_plugin_aws.resource.s3 import AwsS3Bucket

            finding_resources = []
            if finding_resource.s3_bucket_details:
                for s3_bucket_detail in finding_resource.s3_bucket_details:
                    if s3_bucket_detail.name:
                        finding_resources.append((AwsS3Bucket.__name__, s3_bucket_detail.name))

            if finding_resource.instance_details and finding_resource.instance_details.instance_id:
                finding_resources.append((AwsEc2Instance.__name__, finding_resource.instance_details.instance_id))

            if finding_resource.eks_cluster_details and finding_resource.eks_cluster_details.arn:
                finding_resources.append((AwsEksCluster.__name__, finding_resource.eks_cluster_details.arn))

            if finding_resource.ebs_volume_details:
                for vol_detail in finding_resource.ebs_volume_details.scanned_volume_details or []:
                    if vol_detail.volume_arn:
                        finding_resources.append((AwsEc2Volume.__name__, vol_detail.volume_arn))

                for vol_detail in finding_resource.ebs_volume_details.skipped_volume_details or []:
                    if vol_detail.volume_arn:
                        finding_resources.append((AwsEc2Volume.__name__, vol_detail.volume_arn))

            if finding_resource.ecs_cluster_details and finding_resource.ecs_cluster_details.arn:
                finding_resources.append((AwsEcsCluster.__name__, finding_resource.ecs_cluster_details.arn))

            if finding_resource.rds_db_instance_details:
                if finding_resource.rds_db_instance_details.db_instance_identifier:
                    finding_resources.append(
                        (AwsRdsInstance.__name__, finding_resource.rds_db_instance_details.db_instance_identifier)
                    )
                if finding_resource.rds_db_instance_details.db_cluster_identifier:
                    finding_resources.append(
                        (AwsRdsCluster.__name__, finding_resource.rds_db_instance_details.db_cluster_identifier)
                    )

            if finding_resource.lambda_details and finding_resource.lambda_details.function_name:
                finding_resources.append((AwsLambdaFunction.__name__, finding_resource.lambda_details.function_name))

            return finding_resources

        try:
            detector_ids = builder.client.list(service_name, "list-detectors", "DetectorIds")
            finding_id_futures = {
                builder.submit_work(
                    service_name,
                    builder.client.list,
                    service_name,
                    "list-findings",
                    "FindingIds",
                    expected_errors=["BadRequestException"],
                    DetectorId=detector_id,
                ): detector_id
                for detector_id in detector_ids
            }

            for future in as_completed(finding_id_futures):
                detector_id = finding_id_futures[future]
                finding_ids = future.result()
                chunk_futures = []
                for chunk_ids in chunks(finding_ids, 49):
                    future = builder.submit_work(
                        service_name,
                        builder.client.list,
                        service_name,
                        "get-findings",
                        "Findings",
                        expected_errors=["BadRequestException"],
                        DetectorId=detector_id,
                        FindingIds=chunk_ids,
                    )
                    chunk_futures.append(future)

                for chunk_future in as_completed(chunk_futures):
                    findings = chunk_future.result()
                    for finding in findings:
                        if finding.get("AccountId", None) == builder.account.id:
                            if instance := AwsGuardDutyFinding.from_api(finding, builder):
                                if fr := instance.finding_resource:
                                    found_info = check_type_and_adjust_id(fr)
                                    for class_name, id_or_arn_or_name in found_info:
                                        adjusted_finding = instance.parse_finding(finding)
                                        builder.add_finding(
                                            "guard_duty",
                                            class_name,
                                            instance.finding_region or "global",
                                            id_or_arn_or_name,
                                            adjusted_finding,
                                        )
        except Boto3Error as e:
            msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
            builder.core_feedback.error(msg, log)
            raise
        except Exception as e:
            msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
            builder.core_feedback.info(msg, log)
            raise


resources: List[Type[AwsResource]] = [AwsGuardDutyFinding]
