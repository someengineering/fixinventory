from concurrent.futures import as_completed
from datetime import datetime, timezone
from functools import partial
from typing import ClassVar, Dict, List, Optional, Tuple, Type, Any
import logging

from attrs import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder
from fix_plugin_aws.resource.ec2 import AwsEc2Instance, AwsEc2Volume
from fix_plugin_aws.resource.ecs import AwsEcsCluster
from fix_plugin_aws.resource.eks import AwsEksCluster
from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction
from fix_plugin_aws.resource.rds import AwsRdsCluster, AwsRdsInstance
from fix_plugin_aws.resource.s3 import AwsS3Bucket

from fixlib.baseresources import Finding, PhantomBaseResource, Severity
from fixlib.json_bender import F, S, AsInt, Bend, Bender, ForallBend
from fixlib.types import Json
from fixlib.utils import chunks, utc_str

log = logging.getLogger("fix.plugins.aws")
service_name = "guardduty"
amazon_guardduty = "amazon_guard_duty"


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
class AwsGuardDutyFinding(AwsResource, PhantomBaseResource):
    kind: ClassVar[str] = "aws_guard_duty_finding"
    _model_export: ClassVar[bool] = False  # do not export this class, since there will be no instances of it
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
        "finding_severity": S("Severity"),
        "title": S("Title"),
        "type": S("Type"),
        # available but not used property:
        # "finding_service": S("Service"),
    }
    account_id: Optional[str] = field(default=None, metadata={"description": "The ID of the account in which the finding was generated."})  # fmt: skip
    confidence: Optional[float] = field(default=None, metadata={"description": "The confidence score for the finding."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of the finding."})  # fmt: skip
    partition: Optional[str] = field(default=None, metadata={"description": "The partition associated with the finding."})  # fmt: skip
    finding_region: Optional[str] = field(default=None, metadata={"description": "The Region where the finding was generated."})  # fmt: skip
    finding_resource: Optional[AwsGuardDutyResource] = field(default=None, metadata={"description": "Contains information about the Amazon Web Services resource associated with the activity that prompted GuardDuty to generate a finding."})  # fmt: skip
    schema_version: Optional[str] = field(default=None, metadata={"description": "The version of the schema used for the finding."})  # fmt: skip
    finding_severity: Optional[float] = field(default=None, metadata={"description": "The severity of the finding."})  # fmt: skip
    title: Optional[str] = field(default=None, metadata={"description": "The title of the finding."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of finding."})  # fmt: skip

    @classmethod
    def service_name(cls) -> str:
        return service_name

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
        finding_severity = get_severity()
        description = self.description
        updated_at = self.mtime
        details = source.get("Service", {})
        return Finding(finding_title, finding_severity, description, None, updated_at, details)

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:

        def check_type_and_adjust_id(
            finding_resource: AwsGuardDutyResource,
        ) -> List[Tuple[Type[Any], Dict[str, Any]]]:

            finding_resources: List[Tuple[Type[AwsResource], Dict[str, Any]]] = []
            if finding_resource.s3_bucket_details:
                for s3_bucket_detail in finding_resource.s3_bucket_details:
                    if s3_bucket_detail.name:
                        finding_resources.append((AwsS3Bucket, {"name": s3_bucket_detail.name}))

            if finding_resource.instance_details and finding_resource.instance_details.instance_id:
                finding_resources.append((AwsEc2Instance, {"id": finding_resource.instance_details.instance_id}))

            if finding_resource.eks_cluster_details and finding_resource.eks_cluster_details.arn:
                finding_resources.append((AwsEksCluster, {"arn": finding_resource.eks_cluster_details.arn}))

            if finding_resource.ebs_volume_details:
                for vol_detail in finding_resource.ebs_volume_details.scanned_volume_details or []:
                    if vol_detail.volume_arn:
                        finding_resources.append((AwsEc2Volume, {"arn": vol_detail.volume_arn}))

                for vol_detail in finding_resource.ebs_volume_details.skipped_volume_details or []:
                    if vol_detail.volume_arn:
                        finding_resources.append((AwsEc2Volume, {"arn": vol_detail.volume_arn}))

            if finding_resource.ecs_cluster_details and finding_resource.ecs_cluster_details.arn:
                finding_resources.append((AwsEcsCluster, {"arn": finding_resource.ecs_cluster_details.arn}))

            if finding_resource.rds_db_instance_details:
                if finding_resource.rds_db_instance_details.db_instance_identifier:
                    finding_resources.append(
                        (AwsRdsInstance, {"id": finding_resource.rds_db_instance_details.db_instance_identifier})
                    )
                if finding_resource.rds_db_instance_details.db_cluster_identifier:
                    finding_resources.append(
                        (AwsRdsCluster, {"id": finding_resource.rds_db_instance_details.db_cluster_identifier})
                    )

            if finding_resource.lambda_details and finding_resource.lambda_details.function_name:
                finding_resources.append((AwsLambdaFunction, {"name": finding_resource.lambda_details.function_name}))

            return finding_resources

        def add_finding(
            provider: str, finding: Finding, clazz: Optional[Type[AwsResource]] = None, **node: Any
        ) -> None:
            if resource := builder.node(clazz=clazz, **node):
                resource.add_finding(provider, finding)

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
                    FindingCriteria={"Criterion": {"accountId": {"Eq": [builder.account.id]}}},
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
                        if instance := AwsGuardDutyFinding.from_api(finding, builder):
                            if fr := instance.finding_resource:
                                found_info = check_type_and_adjust_id(fr)
                                for clazz, res_filter in found_info:
                                    builder.after_collect_actions.append(
                                        partial(
                                            add_finding,
                                            amazon_guardduty,
                                            instance.parse_finding(finding),
                                            clazz,
                                            **res_filter,
                                        )
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
