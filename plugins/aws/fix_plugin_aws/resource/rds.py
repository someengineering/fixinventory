from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Type, Any

from attr import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchQuery,
    AwsCloudwatchMetricData,
    update_resource_metrics,
)
from fix_plugin_aws.utils import MetricNormalization
from fix_plugin_aws.resource.ec2 import AwsEc2SecurityGroup, AwsEc2Subnet, AwsEc2Vpc
from fix_plugin_aws.resource.kinesis import AwsKinesisStream
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.utils import ToDict, TagsValue
from fixlib.baseresources import BaseDatabase, MetricName, MetricUnit, ModelReference, BaseSnapshot
from fixlib.graph import Graph
from fixlib.json_bender import F, K, S, Bend, Bender, ForallBend, bend
from fixlib.types import Json
from fixlib.utils import utc

service_name = "rds"


# noinspection PyUnresolvedReferences
class RdsTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="add-tags-to-resource",
                    result_name=None,
                    ResourceName=self.arn,
                    Tags=[{"Key": key, "Value": value}],
                )
                return True
            return False
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="remove-tags-from-resource",
                    result_name=None,
                    ResourceName=self.arn,
                    TagKeys=[key],
                )
                return True
            return False
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "add-tags-to-resource"), AwsApiSpec(service_name, "remove-tags-from-resource")]


@define(eq=False, slots=False)
class AwsRdsEndpoint:
    kind: ClassVar[str] = "aws_rds_endpoint"
    kind_display: ClassVar[str] = "AWS RDS Endpoint"
    kind_description: ClassVar[str] = (
        "An RDS Endpoint in AWS is the network address that applications use to"
        " connect to a database instance in the Amazon Relational Database Service"
        " (RDS). It allows users to access and interact with their database instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "address": S("Address"),
        "port": S("Port"),
        "hosted_zone_id": S("HostedZoneId"),
    }
    address: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    hosted_zone_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBSecurityGroupMembership:
    kind: ClassVar[str] = "aws_rds_db_security_group_membership"
    kind_display: ClassVar[str] = "AWS RDS DB Security Group Membership"
    kind_description: ClassVar[str] = (
        "AWS RDS DB Security Group Membership is a resource that represents the"
        " membership of an Amazon RDS database instance in a security group. It allows"
        " controlling access to the database instance by defining inbound and outbound"
        " rules for the security group."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"db_security_group_name": S("DBSecurityGroupName"), "status": S("Status")}
    db_security_group_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsVpcSecurityGroupMembership:
    kind: ClassVar[str] = "aws_rds_vpc_security_group_membership"
    kind_display: ClassVar[str] = "AWS RDS VPC Security Group Membership"
    kind_description: ClassVar[str] = (
        "AWS RDS VPC Security Group Membership represents the group membership of an"
        " Amazon RDS instance in a Virtual Private Cloud (VPC). It controls the"
        " inbound and outbound traffic for the RDS instance within the VPC."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"vpc_security_group_id": S("VpcSecurityGroupId"), "status": S("Status")}
    vpc_security_group_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBParameterGroupStatus:
    kind: ClassVar[str] = "aws_rds_db_parameter_group_status"
    kind_display: ClassVar[str] = "AWS RDS DB Parameter Group Status"
    kind_description: ClassVar[str] = (
        "The status of a parameter group in Amazon RDS, which is a collection of"
        " database engine parameter values that can be applied to one or more DB"
        " instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "db_parameter_group_name": S("DBParameterGroupName"),
        "parameter_apply_status": S("ParameterApplyStatus"),
    }
    db_parameter_group_name: Optional[str] = field(default=None)
    parameter_apply_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsSubnet:
    kind: ClassVar[str] = "aws_rds_subnet"
    kind_display: ClassVar[str] = "AWS RDS Subnet"
    kind_description: ClassVar[str] = (
        "RDS Subnet refers to a network subnet in the Amazon Relational Database"
        " Service (RDS), which is used to isolate and manage database instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "subnet_identifier": S("SubnetIdentifier"),
        "subnet_availability_zone": S("SubnetAvailabilityZone", "Name"),
        "subnet_outpost": S("SubnetOutpost", "Arn"),
        "subnet_status": S("SubnetStatus"),
    }
    subnet_identifier: Optional[str] = field(default=None)
    subnet_availability_zone: Optional[str] = field(default=None)
    subnet_outpost: Optional[str] = field(default=None)
    subnet_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBSubnetGroup:
    kind: ClassVar[str] = "aws_rds_db_subnet_group"
    kind_display: ClassVar[str] = "AWS RDS DB Subnet Group"
    kind_description: ClassVar[str] = (
        "DB Subnet Groups are used to specify the VPC subnets where Amazon RDS DB instances are created."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "db_subnet_group_name": S("DBSubnetGroupName"),
        "db_subnet_group_description": S("DBSubnetGroupDescription"),
        "vpc_id": S("VpcId"),
        "subnet_group_status": S("SubnetGroupStatus"),
        "subnets": S("Subnets", default=[]) >> ForallBend(AwsRdsSubnet.mapping),
        "db_subnet_group_arn": S("DBSubnetGroupArn"),
        "supported_network_types": S("SupportedNetworkTypes", default=[]),
    }
    db_subnet_group_name: Optional[str] = field(default=None)
    db_subnet_group_description: Optional[str] = field(default=None)
    vpc_id: Optional[str] = field(default=None)
    subnet_group_status: Optional[str] = field(default=None)
    subnets: List[AwsRdsSubnet] = field(factory=list)
    db_subnet_group_arn: Optional[str] = field(default=None)
    supported_network_types: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsRdsPendingCloudwatchLogsExports:
    kind: ClassVar[str] = "aws_rds_pending_cloudwatch_logs_exports"
    kind_display: ClassVar[str] = "AWS RDS Pending CloudWatch Logs Exports"
    kind_description: ClassVar[str] = (
        "AWS RDS Pending CloudWatch Logs Exports configuration manages the pending changes to"
        " the log types that are enabled or disabled for export to CloudWatch Logs for an RDS"
        " instance, providing control over which logs are actively monitored and which are not."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "log_types_to_enable": S("LogTypesToEnable", default=[]),
        "log_types_to_disable": S("LogTypesToDisable", default=[]),
    }
    log_types_to_enable: List[str] = field(factory=list)
    log_types_to_disable: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsRdsProcessorFeature:
    kind: ClassVar[str] = "aws_rds_processor_feature"
    kind_display: ClassVar[str] = "AWS RDS Processor Feature"
    kind_description: ClassVar[str] = (
        "RDS Processor Features are customizable settings for processor performance"
        " in Amazon Relational Database Service, allowing users to modify processor"
        " functionalities based on their specific requirements."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "value": S("Value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsPendingModifiedValues:
    kind: ClassVar[str] = "aws_rds_pending_modified_values"
    kind_display: ClassVar[str] = "AWS RDS Pending Modified Values"
    kind_description: ClassVar[str] = (
        "RDS Pending Modified Values represent the changes that are pending to be"
        " applied to an RDS instance, such as changes to its database engine version"
        " or storage capacity."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "db_instance_class": S("DBInstanceClass"),
        "allocated_storage": S("AllocatedStorage"),
        "master_user_password": S("MasterUserPassword"),
        "port": S("Port"),
        "backup_retention_period": S("BackupRetentionPeriod"),
        "multi_az": S("MultiAZ"),
        "engine_version": S("EngineVersion"),
        "license_model": S("LicenseModel"),
        "iops": S("Iops"),
        "db_instance_identifier": S("DBInstanceIdentifier"),
        "storage_type": S("StorageType"),
        "ca_certificate_identifier": S("CACertificateIdentifier"),
        "db_subnet_group_name": S("DBSubnetGroupName"),
        "pending_cloudwatch_logs_exports": S("PendingCloudwatchLogsExports")
        >> Bend(AwsRdsPendingCloudwatchLogsExports.mapping),
        "processor_features": S("ProcessorFeatures", default=[]) >> ForallBend(AwsRdsProcessorFeature.mapping),
        "iam_database_authentication_enabled": S("IAMDatabaseAuthenticationEnabled"),
        "automation_mode": S("AutomationMode"),
        "resume_full_automation_mode_time": S("ResumeFullAutomationModeTime"),
    }
    db_instance_class: Optional[str] = field(default=None)
    allocated_storage: Optional[int] = field(default=None)
    master_user_password: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    backup_retention_period: Optional[int] = field(default=None)
    multi_az: Optional[bool] = field(default=None)
    engine_version: Optional[str] = field(default=None)
    license_model: Optional[str] = field(default=None)
    iops: Optional[int] = field(default=None)
    db_instance_identifier: Optional[str] = field(default=None)
    storage_type: Optional[str] = field(default=None)
    ca_certificate_identifier: Optional[str] = field(default=None)
    db_subnet_group_name: Optional[str] = field(default=None)
    pending_cloudwatch_logs_exports: Optional[AwsRdsPendingCloudwatchLogsExports] = field(default=None)
    processor_features: List[AwsRdsProcessorFeature] = field(factory=list)
    iam_database_authentication_enabled: Optional[bool] = field(default=None)
    automation_mode: Optional[str] = field(default=None)
    resume_full_automation_mode_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsOptionGroupMembership:
    kind: ClassVar[str] = "aws_rds_option_group_membership"
    kind_display: ClassVar[str] = "AWS RDS Option Group Membership"
    kind_description: ClassVar[str] = (
        "RDS Option Group Memberships are used to associate DB instances with option"
        " groups which contain a list of configurable options for the database engine."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"option_group_name": S("OptionGroupName"), "status": S("Status")}
    option_group_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBInstanceStatusInfo:
    kind: ClassVar[str] = "aws_rds_db_instance_status_info"
    kind_display: ClassVar[str] = "AWS RDS DB Instance Status Info"
    kind_description: ClassVar[str] = (
        "RDS DB Instance Status Info provides information about the status of an"
        " Amazon RDS database instance, including its current state and any pending"
        " actions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "status_type": S("StatusType"),
        "normal": S("Normal"),
        "status": S("Status"),
        "message": S("Message"),
    }
    status_type: Optional[str] = field(default=None)
    normal: Optional[bool] = field(default=None)
    status: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDomainMembership:
    kind: ClassVar[str] = "aws_rds_domain_membership"
    kind_display: ClassVar[str] = "AWS RDS Domain Membership"
    kind_description: ClassVar[str] = (
        "RDS Domain Membership is a feature in Amazon RDS that allows you to join an"
        " Amazon RDS DB instance to an existing Microsoft Active Directory domain."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain": S("Domain"),
        "status": S("Status"),
        "fqdn": S("FQDN"),
        "iam_role_name": S("IAMRoleName"),
    }
    domain: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    fqdn: Optional[str] = field(default=None)
    iam_role_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBRole:
    kind: ClassVar[str] = "aws_rds_db_role"
    kind_display: ClassVar[str] = "AWS RDS DB Role"
    kind_description: ClassVar[str] = (
        "The AWS RDS DB Role configuration associates an AWS Identity and Access Management (IAM) role"
        " with an Amazon RDS DB instance to provide access to AWS features and services specified by"
        " the feature name."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "role_arn": S("RoleArn"),
        "feature_name": S("FeatureName"),
        "status": S("Status"),
    }
    role_arn: Optional[str] = field(default=None)
    feature_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsInstance(RdsTaggable, AwsResource, BaseDatabase):
    kind: ClassVar[str] = "aws_rds_instance"
    kind_display: ClassVar[str] = "AWS RDS Instance"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/rds/home?region={region}#database:id={id};is-cluster=false", "arn_tpl": "arn:{partition}:rds:{region}:{account}:db:{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "RDS instances are managed relational databases in Amazon's cloud, providing"
        " scalable and fast performance for applications."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-db-instances", "DBInstances")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_vpc", "aws_ec2_security_group", "aws_ec2_subnet"],
            "delete": ["aws_vpc", "aws_ec2_security_group", "aws_ec2_subnet", "aws_kms_key"],
        },
        "successors": {"default": ["aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("DBInstanceIdentifier"),
        "tags": S("TagList", default=[]) >> ToDict(),
        "name": S("DBName"),
        "ctime": S("InstanceCreateTime"),
        "arn": S("DBInstanceArn"),
        "db_type": S("Engine"),
        "db_status": S("DBInstanceStatus"),
        "db_endpoint": S("Endpoint", "Address") + K(":") + (S("Endpoint", "Port") >> F(str)),
        "db_version": S("EngineVersion"),
        "db_publicly_accessible": S("PubliclyAccessible"),
        "instance_type": S("DBInstanceClass"),
        "volume_size": S("AllocatedStorage"),
        "volume_iops": S("Iops"),
        "volume_encrypted": S("StorageEncrypted"),
        "rds_automatic_restart_time": S("AutomaticRestartTime"),
        "rds_master_username": S("MasterUsername"),
        "rds_preferred_backup_window": S("PreferredBackupWindow"),
        "rds_backup_retention_period": S("BackupRetentionPeriod"),
        "rds_db_security_groups": S("DBSecurityGroups", default=[])
        >> ForallBend(AwsRdsDBSecurityGroupMembership.mapping),
        "rds_vpc_security_groups": S("VpcSecurityGroups", default=[])
        >> ForallBend(AwsRdsVpcSecurityGroupMembership.mapping),
        "rds_db_parameter_groups": S("DBParameterGroups", default=[])
        >> ForallBend(AwsRdsDBParameterGroupStatus.mapping),
        "rds_availability_zone": S("AvailabilityZone"),
        "rds_db_subnet_group": S("DBSubnetGroup") >> Bend(AwsRdsDBSubnetGroup.mapping),
        "rds_preferred_maintenance_window": S("PreferredMaintenanceWindow"),
        "rds_pending_modified_values": S("PendingModifiedValues") >> Bend(AwsRdsPendingModifiedValues.mapping),
        "rds_latest_restorable_time": S("LatestRestorableTime"),
        "rds_multi_az": S("MultiAZ"),
        "rds_auto_minor_version_upgrade": S("AutoMinorVersionUpgrade"),
        "rds_read_replica_source_db_instance_identifier": S("ReadReplicaSourceDBInstanceIdentifier"),
        "rds_read_replica_db_instance_identifiers": S("ReadReplicaDBInstanceIdentifiers", default=[]),
        "rds_read_replica_db_cluster_identifiers": S("ReadReplicaDBClusterIdentifiers", default=[]),
        "rds_replica_mode": S("ReplicaMode"),
        "rds_license_model": S("LicenseModel"),
        "rds_option_group_memberships": S("OptionGroupMemberships", default=[])
        >> ForallBend(AwsRdsOptionGroupMembership.mapping),
        "rds_character_set_name": S("CharacterSetName"),
        "rds_nchar_character_set_name": S("NcharCharacterSetName"),
        "rds_secondary_availability_zone": S("SecondaryAvailabilityZone"),
        "rds_status_infos": S("StatusInfos", default=[]) >> ForallBend(AwsRdsDBInstanceStatusInfo.mapping),
        "rds_storage_type": S("StorageType"),
        "rds_tde_credential_arn": S("TdeCredentialArn"),
        "rds_db_instance_port": S("DbInstancePort"),
        "rds_db_cluster_identifier": S("DBClusterIdentifier"),
        "rds_kms_key_id": S("KmsKeyId"),
        "rds_dbi_resource_id": S("DbiResourceId"),
        "rds_ca_certificate_identifier": S("CACertificateIdentifier"),
        "rds_domain_memberships": S("DomainMemberships", default=[]) >> ForallBend(AwsRdsDomainMembership.mapping),
        "rds_copy_tags_to_snapshot": S("CopyTagsToSnapshot"),
        "rds_monitoring_interval": S("MonitoringInterval"),
        "rds_enhanced_monitoring_resource_arn": S("EnhancedMonitoringResourceArn"),
        "rds_monitoring_role_arn": S("MonitoringRoleArn"),
        "rds_promotion_tier": S("PromotionTier"),
        "rds_timezone": S("Timezone"),
        "rds_iam_database_authentication_enabled": S("IAMDatabaseAuthenticationEnabled"),
        "rds_performance_insights_enabled": S("PerformanceInsightsEnabled"),
        "rds_performance_insights_kms_key_id": S("PerformanceInsightsKMSKeyId"),
        "rds_performance_insights_retention_period": S("PerformanceInsightsRetentionPeriod"),
        "rds_enabled_cloudwatch_logs_exports": S("EnabledCloudwatchLogsExports", default=[]),
        "rds_processor_features": S("ProcessorFeatures", default=[]) >> ForallBend(AwsRdsProcessorFeature.mapping),
        "rds_deletion_protection": S("DeletionProtection"),
        "rds_associated_roles": S("AssociatedRoles", default=[]) >> ForallBend(AwsRdsDBRole.mapping),
        "rds_listener_endpoint": S("ListenerEndpoint") >> Bend(AwsRdsEndpoint.mapping),
        "rds_max_allocated_storage": S("MaxAllocatedStorage"),
        "rds_db_instance_automated_backups_replications": S("DBInstanceAutomatedBackupsReplications", default=[])
        >> ForallBend(S("DBInstanceAutomatedBackupsArn")),
        "rds_customer_owned_ip_enabled": S("CustomerOwnedIpEnabled"),
        "rds_aws_backup_recovery_point_arn": S("AwsBackupRecoveryPointArn"),
        "rds_activity_stream_status": S("ActivityStreamStatus"),
        "rds_activity_stream_kms_key_id": S("ActivityStreamKmsKeyId"),
        "rds_activity_stream_kinesis_stream_name": S("ActivityStreamKinesisStreamName"),
        "rds_activity_stream_mode": S("ActivityStreamMode"),
        "rds_activity_stream_engine_native_audit_fields_included": S("ActivityStreamEngineNativeAuditFieldsIncluded"),
        "rds_automation_mode": S("AutomationMode"),
        "rds_resume_full_automation_mode_time": S("ResumeFullAutomationModeTime"),
        "rds_custom_iam_instance_profile": S("CustomIamInstanceProfile"),
        "rds_backup_target": S("BackupTarget"),
        "rds_network_type": S("NetworkType"),
    }
    rds_automatic_restart_time: Optional[datetime] = field(default=None)
    rds_master_username: Optional[str] = field(default=None)
    rds_preferred_backup_window: Optional[str] = field(default=None)
    rds_backup_retention_period: Optional[int] = field(default=None)
    rds_db_security_groups: List[AwsRdsDBSecurityGroupMembership] = field(factory=list)
    rds_vpc_security_groups: List[AwsRdsVpcSecurityGroupMembership] = field(factory=list)
    rds_db_parameter_groups: List[AwsRdsDBParameterGroupStatus] = field(factory=list)
    rds_availability_zone: Optional[str] = field(default=None)
    rds_db_subnet_group: Optional[AwsRdsDBSubnetGroup] = field(default=None)
    rds_preferred_maintenance_window: Optional[str] = field(default=None)
    rds_pending_modified_values: Optional[AwsRdsPendingModifiedValues] = field(default=None)
    rds_latest_restorable_time: Optional[datetime] = field(default=None)
    rds_multi_az: Optional[bool] = field(default=None)
    rds_auto_minor_version_upgrade: Optional[bool] = field(default=None)
    rds_read_replica_source_db_instance_identifier: Optional[str] = field(default=None)
    rds_read_replica_db_instance_identifiers: List[str] = field(factory=list)
    rds_read_replica_db_cluster_identifiers: List[str] = field(factory=list)
    rds_replica_mode: Optional[str] = field(default=None)
    rds_license_model: Optional[str] = field(default=None)
    rds_option_group_memberships: List[AwsRdsOptionGroupMembership] = field(factory=list)
    rds_character_set_name: Optional[str] = field(default=None)
    rds_nchar_character_set_name: Optional[str] = field(default=None)
    rds_secondary_availability_zone: Optional[str] = field(default=None)
    rds_status_infos: List[AwsRdsDBInstanceStatusInfo] = field(factory=list)
    rds_storage_type: Optional[str] = field(default=None)
    rds_tde_credential_arn: Optional[str] = field(default=None)
    rds_db_instance_port: Optional[int] = field(default=None)
    rds_db_cluster_identifier: Optional[str] = field(default=None)
    rds_kms_key_id: Optional[str] = field(default=None)
    rds_dbi_resource_id: Optional[str] = field(default=None)
    rds_ca_certificate_identifier: Optional[str] = field(default=None)
    rds_domain_memberships: List[AwsRdsDomainMembership] = field(factory=list)
    rds_copy_tags_to_snapshot: Optional[bool] = field(default=None)
    rds_monitoring_interval: Optional[int] = field(default=None)
    rds_enhanced_monitoring_resource_arn: Optional[str] = field(default=None)
    rds_monitoring_role_arn: Optional[str] = field(default=None)
    rds_promotion_tier: Optional[int] = field(default=None)
    rds_timezone: Optional[str] = field(default=None)
    rds_iam_database_authentication_enabled: Optional[bool] = field(default=None)
    rds_performance_insights_enabled: Optional[bool] = field(default=None)
    rds_performance_insights_kms_key_id: Optional[str] = field(default=None)
    rds_performance_insights_retention_period: Optional[int] = field(default=None)
    rds_enabled_cloudwatch_logs_exports: List[str] = field(factory=list)
    rds_processor_features: List[AwsRdsProcessorFeature] = field(factory=list)
    rds_deletion_protection: Optional[bool] = field(default=None)
    rds_associated_roles: List[AwsRdsDBRole] = field(factory=list)
    rds_listener_endpoint: Optional[AwsRdsEndpoint] = field(default=None)
    rds_max_allocated_storage: Optional[int] = field(default=None)
    rds_db_instance_automated_backups_replications: List[str] = field(factory=list)
    rds_customer_owned_ip_enabled: Optional[bool] = field(default=None)
    rds_aws_backup_recovery_point_arn: Optional[str] = field(default=None)
    rds_activity_stream_status: Optional[str] = field(default=None)
    rds_activity_stream_kms_key_id: Optional[str] = field(default=None)
    rds_activity_stream_kinesis_stream_name: Optional[str] = field(default=None)
    rds_activity_stream_mode: Optional[str] = field(default=None)
    rds_activity_stream_engine_native_audit_fields_included: Optional[bool] = field(default=None)
    rds_automation_mode: Optional[str] = field(default=None)
    rds_resume_full_automation_mode_time: Optional[datetime] = field(default=None)
    rds_custom_iam_instance_profile: Optional[str] = field(default=None)
    rds_backup_target: Optional[str] = field(default=None)
    rds_network_type: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(cls.api_spec.service, "list-tags-for-resource")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(rds: AwsRdsInstance) -> None:
            tags = builder.client.list(service_name, "list-tags-for-resource", "TagList", ResourceName=rds.arn)
            if tags:
                rds.tags = bend(ToDict(), tags)

        instances: List[AwsRdsInstance] = []

        def update_atime_mtime() -> None:
            delta = builder.config.atime_mtime_granularity()
            queries = []
            now = utc()
            start = now - builder.config.atime_mtime_period()
            lookup: Dict[str, AwsRdsInstance] = {}
            for rds in instances:
                vid = rds.id
                lookup[vid] = rds
                queries.append(
                    AwsCloudwatchQuery.create("DatabaseConnections", "AWS/RDS", delta, vid, DBInstanceIdentifier=vid)
                )

            for query, metric in AwsCloudwatchMetricData.query_for(builder, queries, start, now).items():
                if non_zero := metric.first_non_zero():
                    at, value = non_zero
                    rds = lookup[query.ref_id]
                    rds.atime = at
                    rds.mtime = at
                    lookup.pop(query.ref_id, None)

            # all volumes in this list do not have value in cloudwatch
            # fall back to either ctime or start time whatever is more recent.
            for rds in lookup.values():
                t = max(rds.ctime or start, start)
                rds.atime = t
                rds.mtime = t

        for js in json:
            if instance := AwsRdsInstance.from_api(js, builder):
                instances.append(instance)
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)
        update_atime_mtime()

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for group in self.rds_vpc_security_groups:
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=AwsEc2SecurityGroup,
                id=group.vpc_security_group_id,
            )
        if self.rds_db_subnet_group and self.rds_db_subnet_group.vpc_id:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=self.rds_db_subnet_group.vpc_id
            )
        if self.rds_db_subnet_group:
            for subnet in self.rds_db_subnet_group.subnets:
                subnet_id = subnet.subnet_identifier
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet_id
                )
        potential_keys = [
            self.rds_kms_key_id,
            self.rds_performance_insights_kms_key_id,
            self.rds_activity_stream_kms_key_id,
        ]
        keys = [key for key in potential_keys if key]
        for key_reference in keys:
            builder.dependant_node(from_node=self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(key_reference))

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-db-instance",
            result_name=None,
            DBInstanceIdentifier=self.id,
            SkipFinalSnapshot=True,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-db-instance")]

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        rds_instances = {
            instance.id: instance
            for instance in builder.nodes(clazz=AwsRdsInstance)
            if instance.region().id == builder.region.id
        }
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at

        for instance_id in rds_instances:
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="CPUUtilization",
                        namespace="AWS/RDS",
                        period=delta,
                        ref_id=instance_id,
                        stat=stat,
                        unit="Percent",
                        DBInstanceIdentifier=instance_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/RDS",
                        period=delta,
                        ref_id=instance_id,
                        stat=stat,
                        unit="Count",
                        DBInstanceIdentifier=instance_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for name in ["DatabaseConnections", "ReadIOPS", "WriteIOPS", "DiskQueueDepth"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/RDS",
                        period=delta,
                        ref_id=instance_id,
                        stat=stat,
                        unit="Seconds",
                        DBInstanceIdentifier=instance_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for name in ["ReadLatency", "WriteLatency"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/RDS",
                        period=delta,
                        ref_id=instance_id,
                        stat=stat,
                        unit="Bytes",
                        DBInstanceIdentifier=instance_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for name in ["FreeableMemory", "FreeStorageSpace", "SwapUsage"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/RDS",
                        period=delta,
                        ref_id=instance_id,
                        stat=stat,
                        unit="Bytes/Second",
                        DBInstanceIdentifier=instance_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for name in ["NetworkReceiveThroughput", "NetworkTransmitThroughput"]
                ]
            )

        metric_normalizers = {
            "CPUUtilization": MetricNormalization(
                metric_name=MetricName.CpuUtilization,
                unit=MetricUnit.Percent,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "DatabaseConnections": MetricNormalization(
                metric_name=MetricName.DatabaseConnections,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ReadIOPS": MetricNormalization(
                metric_name=MetricName.DiskRead,
                unit=MetricUnit.IOPS,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "WriteIOPS": MetricNormalization(
                metric_name=MetricName.DiskWrite,
                unit=MetricUnit.IOPS,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ReadLatency": MetricNormalization(
                metric_name=MetricName.ReadLatency,
                unit=MetricUnit.Seconds,
                # normalize to packets per second
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "WriteLatency": MetricNormalization(
                metric_name=MetricName.WriteLatency,
                unit=MetricUnit.Seconds,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "FreeStorageSpace": MetricNormalization(
                metric_name=MetricName.FreeStorageSpace,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "FreeableMemory": MetricNormalization(
                metric_name=MetricName.FreeableMemory,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "SwapUsage": MetricNormalization(
                metric_name=MetricName.SwapUsage,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "DiskQueueDepth": MetricNormalization(
                metric_name=MetricName.DiskQueueDepth,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=6),
            ),
            "NetworkReceiveThroughput": MetricNormalization(
                metric_name=MetricName.NetworkReceiveThroughput,
                unit=MetricUnit.BytesPerSecond,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "NetworkTransmitThroughput": MetricNormalization(
                metric_name=MetricName.NetworkTransmitThroughput,
                unit=MetricUnit.BytesPerSecond,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(rds_instances, cloudwatch_result, metric_normalizers)


@define(eq=False, slots=False)
class AwsRdsDBClusterOptionGroupStatus:
    kind: ClassVar[str] = "aws_rds_db_cluster_option_group_status"
    kind_display: ClassVar[str] = "AWS RDS DB Cluster Option Group Status"
    kind_description: ClassVar[str] = (
        "The status of the option group for a DB cluster in Amazon RDS, which is a"
        " collection of database options and settings that can be applied to a DB"
        " instance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "db_cluster_option_group_name": S("DBClusterOptionGroupName"),
        "status": S("Status"),
    }
    db_cluster_option_group_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBClusterMember:
    kind: ClassVar[str] = "aws_rds_db_cluster_member"
    kind_display: ClassVar[str] = "AWS RDS DB Cluster Member"
    kind_description: ClassVar[str] = (
        "DB Cluster Member is a participant in an Amazon RDS Database Cluster, which"
        " is a managed relational database service offered by AWS for scaling and high"
        " availability."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "db_instance_identifier": S("DBInstanceIdentifier"),
        "is_cluster_writer": S("IsClusterWriter"),
        "db_cluster_parameter_group_status": S("DBClusterParameterGroupStatus"),
        "promotion_tier": S("PromotionTier"),
    }
    db_instance_identifier: Optional[str] = field(default=None)
    is_cluster_writer: Optional[bool] = field(default=None)
    db_cluster_parameter_group_status: Optional[str] = field(default=None)
    promotion_tier: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsScalingConfigurationInfo:
    kind: ClassVar[str] = "aws_rds_scaling_configuration_info"
    kind_display: ClassVar[str] = "AWS RDS Scaling Configuration Info"
    kind_description: ClassVar[str] = (
        "RDS Scaling Configuration Info provides information about the scaling"
        " configuration for Amazon RDS (Relational Database Service). It includes"
        " details about scaling policies, auto-scaling settings, and capacity planning"
        " for RDS instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_capacity": S("MinCapacity"),
        "max_capacity": S("MaxCapacity"),
        "auto_pause": S("AutoPause"),
        "seconds_until_auto_pause": S("SecondsUntilAutoPause"),
        "timeout_action": S("TimeoutAction"),
        "seconds_before_timeout": S("SecondsBeforeTimeout"),
    }
    min_capacity: Optional[int] = field(default=None)
    max_capacity: Optional[int] = field(default=None)
    auto_pause: Optional[bool] = field(default=None)
    seconds_until_auto_pause: Optional[int] = field(default=None)
    timeout_action: Optional[str] = field(default=None)
    seconds_before_timeout: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsClusterPendingModifiedValues:
    kind: ClassVar[str] = "aws_rds_cluster_pending_modified_values"
    kind_display: ClassVar[str] = "AWS RDS Cluster Pending Modified Values"
    kind_description: ClassVar[str] = (
        "RDS Cluster Pending Modified Values represents the pending modifications"
        " made to an Amazon RDS Cluster, indicating changes that will be applied soon."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "pending_cloudwatch_logs_exports": S("PendingCloudwatchLogsExports")
        >> Bend(AwsRdsPendingCloudwatchLogsExports.mapping),
        "db_cluster_identifier": S("DBClusterIdentifier"),
        "master_user_password": S("MasterUserPassword"),
        "iam_database_authentication_enabled": S("IAMDatabaseAuthenticationEnabled"),
        "engine_version": S("EngineVersion"),
        "backup_retention_period": S("BackupRetentionPeriod"),
        "allocated_storage": S("AllocatedStorage"),
        "iops": S("Iops"),
    }
    pending_cloudwatch_logs_exports: Optional[AwsRdsPendingCloudwatchLogsExports] = field(default=None)
    db_cluster_identifier: Optional[str] = field(default=None)
    master_user_password: Optional[str] = field(default=None)
    iam_database_authentication_enabled: Optional[bool] = field(default=None)
    engine_version: Optional[str] = field(default=None)
    backup_retention_period: Optional[int] = field(default=None)
    allocated_storage: Optional[int] = field(default=None)
    iops: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsServerlessV2ScalingConfigurationInfo:
    kind: ClassVar[str] = "aws_rds_serverless_v2_scaling_configuration_info"
    kind_display: ClassVar[str] = "AWS RDS Serverless V2 Scaling Configuration Info"
    kind_description: ClassVar[str] = (
        "RDS Serverless V2 Scaling Configuration provides information about the"
        " configuration settings for scaling Amazon RDS Aurora Serverless v2. It"
        " allows users to specify the minimum and maximum capacity for their"
        " serverless clusters, as well as the target utilization and scaling"
        " thresholds."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"min_capacity": S("MinCapacity"), "max_capacity": S("MaxCapacity")}
    min_capacity: Optional[float] = field(default=None)
    max_capacity: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsMasterUserSecret:
    kind: ClassVar[str] = "aws_rds_master_user_secret"
    kind_display: ClassVar[str] = "AWS RDS Master User Secret"
    kind_description: ClassVar[str] = (
        "AWS RDS Master User Secret refers to the credentials used to authenticate"
        " the master user of an Amazon RDS (Relational Database Service) instance."
        " These credentials are private and should be securely stored."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "secret_arn": S("SecretArn"),
        "secret_status": S("SecretStatus"),
        "kms_key_id": S("KmsKeyId"),
    }
    secret_arn: Optional[str] = field(default=None)
    secret_status: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsCluster(RdsTaggable, AwsResource, BaseDatabase):
    kind: ClassVar[str] = "aws_rds_cluster"
    kind_display: ClassVar[str] = "AWS RDS Cluster"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/rds/home?region={region}#database:id={id};is-cluster=true", "arn_tpl": "arn:{partition}:rds:{region}:{account}:cluster/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "RDS Clusters are managed relational database services in Amazon's cloud,"
        " providing scalable and highly available databases for applications running"
        " on the Amazon Web Services infrastructure."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-db-clusters", "DBClusters")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("DBClusterIdentifier"),
        "tags": S("TagList", default=[]) >> ToDict(),
        "name": S("DBClusterIdentifier"),
        "ctime": S("ClusterCreateTime"),
        "db_type": S("Engine"),
        "db_status": S("Status"),
        "db_endpoint": S("Endpoint") + K(":") + (S("Port") >> F(str)),
        "db_version": S("EngineVersion"),
        "db_publicly_accessible": S("PubliclyAccessible"),
        "volume_iops": S("Iops"),
        "volume_encrypted": S("StorageEncrypted"),
        "rds_allocated_storage": S("AllocatedStorage"),
        "rds_availability_zones": S("AvailabilityZones", default=[]),
        "rds_backup_retention_period": S("BackupRetentionPeriod"),
        "rds_character_set_name": S("CharacterSetName"),
        "rds_database_name": S("DatabaseName"),
        "rds_db_cluster_parameter_group": S("DBClusterParameterGroup"),
        "rds_db_subnet_group_name": S("DBSubnetGroup"),
        "rds_automatic_restart_time": S("AutomaticRestartTime"),
        "rds_earliest_restorable_time": S("EarliestRestorableTime"),
        "rds_endpoint": S("Endpoint"),
        "rds_reader_endpoint": S("ReaderEndpoint"),
        "rds_custom_endpoints": S("CustomEndpoints", default=[]),
        "rds_multi_az": S("MultiAZ"),
        "rds_latest_restorable_time": S("LatestRestorableTime"),
        "rds_port": S("Port"),
        "rds_master_username": S("MasterUsername"),
        "rds_db_cluster_option_group_memberships": S("DBClusterOptionGroupMemberships", default=[])
        >> ForallBend(AwsRdsDBClusterOptionGroupStatus.mapping),
        "rds_preferred_backup_window": S("PreferredBackupWindow"),
        "rds_preferred_maintenance_window": S("PreferredMaintenanceWindow"),
        "rds_replication_source_identifier": S("ReplicationSourceIdentifier"),
        "rds_read_replica_identifiers": S("ReadReplicaIdentifiers", default=[]),
        "rds_db_cluster_members": S("DBClusterMembers", default=[]) >> ForallBend(AwsRdsDBClusterMember.mapping),
        "rds_vpc_security_groups": S("VpcSecurityGroups", default=[])
        >> ForallBend(AwsRdsVpcSecurityGroupMembership.mapping),
        "rds_hosted_zone_id": S("HostedZoneId"),
        "rds_kms_key_id": S("KmsKeyId"),
        "rds_db_cluster_resource_id": S("DbClusterResourceId"),
        "arn": S("DBClusterArn"),
        "rds_associated_roles": S("AssociatedRoles", default=[]) >> ForallBend(AwsRdsDBRole.mapping),
        "rds_iam_database_authentication_enabled": S("IAMDatabaseAuthenticationEnabled"),
        "rds_clone_group_id": S("CloneGroupId"),
        "rds_earliest_backtrack_time": S("EarliestBacktrackTime"),
        "rds_backtrack_window": S("BacktrackWindow"),
        "rds_backtrack_consumed_change_records": S("BacktrackConsumedChangeRecords"),
        "rds_enabled_cloudwatch_logs_exports": S("EnabledCloudwatchLogsExports", default=[]),
        "rds_capacity": S("Capacity"),
        "rds_engine_mode": S("EngineMode"),
        "rds_scaling_configuration_info": S("ScalingConfigurationInfo") >> Bend(AwsRdsScalingConfigurationInfo.mapping),
        "rds_deletion_protection": S("DeletionProtection"),
        "rds_http_endpoint_enabled": S("HttpEndpointEnabled"),
        "rds_activity_stream_mode": S("ActivityStreamMode"),
        "rds_activity_stream_status": S("ActivityStreamStatus"),
        "rds_activity_stream_kms_key_id": S("ActivityStreamKmsKeyId"),
        "rds_activity_stream_kinesis_stream_name": S("ActivityStreamKinesisStreamName"),
        "rds_copy_tags_to_snapshot": S("CopyTagsToSnapshot"),
        "rds_cross_account_clone": S("CrossAccountClone"),
        "rds_domain_memberships": S("DomainMemberships", default=[]) >> ForallBend(AwsRdsDomainMembership.mapping),
        "rds_global_write_forwarding_status": S("GlobalWriteForwardingStatus"),
        "rds_global_write_forwarding_requested": S("GlobalWriteForwardingRequested"),
        "rds_cluster_pending_modified_values": S("PendingModifiedValues")
        >> Bend(AwsRdsClusterPendingModifiedValues.mapping),
        "rds_db_cluster_instance_class": S("DBClusterInstanceClass"),
        "rds_storage_type": S("StorageType"),
        "rds_auto_minor_version_upgrade": S("AutoMinorVersionUpgrade"),
        "rds_monitoring_interval": S("MonitoringInterval"),
        "rds_monitoring_role_arn": S("MonitoringRoleArn"),
        "rds_performance_insights_enabled": S("PerformanceInsightsEnabled"),
        "rds_performance_insights_kms_key_id": S("PerformanceInsightsKMSKeyId"),
        "rds_performance_insights_retention_period": S("PerformanceInsightsRetentionPeriod"),
        "rds_serverless_v2_scaling_configuration": S("ServerlessV2ScalingConfiguration")
        >> Bend(AwsRdsServerlessV2ScalingConfigurationInfo.mapping),
        "rds_network_type": S("NetworkType"),
        "rds_db_system_id": S("DBSystemId"),
        "rds_master_user_secret": S("MasterUserSecret") >> Bend(AwsRdsMasterUserSecret.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_rds_instance", "aws_kms_key", "aws_kinesis_stream"],
            "delete": ["aws_rds_instance"],
        },
        "predecessors": {"default": ["aws_ec2_security_group"]},
    }
    rds_allocated_storage: Optional[int] = field(default=None)
    rds_availability_zones: List[str] = field(factory=list)
    rds_backup_retention_period: Optional[int] = field(default=None)
    rds_character_set_name: Optional[str] = field(default=None)
    rds_database_name: Optional[str] = field(default=None)
    rds_db_cluster_parameter_group: Optional[str] = field(default=None)
    rds_db_subnet_group_name: Optional[str] = field(default=None)
    rds_automatic_restart_time: Optional[datetime] = field(default=None)
    rds_earliest_restorable_time: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    rds_endpoint: Optional[str] = field(default=None)
    rds_reader_endpoint: Optional[str] = field(default=None)
    rds_custom_endpoints: List[str] = field(factory=list)
    rds_multi_az: Optional[bool] = field(default=None)
    rds_latest_restorable_time: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    rds_port: Optional[int] = field(default=None)
    rds_master_username: Optional[str] = field(default=None)
    rds_db_cluster_option_group_memberships: List[AwsRdsDBClusterOptionGroupStatus] = field(factory=list)
    rds_preferred_backup_window: Optional[str] = field(default=None)
    rds_preferred_maintenance_window: Optional[str] = field(default=None)
    rds_replication_source_identifier: Optional[str] = field(default=None)
    rds_read_replica_identifiers: List[str] = field(factory=list)
    rds_db_cluster_members: List[AwsRdsDBClusterMember] = field(factory=list)
    rds_vpc_security_groups: List[AwsRdsVpcSecurityGroupMembership] = field(factory=list)
    rds_hosted_zone_id: Optional[str] = field(default=None)
    rds_kms_key_id: Optional[str] = field(default=None)
    rds_db_cluster_resource_id: Optional[str] = field(default=None)
    rds_associated_roles: List[AwsRdsDBRole] = field(factory=list)
    rds_iam_database_authentication_enabled: Optional[bool] = field(default=None)
    rds_clone_group_id: Optional[str] = field(default=None)
    rds_earliest_backtrack_time: Optional[datetime] = field(default=None)
    rds_backtrack_window: Optional[int] = field(default=None)
    rds_backtrack_consumed_change_records: Optional[int] = field(default=None)
    rds_enabled_cloudwatch_logs_exports: List[str] = field(factory=list)
    rds_capacity: Optional[int] = field(default=None)
    rds_engine_mode: Optional[str] = field(default=None)
    rds_scaling_configuration_info: Optional[AwsRdsScalingConfigurationInfo] = field(default=None)
    rds_deletion_protection: Optional[bool] = field(default=None)
    rds_http_endpoint_enabled: Optional[bool] = field(default=None)
    rds_activity_stream_mode: Optional[str] = field(default=None)
    rds_activity_stream_status: Optional[str] = field(default=None)
    rds_activity_stream_kms_key_id: Optional[str] = field(default=None)
    rds_activity_stream_kinesis_stream_name: Optional[str] = field(default=None)
    rds_copy_tags_to_snapshot: Optional[bool] = field(default=None)
    rds_cross_account_clone: Optional[bool] = field(default=None)
    rds_domain_memberships: List[AwsRdsDomainMembership] = field(factory=list)
    rds_global_write_forwarding_status: Optional[str] = field(default=None)
    rds_global_write_forwarding_requested: Optional[bool] = field(default=None)
    rds_cluster_pending_modified_values: Optional[AwsRdsClusterPendingModifiedValues] = field(default=None)
    rds_db_cluster_instance_class: Optional[str] = field(default=None)
    rds_storage_type: Optional[str] = field(default=None)
    rds_auto_minor_version_upgrade: Optional[bool] = field(default=None)
    rds_monitoring_interval: Optional[int] = field(default=None)
    rds_monitoring_role_arn: Optional[str] = field(default=None)
    rds_performance_insights_enabled: Optional[bool] = field(default=None)
    rds_performance_insights_kms_key_id: Optional[str] = field(default=None)
    rds_performance_insights_retention_period: Optional[int] = field(default=None)
    rds_serverless_v2_scaling_configuration: Optional[AwsRdsServerlessV2ScalingConfigurationInfo] = field(default=None)
    rds_network_type: Optional[str] = field(default=None)
    rds_db_system_id: Optional[str] = field(default=None)
    rds_master_user_secret: Optional[AwsRdsMasterUserSecret] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if kms_id := self.rds_kms_key_id:
            builder.add_edge(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(kms_id))
        for member in self.rds_db_cluster_members:
            builder.dependant_node(
                self, delete_same_as_default=True, clazz=AwsRdsInstance, id=member.db_instance_identifier
            )
        for sg in self.rds_vpc_security_groups:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=sg.vpc_security_group_id
            )
        if kinesis := self.rds_activity_stream_kinesis_stream_name:
            builder.add_edge(self, clazz=AwsKinesisStream, name=kinesis)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-db-cluster",
            result_name=None,
            DBClusterIdentifier=self.id,
            SkipFinalSnapshot=True,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-db-cluster")]


@define(eq=False, slots=False)
class AwsRdsSnapshot(RdsTaggable, AwsResource, BaseSnapshot):
    kind: ClassVar[str] = "aws_rds_snapshot"
    kind_display: ClassVar[str] = "AWS RDS Snapshot"
    kind_description: ClassVar[str] = "An AWS RDS Snapshot is a backup tool used for creating a point-in-time copy of an RDS database instance, facilitating data recovery and replication."  # fmt: skip
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/rds/home?region={region}#db-snapshot:engine={Engine};id={id}", "arn_tpl": "arn:{partition}:rds:{region}:{account}:snapshot:{id}/{name}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("rds", "describe-db-snapshots", "DBSnapshots")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("DBSnapshotIdentifier"),
        "tags": S("TagList", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("SnapshotCreateTime"),
        "arn": S("DBSnapshotArn"),
        "rds_db_instance_identifier": S("DBInstanceIdentifier"),
        "rds_engine": S("Engine"),
        "rds_allocated_storage": S("AllocatedStorage"),
        "snapshot_status": S("Status"),
        "rds_port": S("Port"),
        "rds_availability_zone": S("AvailabilityZone"),
        "rds_vpc_id": S("VpcId"),
        "rds_instance_create_time": S("InstanceCreateTime"),
        "rds_master_username": S("MasterUsername"),
        "rds_engine_version": S("EngineVersion"),
        "rds_license_model": S("LicenseModel"),
        "rds_snapshot_type": S("SnapshotType"),
        "rds_iops": S("Iops"),
        "rds_option_group_name": S("OptionGroupName"),
        "rds_percent_progress": S("PercentProgress"),
        "rds_source_region": S("SourceRegion"),
        "rds_source_db_snapshot_identifier": S("SourceDBSnapshotIdentifier"),
        "rds_storage_type": S("StorageType"),
        "rds_tde_credential_arn": S("TdeCredentialArn"),
        "rds_encrypted": S("Encrypted"),
        "rds_kms_key_id": S("KmsKeyId"),
        "rds_timezone": S("Timezone"),
        "rds_iam_database_authentication_enabled": S("IAMDatabaseAuthenticationEnabled"),
        "rds_processor_features": S("ProcessorFeatures", default=[]) >> ToDict(key="Name", value="Value"),
        "rds_dbi_resource_id": S("DbiResourceId"),
        "rds_original_snapshot_create_time": S("OriginalSnapshotCreateTime"),
        "rds_snapshot_database_time": S("SnapshotDatabaseTime"),
        "rds_snapshot_target": S("SnapshotTarget"),
        "rds_storage_throughput": S("StorageThroughput"),
        "rds_db_system_id": S("DBSystemId"),
        "rds_dedicated_log_volume": S("DedicatedLogVolume"),
        "rds_multi_tenant": S("MultiTenant"),
    }
    rds_db_instance_identifier: Optional[str] = field(default=None, metadata={"description": "Specifies the DB instance identifier of the DB instance this DB snapshot was created from."})  # fmt: skip
    rds_engine: Optional[str] = field(default=None, metadata={"description": "Specifies the name of the database engine."})  # fmt: skip
    rds_allocated_storage: Optional[int] = field(default=None, metadata={"description": "Specifies the allocated storage size in gibibytes (GiB)."})  # fmt: skip
    rds_port: Optional[int] = field(default=None, metadata={"description": "Specifies the port that the database engine was listening on at the time of the snapshot."})  # fmt: skip
    rds_availability_zone: Optional[str] = field(default=None, metadata={"description": "Specifies the name of the Availability Zone the DB instance was located in at the time of the DB snapshot."})  # fmt: skip
    rds_vpc_id: Optional[str] = field(default=None, metadata={"description": "Provides the VPC ID associated with the DB snapshot."})  # fmt: skip
    rds_instance_create_time: Optional[datetime] = field(default=None, metadata={"description": "Specifies the time in Coordinated Universal Time (UTC) when the DB instance, from which the snapshot was taken, was created."})  # fmt: skip
    rds_master_username: Optional[str] = field(default=None, metadata={"description": "Provides the master username for the DB snapshot."})  # fmt: skip
    rds_engine_version: Optional[str] = field(default=None, metadata={"description": "Specifies the version of the database engine."})  # fmt: skip
    rds_license_model: Optional[str] = field(default=None, metadata={"description": "License model information for the restored DB instance."})  # fmt: skip
    rds_snapshot_type: Optional[str] = field(default=None, metadata={"description": "Provides the type of the DB snapshot."})  # fmt: skip
    rds_iops: Optional[int] = field(default=None, metadata={"description": "Specifies the Provisioned IOPS (I/O operations per second) value of the DB instance at the time of the snapshot."})  # fmt: skip
    rds_option_group_name: Optional[str] = field(default=None, metadata={"description": "Provides the option group name for the DB snapshot."})  # fmt: skip
    rds_percent_progress: Optional[int] = field(default=None, metadata={"description": "The percentage of the estimated data that has been transferred."})  # fmt: skip
    rds_source_region: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services Region that the DB snapshot was created in or copied from."})  # fmt: skip
    rds_source_db_snapshot_identifier: Optional[str] = field(default=None, metadata={"description": "The DB snapshot Amazon Resource Name (ARN) that the DB snapshot was copied from. It only has a value in the case of a cross-account or cross-Region copy."})  # fmt: skip
    rds_storage_type: Optional[str] = field(default=None, metadata={"description": "Specifies the storage type associated with DB snapshot."})  # fmt: skip
    rds_tde_credential_arn: Optional[str] = field(default=None, metadata={"description": "The ARN from the key store with which to associate the instance for TDE encryption."})  # fmt: skip
    rds_encrypted: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the DB snapshot is encrypted."})  # fmt: skip
    rds_kms_key_id: Optional[str] = field(default=None, metadata={"description": "If Encrypted is true, the Amazon Web Services KMS key identifier for the encrypted DB snapshot. The Amazon Web Services KMS key identifier is the key ARN, key ID, alias ARN, or alias name for the KMS key."})  # fmt: skip
    rds_timezone: Optional[str] = field(default=None, metadata={"description": "The time zone of the DB snapshot. In most cases, the Timezone element is empty. Timezone content appears only for snapshots taken from Microsoft SQL Server DB instances that were created with a time zone specified."})  # fmt: skip
    rds_iam_database_authentication_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether mapping of Amazon Web Services Identity and Access Management (IAM) accounts to database accounts is enabled."})  # fmt: skip
    rds_processor_features: Optional[Dict[str, str]] = field(default=None, metadata={"description": "The number of CPU cores and the number of threads per core for the DB instance class of the DB instance when the DB snapshot was created."})  # fmt: skip
    rds_dbi_resource_id: Optional[str] = field(default=None, metadata={"description": "The identifier for the source DB instance, which can't be changed and which is unique to an Amazon Web Services Region."})  # fmt: skip
    rds_original_snapshot_create_time: Optional[datetime] = field(default=None, metadata={"description": "Specifies the time of the CreateDBSnapshot operation in Coordinated Universal Time (UTC). Doesn't change when the snapshot is copied."})  # fmt: skip
    rds_snapshot_database_time: Optional[datetime] = field(default=None, metadata={"description": "The timestamp of the most recent transaction applied to the database that you're backing up. Thus, if you restore a snapshot, SnapshotDatabaseTime is the most recent transaction in the restored DB instance. In contrast, originalSnapshotCreateTime specifies the system time that the snapshot completed. If you back up a read replica, you can determine the replica lag by comparing SnapshotDatabaseTime with originalSnapshotCreateTime. For example, if originalSnapshotCreateTime is two hours later than SnapshotDatabaseTime, then the replica lag is two hours."})  # fmt: skip
    rds_snapshot_target: Optional[str] = field(default=None, metadata={"description": "Specifies where manual snapshots are stored: Amazon Web Services Outposts or the Amazon Web Services Region."})  # fmt: skip
    rds_storage_throughput: Optional[int] = field(default=None, metadata={"description": "Specifies the storage throughput for the DB snapshot."})  # fmt: skip
    rds_db_system_id: Optional[str] = field(default=None, metadata={"description": "The Oracle system identifier (SID), which is the name of the Oracle database instance that manages your database files. The Oracle SID is also the name of your CDB."})  # fmt: skip
    rds_dedicated_log_volume: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the DB instance has a dedicated log volume (DLV) enabled."})  # fmt: skip
    rds_multi_tenant: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the snapshot is of a DB instance using the multi-tenant configuration (TRUE) or the single-tenant configuration (FALSE)."})  # fmt: skip
    rds_attributes: Optional[Dict[str, List[str]]] = None

    def post_process(self, builder: GraphBuilder, source: Json) -> None:
        def fetch_snapshot_attributes() -> None:
            with builder.suppress("rds.describe-db-snapshot-attributes"):
                if attrs := builder.client.get(
                    "rds",
                    "describe-db-snapshot-attributes",
                    "DBSnapshotAttributesResult.DBSnapshotAttributes",
                    DBSnapshotIdentifier=self.id,
                ):
                    self.rds_attributes = bend(ToDict(key="AttributeName", value="AttributeValues"), attrs)

        builder.submit_work(service_name, fetch_snapshot_attributes)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if dbi := self.rds_db_instance_identifier:
            builder.add_edge(self, reverse=True, clazz=AwsRdsInstance, id=dbi)
        if vpc_id := self.rds_vpc_id:
            builder.add_edge(self, reverse=True, clazz=AwsEc2Vpc, id=vpc_id)


@define(eq=False, slots=False)
class AwsRdsClusterSnapshot(AwsResource):
    kind: ClassVar[str] = "aws_rds_cluster_snapshot"
    kind_display: ClassVar[str] = "AWS RDS Cluster Snapshot"
    kind_description: ClassVar[str] = "An AWS RDS Cluster Snapshot is a point-in-time backup of an Amazon RDS cluster that provides data persistence and recovery for disaster management."  # fmt: skip
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/rds/home?region={region}#db-snapshot:engine={Engine};id={id}", "arn_tpl": "arn:{partition}:rds:{region}:{account}:snapshot/{name}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("rds", "describe-db-cluster-snapshots", "DBClusterSnapshots")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("DBClusterSnapshotIdentifier"),
        "tags": S("TagList", default=[]) >> ToDict(),
        "name": S("TagList", default=[]) >> TagsValue("Name"),
        "ctime": S("SnapshotCreateTime"),
        "rds_availability_zones": S("AvailabilityZones", default=[]),
        "rds_db_cluster_identifier": S("DBClusterIdentifier"),
        "rds_engine": S("Engine"),
        "rds_engine_mode": S("EngineMode"),
        "rds_allocated_storage": S("AllocatedStorage"),
        "rds_status": S("Status"),
        "rds_port": S("Port"),
        "rds_vpc_id": S("VpcId"),
        "rds_cluster_create_time": S("ClusterCreateTime"),
        "rds_master_username": S("MasterUsername"),
        "rds_engine_version": S("EngineVersion"),
        "rds_license_model": S("LicenseModel"),
        "rds_snapshot_type": S("SnapshotType"),
        "rds_percent_progress": S("PercentProgress"),
        "rds_storage_encrypted": S("StorageEncrypted"),
        "rds_kms_key_id": S("KmsKeyId"),
        "rds_db_cluster_snapshot_arn": S("DBClusterSnapshotArn"),
        "rds_source_db_cluster_snapshot_arn": S("SourceDBClusterSnapshotArn"),
        "rds_iam_database_authentication_enabled": S("IAMDatabaseAuthenticationEnabled"),
        "rds_db_system_id": S("DBSystemId"),
        "rds_storage_type": S("StorageType"),
        "rds_db_cluster_resource_id": S("DbClusterResourceId"),
    }
    rds_availability_zones: Optional[List[str]] = field(factory=list, metadata={"description": "The list of Availability Zones (AZs) where instances in the DB cluster snapshot can be restored."})  # fmt: skip
    rds_db_cluster_identifier: Optional[str] = field(default=None, metadata={"description": "The DB cluster identifier of the DB cluster that this DB cluster snapshot was created from."})  # fmt: skip
    rds_engine: Optional[str] = field(default=None, metadata={"description": "The name of the database engine for this DB cluster snapshot."})  # fmt: skip
    rds_engine_mode: Optional[str] = field(default=None, metadata={"description": "The engine mode of the database engine for this DB cluster snapshot."})  # fmt: skip
    rds_allocated_storage: Optional[int] = field(default=None, metadata={"description": "The allocated storage size of the DB cluster snapshot in gibibytes (GiB)."})  # fmt: skip
    rds_status: Optional[str] = field(default=None, metadata={"description": "The status of this DB cluster snapshot. Valid statuses are the following:    available     copying     creating"})  # fmt: skip
    rds_port: Optional[int] = field(default=None, metadata={"description": "The port that the DB cluster was listening on at the time of the snapshot."})  # fmt: skip
    rds_vpc_id: Optional[str] = field(default=None, metadata={"description": "The VPC ID associated with the DB cluster snapshot."})  # fmt: skip
    rds_cluster_create_time: Optional[datetime] = field(default=None, metadata={"description": "The time when the DB cluster was created, in Universal Coordinated Time (UTC)."})  # fmt: skip
    rds_master_username: Optional[str] = field(default=None, metadata={"description": "The master username for this DB cluster snapshot."})  # fmt: skip
    rds_engine_version: Optional[str] = field(default=None, metadata={"description": "The version of the database engine for this DB cluster snapshot."})  # fmt: skip
    rds_license_model: Optional[str] = field(default=None, metadata={"description": "The license model information for this DB cluster snapshot."})  # fmt: skip
    rds_snapshot_type: Optional[str] = field(default=None, metadata={"description": "The type of the DB cluster snapshot."})  # fmt: skip
    rds_percent_progress: Optional[int] = field(default=None, metadata={"description": "The percentage of the estimated data that has been transferred."})  # fmt: skip
    rds_storage_encrypted: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the DB cluster snapshot is encrypted."})  # fmt: skip
    rds_kms_key_id: Optional[str] = field(default=None, metadata={"description": "If StorageEncrypted is true, the Amazon Web Services KMS key identifier for the encrypted DB cluster snapshot. The Amazon Web Services KMS key identifier is the key ARN, key ID, alias ARN, or alias name for the KMS key."})  # fmt: skip
    rds_db_cluster_snapshot_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) for the DB cluster snapshot."})  # fmt: skip
    rds_source_db_cluster_snapshot_arn: Optional[str] = field(default=None, metadata={"description": "If the DB cluster snapshot was copied from a source DB cluster snapshot, the Amazon Resource Name (ARN) for the source DB cluster snapshot, otherwise, a null value."})  # fmt: skip
    rds_iam_database_authentication_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether mapping of Amazon Web Services Identity and Access Management (IAM) accounts to database accounts is enabled."})  # fmt: skip
    rds_db_system_id: Optional[str] = field(default=None, metadata={"description": "Reserved for future use."})  # fmt: skip
    rds_storage_type: Optional[str] = field(default=None, metadata={"description": "The storage type associated with the DB cluster snapshot. This setting is only for Aurora DB clusters."})  # fmt: skip
    rds_db_cluster_resource_id: Optional[str] = field(default=None, metadata={"description": "The resource ID of the DB cluster that this DB cluster snapshot was created from."})  # fmt: skip
    rds_attributes: Optional[Dict[str, List[str]]] = None

    def post_process(self, builder: GraphBuilder, source: Json) -> None:
        def fetch_snapshot_attributes() -> None:
            with builder.suppress("rds.describe-db-cluster-snapshot-attributes"):
                if attrs := builder.client.get(
                    "rds",
                    "describe-db-cluster-snapshot-attributes",
                    "DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes",
                    DBClusterSnapshotIdentifier=self.id,
                ):
                    self.rds_attributes = bend(ToDict(key="AttributeName", value="AttributeValues"), attrs)

        builder.submit_work(service_name, fetch_snapshot_attributes)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if dbi := self.rds_db_cluster_identifier:
            builder.add_edge(self, reverse=True, clazz=AwsRdsCluster, id=dbi)
        if vpc_id := self.rds_vpc_id:
            builder.add_edge(self, reverse=True, clazz=AwsEc2Vpc, id=vpc_id)
        if key_id := self.rds_kms_key_id:
            builder.add_edge(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(key_id))


resources: List[Type[AwsResource]] = [AwsRdsCluster, AwsRdsInstance, AwsRdsSnapshot, AwsRdsClusterSnapshot]
