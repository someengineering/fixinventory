from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Type
from attr import define, field
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.cloudwatch import AwsCloudwatchQuery, AwsCloudwatchMetricData
from resoto_plugin_aws.resource.ec2 import AwsEc2SecurityGroup, AwsEc2Subnet, AwsEc2Vpc
from resoto_plugin_aws.resource.kinesis import AwsKinesisStream
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import BaseDatabase, ModelReference
from resotolib.graph import Graph
from resotolib.json_bender import F, K, S, Bend, Bender, ForallBend, bend
from resotolib.types import Json
from resotolib.utils import utc
from resoto_plugin_aws.aws_client import AwsClient

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
    mapping: ClassVar[Dict[str, Bender]] = {"db_security_group_name": S("DBSecurityGroupName"), "status": S("Status")}
    db_security_group_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsVpcSecurityGroupMembership:
    kind: ClassVar[str] = "aws_rds_vpc_security_group_membership"
    mapping: ClassVar[Dict[str, Bender]] = {"vpc_security_group_id": S("VpcSecurityGroupId"), "status": S("Status")}
    vpc_security_group_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBParameterGroupStatus:
    kind: ClassVar[str] = "aws_rds_db_parameter_group_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "db_parameter_group_name": S("DBParameterGroupName"),
        "parameter_apply_status": S("ParameterApplyStatus"),
    }
    db_parameter_group_name: Optional[str] = field(default=None)
    parameter_apply_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsSubnet:
    kind: ClassVar[str] = "aws_rds_subnet"
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "log_types_to_enable": S("LogTypesToEnable", default=[]),
        "log_types_to_disable": S("LogTypesToDisable", default=[]),
    }
    log_types_to_enable: List[str] = field(factory=list)
    log_types_to_disable: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsRdsProcessorFeature:
    kind: ClassVar[str] = "aws_rds_processor_feature"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "value": S("Value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsPendingModifiedValues:
    kind: ClassVar[str] = "aws_rds_pending_modified_values"
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
    mapping: ClassVar[Dict[str, Bender]] = {"option_group_name": S("OptionGroupName"), "status": S("Status")}
    option_group_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBInstanceStatusInfo:
    kind: ClassVar[str] = "aws_rds_db_instance_status_info"
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "role_arn": S("RoleArn"),
        "feature_name": S("FeatureName"),
        "status": S("Status"),
    }
    role_arn: Optional[str] = field(default=None)
    feature_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsTag:
    kind: ClassVar[str] = "aws_rds_tag"
    mapping: ClassVar[Dict[str, Bender]] = {"key": S("Key"), "value": S("Value")}
    key: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsInstance(RdsTaggable, AwsResource, BaseDatabase):
    kind: ClassVar[str] = "aws_rds_instance"
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
        "tags": S("TagList", default=[]) >> ForallBend(AwsRdsTag.mapping) >> ToDict(),
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

            for query, metric in AwsCloudwatchMetricData.query_for(builder.client, queries, start, now).items():
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
            instance = AwsRdsInstance.from_api(js)
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


@define(eq=False, slots=False)
class AwsRdsDBClusterOptionGroupStatus:
    kind: ClassVar[str] = "aws_rds_db_cluster_option_group_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "db_cluster_option_group_name": S("DBClusterOptionGroupName"),
        "status": S("Status"),
    }
    db_cluster_option_group_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsDBClusterMember:
    kind: ClassVar[str] = "aws_rds_db_cluster_member"
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
    mapping: ClassVar[Dict[str, Bender]] = {"min_capacity": S("MinCapacity"), "max_capacity": S("MaxCapacity")}
    min_capacity: Optional[float] = field(default=None)
    max_capacity: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AwsRdsMasterUserSecret:
    kind: ClassVar[str] = "aws_rds_master_user_secret"
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
        "rds_percent_progress": S("PercentProgress"),
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
    rds_percent_progress: Optional[str] = field(default=None)
    rds_earliest_restorable_time: Optional[datetime] = field(default=None)
    rds_endpoint: Optional[str] = field(default=None)
    rds_reader_endpoint: Optional[str] = field(default=None)
    rds_custom_endpoints: List[str] = field(factory=list)
    rds_multi_az: Optional[bool] = field(default=None)
    rds_latest_restorable_time: Optional[datetime] = field(default=None)
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


resources: List[Type[AwsResource]] = [AwsRdsCluster, AwsRdsInstance]
