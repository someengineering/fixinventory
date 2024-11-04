import logging
from datetime import datetime
from typing import Any, ClassVar, Dict, Optional, List, Tuple, Type
from json import loads as json_loads

from attrs import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.resource.cloudformation import AwsCloudFormationStack
from fix_plugin_aws.resource.dynamodb import AwsDynamoDbTable, AwsDynamoDbGlobalTable
from fix_plugin_aws.resource.ec2 import AwsEc2Instance, AwsEc2Volume
from fix_plugin_aws.resource.efs import AwsEfsFileSystem
from fix_plugin_aws.resource.rds import AwsRdsCluster, AwsRdsInstance
from fix_plugin_aws.resource.redshift import AwsRedshiftCluster
from fix_plugin_aws.resource.s3 import AwsS3Bucket
from fix_plugin_aws.utils import TagsValue
from fixlib.baseresources import HasResourcePolicy, ModelReference, PolicySource, PolicySourceKind
from fixlib.graph import Graph
from fixlib.json_bender import F, Bender, S, ForallBend, Bend
from fixlib.types import Json
from fixlib.json import sort_json

log = logging.getLogger("fix.plugins.aws")
service_name = "backup"


class BackupResourceTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="tag-resource",
                result_name=None,
                ResourceArn=self.arn,
                Tags={key: value},
            )
            return True
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="untag-resource",
                result_name=None,
                ResourceArn=self.arn,
                TagKeyList=[key],
            )
            return True
        return False


@define(eq=False, slots=False)
class AwsBackupRecoveryPointCreator:
    kind: ClassVar[str] = "aws_backup_recovery_point_creator"
    mapping: ClassVar[Dict[str, Bender]] = {
        "backup_plan_id": S("BackupPlanId"),
        "backup_plan_arn": S("BackupPlanArn"),
        "backup_plan_version": S("BackupPlanVersion"),
        "backup_rule_id": S("BackupRuleId"),
    }
    backup_plan_id: Optional[str] = field(default=None, metadata={"description": "Uniquely identifies a backup plan."})  # fmt: skip
    backup_plan_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a backup plan; for example, arn:aws:backup:us-east-1:123456789012:plan:8F81F553-3A74-4A3F-B93D-B3360DC80C50."})  # fmt: skip
    backup_plan_version: Optional[str] = field(default=None, metadata={"description": "Version IDs are unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. They cannot be edited."})  # fmt: skip
    backup_rule_id: Optional[str] = field(default=None, metadata={"description": "Uniquely identifies a rule used to schedule the backup of a selection of resources."})  # fmt: skip


@define(eq=False, slots=False)
class AwsBackupJob(AwsResource):
    kind: ClassVar[str] = "aws_backup_job"
    _kind_display: ClassVar[str] = "AWS Backup Job"
    _kind_description: ClassVar[str] = "AWS Backup Job is a task that creates and manages backups of AWS resources. It defines the source data, backup frequency, and retention policy. The job executes according to a schedule, creating point-in-time snapshots of specified resources. It handles backup creation, storage, and lifecycle management, ensuring data protection and recovery capabilities for AWS environments."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/backup-jobs.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "job", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/backupplan/details/{id}"}  # fmt: skip
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_backup_plan", "aws_backup_vault"]},
        "successors": {"default": ["aws_backup_protected_resource", "aws_backup_recovery_point"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-backup-jobs", "BackupJobs")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("BackupJobId"),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreationDate"),
        "account_id": S("AccountId"),
        "backup_job_id": S("BackupJobId"),
        "backup_vault_name": S("BackupVaultName"),
        "backup_vault_arn": S("BackupVaultArn"),
        "recovery_point_arn": S("RecoveryPointArn"),
        "resource_arn": S("ResourceArn"),
        "creation_date": S("CreationDate"),
        "completion_date": S("CompletionDate"),
        "state": S("State"),
        "status_message": S("StatusMessage"),
        "percent_done": S("PercentDone"),
        "backup_size_in_bytes": S("BackupSizeInBytes"),
        "iam_role_arn": S("IamRoleArn"),
        "job_created_by": S("CreatedBy") >> Bend(AwsBackupRecoveryPointCreator.mapping),
        "expected_completion_date": S("ExpectedCompletionDate"),
        "start_by": S("StartBy"),
        "resource_type": S("ResourceType"),
        "bytes_transferred": S("BytesTransferred"),
        "backup_options": S("BackupOptions"),
        "backup_type": S("BackupType"),
        "parent_job_id": S("ParentJobId"),
        "is_parent": S("IsParent"),
        "resource_name": S("ResourceName"),
        "initiation_date": S("InitiationDate"),
        "message_category": S("MessageCategory"),
    }
    account_id: Optional[str] = field(default=None, metadata={"description": "The account ID that owns the backup job."})  # fmt: skip
    backup_job_id: Optional[str] = field(default=None, metadata={"description": "Uniquely identifies a request to Backup to back up a resource."})  # fmt: skip
    backup_vault_name: Optional[str] = field(default=None, metadata={"description": "The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the Amazon Web Services Region where they are created. They consist of lowercase letters, numbers, and hyphens."})  # fmt: skip
    backup_vault_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a backup vault; for example, arn:aws:backup:us-east-1:123456789012:vault:aBackupVault."})  # fmt: skip
    recovery_point_arn: Optional[str] = field(default=None, metadata={"description": "An ARN that uniquely identifies a recovery point; for example, arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45."})  # fmt: skip
    resource_arn: Optional[str] = field(default=None, metadata={"description": "An ARN that uniquely identifies a resource. The format of the ARN depends on the resource type."})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a backup job is created, in Unix format and Coordinated Universal Time (UTC). The value of CreationDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    completion_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a job to create a backup job is completed, in Unix format and Coordinated Universal Time (UTC). The value of CompletionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The current state of a backup job."})  # fmt: skip
    status_message: Optional[str] = field(default=None, metadata={"description": "A detailed message explaining the status of the job to back up a resource."})  # fmt: skip
    percent_done: Optional[str] = field(default=None, metadata={"description": "Contains an estimated percentage complete of a job at the time the job status was queried."})  # fmt: skip
    backup_size_in_bytes: Optional[int] = field(default=None, metadata={"description": "The size, in bytes, of a backup."})  # fmt: skip
    iam_role_arn: Optional[str] = field(default=None, metadata={"description": "Specifies the IAM role ARN used to create the target recovery point. IAM roles other than the default role must include either AWSBackup or AwsBackup in the role name. For example, arn:aws:iam::123456789012:role/AWSBackupRDSAccess. Role names without those strings lack permissions to perform backup jobs."})  # fmt: skip
    job_created_by: Optional[AwsBackupRecoveryPointCreator] = field(default=None, metadata={"description": "Contains identifying information about the creation of a backup job, including the BackupPlanArn, BackupPlanId, BackupPlanVersion, and BackupRuleId of the backup plan used to create it."})  # fmt: skip
    expected_completion_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a job to back up resources is expected to be completed, in Unix format and Coordinated Universal Time (UTC). The value of ExpectedCompletionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    start_by: Optional[datetime] = field(default=None, metadata={"description": "Specifies the time in Unix format and Coordinated Universal Time (UTC) when a backup job must be started before it is canceled. The value is calculated by adding the start window to the scheduled time. So if the scheduled time were 6:00 PM and the start window is 2 hours, the StartBy time would be 8:00 PM on the date specified. The value of StartBy is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of Amazon Web Services resource to be backed up; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2."})  # fmt: skip
    bytes_transferred: Optional[int] = field(default=None, metadata={"description": "The size in bytes transferred to a backup vault at the time that the job status was queried."})  # fmt: skip
    backup_options: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Specifies the backup option for a selected resource. This option is only available for Windows Volume Shadow Copy Service (VSS) backup jobs."})  # fmt: skip
    backup_type: Optional[str] = field(default=None, metadata={"description": "Represents the type of backup for a backup job."})  # fmt: skip
    parent_job_id: Optional[str] = field(default=None, metadata={"description": "This uniquely identifies a request to Backup to back up a resource. The return will be the parent (composite) job ID."})  # fmt: skip
    is_parent: Optional[bool] = field(default=None, metadata={"description": "This is a boolean value indicating this is a parent (composite) backup job."})  # fmt: skip
    resource_name: Optional[str] = field(default=None, metadata={"description": "This is the non-unique name of the resource that belongs to the specified backup."})  # fmt: skip
    initiation_date: Optional[datetime] = field(default=None, metadata={"description": "This is the date on which the backup job was initiated."})  # fmt: skip
    message_category: Optional[str] = field(default=None, metadata={"description": "This parameter is the job count for the specified message category. Example strings may include AccessDenied, SUCCESS, AGGREGATE_ALL, and INVALIDPARAMETERS. See Monitoring for a list of MessageCategory strings. The the value ANY returns count of all message categories.  AGGREGATE_ALL aggregates job counts for all message categories and returns the sum."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if resource_arn := self.resource_arn:
            builder.add_edge(self, clazz=AwsBackupProtectedResource, resource_arn=resource_arn)
        if recovery_point_arn := self.recovery_point_arn:
            builder.add_edge(self, clazz=AwsBackupRecoveryPoint, id=recovery_point_arn)
        if (created_by := self.job_created_by) and (plan_id := created_by.backup_plan_id):
            builder.add_edge(self, reverse=True, clazz=AwsBackupPlan, id=plan_id)
        if backup_vault_name := self.backup_vault_name:
            builder.add_edge(self, reverse=True, clazz=AwsBackupVault, name=backup_vault_name)


@define(eq=False, slots=False)
class AwsBackupProtectedResource(AwsResource):
    kind: ClassVar[str] = "aws_backup_protected_resource"
    _kind_display: ClassVar[str] = "AWS Backup Protected Resource"
    _kind_description: ClassVar[str] = "AWS Backup Protected Resource refers to a specific data entity or system component safeguarded by AWS Backup service. It includes databases, file systems, and storage volumes that are backed up and can be restored as needed. This resource type helps organizations maintain data integrity, comply with retention policies, and recover from potential data loss or system failures."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/protected-resources.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/resources/{id}"}  # fmt: skip
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_backup_vault", "aws_backup_recovery_point"]},
        "successors": {
            "default": [
                "aws_s3_bucket",
                "aws_ec2_instance",
                "aws_ec2_volume",
                "aws_rds_cluster",
                "aws_rds_instance",
                "aws_dynamodb_table",
                "aws_dynamodb_global_table",
                "aws_efs_file_system",
                "aws_redshift_cluster",
                "aws_cloudformation_stack",
            ]
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-protected-resources", "Results")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ResourceArn") >> F(AwsResource.id_from_arn),
        "name": S("ResourceName"),
        "resource_arn": S("ResourceArn"),
        "resource_type": S("ResourceType"),
        "last_backup_time": S("LastBackupTime"),
        "resource_name": S("ResourceName"),
        "last_backup_vault_arn": S("LastBackupVaultArn"),
        "last_recovery_point_arn": S("LastRecoveryPointArn"),
    }
    resource_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of Amazon Web Services resource; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2."})  # fmt: skip
    last_backup_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time a resource was last backed up, in Unix format and Coordinated Universal Time (UTC). The value of LastBackupTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    resource_name: Optional[str] = field(default=None, metadata={"description": "This is the non-unique name of the resource that belongs to the specified backup."})  # fmt: skip
    last_backup_vault_arn: Optional[str] = field(default=None, metadata={"description": "This is the ARN (Amazon Resource Name) of the backup vault that contains the most recent backup recovery point."})  # fmt: skip
    last_recovery_point_arn: Optional[str] = field(default=None, metadata={"description": "This is the ARN (Amazon Resource Name) of the most recent recovery point."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if resource_arn := self.resource_arn:
            builder.add_edge(
                self,
                clazz=(
                    AwsS3Bucket,
                    AwsEc2Instance,
                    AwsEc2Volume,
                    AwsRdsCluster,
                    AwsRdsInstance,
                    AwsDynamoDbTable,
                    AwsDynamoDbGlobalTable,
                    AwsEfsFileSystem,
                    AwsRedshiftCluster,
                    AwsCloudFormationStack,
                ),
                arn=resource_arn,
            )
        if vault_arn := self.last_backup_vault_arn:
            builder.add_edge(self, reverse=True, clazz=AwsBackupVault, id=vault_arn)
        if recovery_point_arn := self.last_recovery_point_arn:
            builder.add_edge(self, reverse=True, clazz=AwsBackupRecoveryPoint, id=recovery_point_arn)


@define(eq=False, slots=False)
class AwsBackupAdvancedBackupSetting:
    kind: ClassVar[str] = "aws_backup_advanced_backup_setting"
    mapping: ClassVar[Dict[str, Bender]] = {"resource_type": S("ResourceType"), "backup_options": S("BackupOptions")}
    resource_type: Optional[str] = field(default=None, metadata={"description": "Specifies an object containing resource type and backup options. The only supported resource type is Amazon EC2 instances with Windows Volume Shadow Copy Service (VSS). For a CloudFormation example, see the sample CloudFormation template to enable Windows VSS in the Backup User Guide. Valid values: EC2."})  # fmt: skip
    backup_options: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Specifies the backup option for a selected resource. This option is only available for Windows VSS backup jobs."})  # fmt: skip


@define(eq=False, slots=False)
class AwsBackupPlan(BackupResourceTaggable, AwsResource):
    kind: ClassVar[str] = "aws_backup_plan"
    _kind_display: ClassVar[str] = "AWS Backup Plan"
    _kind_description: ClassVar[str] = "AWS Backup Plan is a feature of AWS Backup that automates and manages data protection for AWS resources. It defines when and how often backups are created, specifies retention periods for backups, and sets rules for copying backups across AWS Regions or accounts. Users can create custom backup plans or use pre-configured plans to meet their data protection requirements."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-backup-plan.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "plan", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/backupplan/details/{id}", "arn_tpl": "arn:{partition}:backup:{region}:{account}:backup-plan:{id}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-backup-plans", "BackupPlansList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("BackupPlanId"),
        "name": S("BackupPlanName"),
        "ctime": S("CreationDate"),
        "backup_plan_arn": S("BackupPlanArn"),
        "backup_plan_id": S("BackupPlanId"),
        "creation_date": S("CreationDate"),
        "deletion_date": S("DeletionDate"),
        "version_id": S("VersionId"),
        "backup_plan_name": S("BackupPlanName"),
        "creator_request_id": S("CreatorRequestId"),
        "last_execution_date": S("LastExecutionDate"),
        "advanced_backup_settings": S("AdvancedBackupSettings", default=[])
        >> ForallBend(AwsBackupAdvancedBackupSetting.mapping),
        "arn": S("BackupPlanArn"),
    }
    backup_plan_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a backup plan; for example, arn:aws:backup:us-east-1:123456789012:plan:8F81F553-3A74-4A3F-B93D-B3360DC80C50."})  # fmt: skip
    backup_plan_id: Optional[str] = field(default=None, metadata={"description": "Uniquely identifies a backup plan."})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a resource backup plan is created, in Unix format and Coordinated Universal Time (UTC). The value of CreationDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    deletion_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a backup plan is deleted, in Unix format and Coordinated Universal Time (UTC). The value of DeletionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    version_id: Optional[str] = field(default=None, metadata={"description": "Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited."})  # fmt: skip
    backup_plan_name: Optional[str] = field(default=None, metadata={"description": "The display name of a saved backup plan."})  # fmt: skip
    creator_request_id: Optional[str] = field(default=None, metadata={"description": "A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice. This parameter is optional. If used, this parameter must contain 1 to 50 alphanumeric or '-_.' characters."})  # fmt: skip
    last_execution_date: Optional[datetime] = field(default=None, metadata={"description": "The last time a job to back up resources was run with this rule. A date and time, in Unix format and Coordinated Universal Time (UTC). The value of LastExecutionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    advanced_backup_settings: Optional[List[AwsBackupAdvancedBackupSetting]] = field(factory=list, metadata={"description": "Contains a list of BackupOptions for a resource type."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-backup-plan"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-backup-plan",
            result_name=None,
            BackupPlanId=self.id,
        )
        return True

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(backup_plan: AwsBackupPlan) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags",
                "Tags",
                expected_errors=["ResourceNotFoundException"],
                ResourceArn=backup_plan.backup_plan_arn,
            )
            if tags:
                for tag in tags:
                    backup_plan.tags.update(tag)

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)


@define(eq=False, slots=False)
class AwsBackupVault(BackupResourceTaggable, AwsResource, HasResourcePolicy):
    kind: ClassVar[str] = "aws_backup_vault"
    _kind_display: ClassVar[str] = "AWS Backup Vault"
    _kind_description: ClassVar[str] = "AWS Backup Vault is a secure storage container for backup data in AWS Backup. It stores and organizes backup copies, providing encryption and access policies to protect backups. Users can create multiple vaults to separate backups by application, environment, or compliance requirements. AWS Backup Vault supports retention policies and lifecycle management for stored backups."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/vaults.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "bucket", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/backupplan/details/{name}", "arn_tpl": "arn:{partition}:backup:{region}:{account}:backup-vault:{name}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-backup-vaults", "BackupVaultList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("BackupVaultArn"),
        "name": S("BackupVaultName"),
        "ctime": S("CreationDate"),
        "backup_vault_name": S("BackupVaultName"),
        "backup_vault_arn": S("BackupVaultArn"),
        "creation_date": S("CreationDate"),
        "encryption_key_arn": S("EncryptionKeyArn"),
        "creator_request_id": S("CreatorRequestId"),
        "number_of_recovery_points": S("NumberOfRecoveryPoints"),
        "locked": S("Locked"),
        "min_retention_days": S("MinRetentionDays"),
        "max_retention_days": S("MaxRetentionDays"),
        "lock_date": S("LockDate"),
        "arn": S("BackupVaultArn"),
    }
    backup_vault_name: Optional[str] = field(default=None, metadata={"description": "The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the Amazon Web Services Region where they are created. They consist of lowercase letters, numbers, and hyphens."})  # fmt: skip
    backup_vault_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a backup vault; for example, arn:aws:backup:us-east-1:123456789012:vault:aBackupVault."})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a resource backup is created, in Unix format and Coordinated Universal Time (UTC). The value of CreationDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    encryption_key_arn: Optional[str] = field(default=None, metadata={"description": "A server-side encryption key you can specify to encrypt your backups from services that support full Backup management; for example, arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab. If you specify a key, you must specify its ARN, not its alias. If you do not specify a key, Backup creates a KMS key for you by default. To learn which Backup services support full Backup management and how Backup handles encryption for backups from services that do not yet support full Backup, see  Encryption for backups in Backup"})  # fmt: skip
    creator_request_id: Optional[str] = field(default=None, metadata={"description": "A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice. This parameter is optional. If used, this parameter must contain 1 to 50 alphanumeric or '-_.' characters."})  # fmt: skip
    number_of_recovery_points: Optional[int] = field(default=None, metadata={"description": "The number of recovery points that are stored in a backup vault."})  # fmt: skip
    locked: Optional[bool] = field(default=None, metadata={"description": "A Boolean value that indicates whether Backup Vault Lock applies to the selected backup vault. If true, Vault Lock prevents delete and update operations on the recovery points in the selected vault."})  # fmt: skip
    min_retention_days: Optional[int] = field(default=None, metadata={"description": "The Backup Vault Lock setting that specifies the minimum retention period that the vault retains its recovery points. If this parameter is not specified, Vault Lock does not enforce a minimum retention period. If specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or longer than the minimum retention period. If the job's retention period is shorter than that minimum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. Recovery points already stored in the vault prior to Vault Lock are not affected."})  # fmt: skip
    max_retention_days: Optional[int] = field(default=None, metadata={"description": "The Backup Vault Lock setting that specifies the maximum retention period that the vault retains its recovery points. If this parameter is not specified, Vault Lock does not enforce a maximum retention period on the recovery points in the vault (allowing indefinite storage). If specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or shorter than the maximum retention period. If the job's retention period is longer than that maximum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. Recovery points already stored in the vault prior to Vault Lock are not affected."})  # fmt: skip
    lock_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time when Backup Vault Lock configuration becomes immutable, meaning it cannot be changed or deleted. If you applied Vault Lock to your vault without specifying a lock date, you can change your Vault Lock settings, or delete Vault Lock from the vault entirely, at any time. This value is in Unix format, Coordinated Universal Time (UTC), and accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    vault_policy: Optional[Json] = field(default=None)

    def resource_policy(self, builder: Any) -> List[Tuple[PolicySource, Dict[str, Any]]]:
        if not self.vault_policy or not self.arn:
            return []

        return [(PolicySource(PolicySourceKind.resource, uri=self.arn), self.vault_policy)]

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-tags"),
            AwsApiSpec(service_name, "list-recovery-points-by-backup-vault"),
            AwsApiSpec(service_name, "get-backup-vault-access-policy"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-backup-vault"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-backup-vault",
            result_name=None,
            BackupVaultName=self.name,
        )
        return True

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def collect_recovery_points(vault: AwsBackupVault) -> None:
            recovery_points = builder.client.list(
                service_name,
                "list-recovery-points-by-backup-vault",
                result_name="RecoveryPoints",
                BackupVaultName=vault.name,
            )
            AwsBackupRecoveryPoint.collect(recovery_points, builder)

        def add_tags(backup_plan: AwsBackupVault) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags",
                "Tags",
                expected_errors=["ResourceNotFoundException"],
                ResourceArn=backup_plan.backup_vault_arn,
            )
            if tags:
                for tag in tags:
                    backup_plan.tags.update(tag)

        def add_vault_policy(vault: AwsBackupVault) -> None:
            with builder.suppress(f"{service_name}.get-backup-vault-access-policy"):
                if raw_policy := builder.client.get(
                    service_name,
                    "get-backup-vault-access-policy",
                    "Policy",
                    BackupVaultName=vault.name,
                    expected_errors=["ResourceNotFoundException"],
                ):
                    vault.vault_policy = sort_json(json_loads(raw_policy), sort_list=True)  # type: ignore

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, collect_recovery_points, instance)
                builder.submit_work(service_name, add_tags, instance)
                builder.submit_work(service_name, add_vault_policy, instance)


@define(eq=False, slots=False)
class AwsBackupCalculatedLifecycle:
    kind: ClassVar[str] = "aws_backup_calculated_lifecycle"
    mapping: ClassVar[Dict[str, Bender]] = {
        "move_to_cold_storage_at": S("MoveToColdStorageAt"),
        "delete_at": S("DeleteAt"),
    }
    move_to_cold_storage_at: Optional[datetime] = field(default=None, metadata={"description": "A timestamp that specifies when to transition a recovery point to cold storage."})  # fmt: skip
    delete_at: Optional[datetime] = field(default=None, metadata={"description": "A timestamp that specifies when to delete a recovery point."})  # fmt: skip


@define(eq=False, slots=False)
class AwsBackupLifecycle:
    kind: ClassVar[str] = "aws_backup_lifecycle"
    mapping: ClassVar[Dict[str, Bender]] = {
        "move_to_cold_storage_after_days": S("MoveToColdStorageAfterDays"),
        "delete_after_days": S("DeleteAfterDays"),
        "opt_in_to_archive_for_supported_resources": S("OptInToArchiveForSupportedResources"),
    }
    move_to_cold_storage_after_days: Optional[int] = field(default=None, metadata={"description": "Specifies the number of days after creation that a recovery point is moved to cold storage."})  # fmt: skip
    delete_after_days: Optional[int] = field(default=None, metadata={"description": "Specifies the number of days after creation that a recovery point is deleted. Must be greater than 90 days plus MoveToColdStorageAfterDays."})  # fmt: skip
    opt_in_to_archive_for_supported_resources: Optional[bool] = field(default=None, metadata={"description": "Optional Boolean. If this is true, this setting will instruct your backup plan to transition supported resources to archive (cold) storage tier in accordance with your lifecycle settings."})  # fmt: skip


@define(eq=False, slots=False)
class AwsBackupRecoveryPoint(AwsResource):
    kind: ClassVar[str] = "aws_backup_recovery_point"
    _kind_display: ClassVar[str] = "AWS Backup Recovery Point"
    _kind_description: ClassVar[str] = "AWS Backup Recovery Point is a snapshot of data created by AWS Backup. It represents a point-in-time copy of resources, such as EBS volumes, RDS databases, or EFS file systems. Recovery Points can be used to restore data to a specific state, helping organizations recover from data loss or system failures."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/recovery-points.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "backup", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/backupvaults/details/{backup_vault_name}/{id}"}  # fmt: skip
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_backup_vault", "aws_backup_plan"]},
    }
    # Resource will be collect by AwsBackupVault
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("RecoveryPointArn"),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreationDate"),
        "recovery_point_arn": S("RecoveryPointArn"),
        "backup_vault_name": S("BackupVaultName"),
        "backup_vault_arn": S("BackupVaultArn"),
        "source_backup_vault_arn": S("SourceBackupVaultArn"),
        "resource_arn": S("ResourceArn"),
        "resource_type": S("ResourceType"),
        "recovery_point_created_by": S("CreatedBy") >> Bend(AwsBackupRecoveryPointCreator.mapping),
        "iam_role_arn": S("IamRoleArn"),
        "status": S("Status"),
        "status_message": S("StatusMessage"),
        "creation_date": S("CreationDate"),
        "completion_date": S("CompletionDate"),
        "backup_size_in_bytes": S("BackupSizeInBytes"),
        "calculated_lifecycle": S("CalculatedLifecycle") >> Bend(AwsBackupCalculatedLifecycle.mapping),
        "lifecycle": S("Lifecycle") >> Bend(AwsBackupLifecycle.mapping),
        "encryption_key_arn": S("EncryptionKeyArn"),
        "is_encrypted": S("IsEncrypted"),
        "last_restore_time": S("LastRestoreTime"),
        "parent_recovery_point_arn": S("ParentRecoveryPointArn"),
        "composite_member_identifier": S("CompositeMemberIdentifier"),
        "is_parent": S("IsParent"),
        "resource_name": S("ResourceName"),
        "vault_type": S("VaultType"),
        "arn": S("RecoveryPointArn"),
    }
    recovery_point_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a recovery point; for example, arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45."})  # fmt: skip
    backup_vault_name: Optional[str] = field(default=None, metadata={"description": "The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the Amazon Web Services Region where they are created. They consist of lowercase letters, numbers, and hyphens."})  # fmt: skip
    backup_vault_arn: Optional[str] = field(default=None, metadata={"description": "An ARN that uniquely identifies a backup vault; for example, arn:aws:backup:us-east-1:123456789012:vault:aBackupVault."})  # fmt: skip
    source_backup_vault_arn: Optional[str] = field(default=None, metadata={"description": "The backup vault where the recovery point was originally copied from. If the recovery point is restored to the same account this value will be null."})  # fmt: skip
    resource_arn: Optional[str] = field(default=None, metadata={"description": "An ARN that uniquely identifies a resource. The format of the ARN depends on the resource type."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of Amazon Web Services resource saved as a recovery point; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2."})  # fmt: skip
    recovery_point_created_by: Optional[AwsBackupRecoveryPointCreator] = field(default=None, metadata={"description": "Contains identifying information about the creation of a recovery point, including the BackupPlanArn, BackupPlanId, BackupPlanVersion, and BackupRuleId of the backup plan that is used to create it."})  # fmt: skip
    iam_role_arn: Optional[str] = field(default=None, metadata={"description": "Specifies the IAM role ARN used to create the target recovery point; for example, arn:aws:iam::123456789012:role/S3Access."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "A status code specifying the state of the recovery point."})  # fmt: skip
    status_message: Optional[str] = field(default=None, metadata={"description": "A message explaining the reason of the recovery point deletion failure."})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a recovery point is created, in Unix format and Coordinated Universal Time (UTC). The value of CreationDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    completion_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a job to restore a recovery point is completed, in Unix format and Coordinated Universal Time (UTC). The value of CompletionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    backup_size_in_bytes: Optional[int] = field(default=None, metadata={"description": "The size, in bytes, of a backup."})  # fmt: skip
    calculated_lifecycle: Optional[AwsBackupCalculatedLifecycle] = field(default=None, metadata={"description": "A CalculatedLifecycle object containing DeleteAt and MoveToColdStorageAt timestamps."})  # fmt: skip
    lifecycle: Optional[AwsBackupLifecycle] = field(default=None, metadata={"description": "The lifecycle defines when a protected resource is transitioned to cold storage and when it expires. Backup transitions and expires backups automatically according to the lifecycle that you define."})  # fmt: skip
    encryption_key_arn: Optional[str] = field(default=None, metadata={"description": "The server-side encryption key that is used to protect your backups; for example, arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab."})  # fmt: skip
    is_encrypted: Optional[bool] = field(default=None, metadata={"description": "A Boolean value that is returned as TRUE if the specified recovery point is encrypted, or FALSE if the recovery point is not encrypted."})  # fmt: skip
    last_restore_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time a recovery point was last restored, in Unix format and Coordinated Universal Time (UTC). The value of LastRestoreTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    parent_recovery_point_arn: Optional[str] = field(default=None, metadata={"description": "This is the Amazon Resource Name (ARN) of the parent (composite) recovery point."})  # fmt: skip
    composite_member_identifier: Optional[str] = field(default=None, metadata={"description": "This is the identifier of a resource within a composite group, such as nested (child) recovery point belonging to a composite (parent) stack. The ID is transferred from the  logical ID within a stack."})  # fmt: skip
    is_parent: Optional[bool] = field(default=None, metadata={"description": "This is a boolean value indicating this is a parent (composite) recovery point."})  # fmt: skip
    resource_name: Optional[str] = field(default=None, metadata={"description": "This is the non-unique name of the resource that belongs to the specified backup."})  # fmt: skip
    vault_type: Optional[str] = field(default=None, metadata={"description": "This is the type of vault in which the described recovery point is stored."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "delete-recovery-point"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-recovery-point",
            result_name=None,
            BackupVaultName=self.backup_vault_name,
            RecoveryPointArn=self.arn,
        )
        return True

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(recovery_point: AwsBackupRecoveryPoint) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags",
                "Tags",
                expected_errors=["ResourceNotFoundException"],
                ResourceArn=recovery_point.recovery_point_arn,
            )
            if tags:
                for tag in tags:
                    recovery_point.tags.update(tag)

        for js in json:
            if (instance := cls.from_api(js, builder)) and (isinstance(instance, AwsBackupRecoveryPoint)):
                if (status := instance.status) and (status in ["COMPLETED", "PARTIAL"]):
                    builder.add_node(instance, js)
                    builder.submit_work(service_name, add_tags, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if backup_vault_name := self.backup_vault_name:
            builder.add_edge(self, reverse=True, clazz=AwsBackupVault, name=backup_vault_name)
        if (created_by := self.recovery_point_created_by) and (backup_plan_id := created_by.backup_plan_id):
            builder.add_edge(self, reverse=True, clazz=AwsBackupPlan, id=backup_plan_id)

    @classmethod
    def service_name(cls) -> Optional[str]:
        return service_name


@define(eq=False, slots=False)
class AwsBackupReportSetting:
    kind: ClassVar[str] = "aws_backup_report_setting"
    mapping: ClassVar[Dict[str, Bender]] = {
        "report_template": S("ReportTemplate"),
        "framework_arns": S("FrameworkArns", default=[]),
        "number_of_frameworks": S("NumberOfFrameworks"),
        "accounts": S("Accounts", default=[]),
        "organization_units": S("OrganizationUnits", default=[]),
        "regions": S("Regions", default=[]),
    }
    report_template: Optional[str] = field(default=None, metadata={"description": "Identifies the report template for the report. Reports are built using a report template. The report templates are:  RESOURCE_COMPLIANCE_REPORT | CONTROL_COMPLIANCE_REPORT | BACKUP_JOB_REPORT | COPY_JOB_REPORT | RESTORE_JOB_REPORT"})  # fmt: skip
    framework_arns: Optional[List[str]] = field(factory=list, metadata={"description": "The Amazon Resource Names (ARNs) of the frameworks a report covers."})  # fmt: skip
    number_of_frameworks: Optional[int] = field(default=None, metadata={"description": "The number of frameworks a report covers."})  # fmt: skip
    accounts: Optional[List[str]] = field(factory=list, metadata={"description": "These are the accounts to be included in the report."})  # fmt: skip
    organization_units: Optional[List[str]] = field(factory=list, metadata={"description": "These are the Organizational Units to be included in the report."})  # fmt: skip
    regions: Optional[List[str]] = field(factory=list, metadata={"description": "These are the Regions to be included in the report."})  # fmt: skip


@define(eq=False, slots=False)
class AwsBackupReportDeliveryChannel:
    kind: ClassVar[str] = "aws_backup_report_delivery_channel"
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_bucket_name": S("S3BucketName"),
        "s3_key_prefix": S("S3KeyPrefix"),
        "formats": S("Formats", default=[]),
    }
    s3_bucket_name: Optional[str] = field(default=None, metadata={"description": "The unique name of the S3 bucket that receives your reports."})  # fmt: skip
    s3_key_prefix: Optional[str] = field(default=None, metadata={"description": "The prefix for where Backup Audit Manager delivers your reports to Amazon S3. The prefix is this part of the following path: s3://your-bucket-name/prefix/Backup/us-west-2/year/month/day/report-name. If not specified, there is no prefix."})  # fmt: skip
    formats: Optional[List[str]] = field(factory=list, metadata={"description": "A list of the format of your reports: CSV, JSON, or both. If not specified, the default format is CSV."})  # fmt: skip


@define(eq=False, slots=False)
class AwsBackupReportPlan(BackupResourceTaggable, AwsResource):
    kind: ClassVar[str] = "aws_backup_report_plan"
    _kind_display: ClassVar[str] = "AWS Backup Report Plan"
    _kind_description: ClassVar[str] = "AWS Backup Report Plan is a feature that generates reports on backup activities across AWS services. It provides insights into backup jobs, restore points, and protected resources. Users can schedule recurring reports or create on-demand reports, customizing content and delivery options. These reports help monitor backup compliance, track resource changes, and analyze backup trends."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/report-plans.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "plan", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/compliance/reports/details/{name}", "arn_tpl": "arn:{partition}:backup:{region}:{account}:report-plan:{name}"}  # fmt: skip
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_backup_framework"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "backup", "list-report-plans", "ReportPlans", expected_errors=["AccessDeniedException"]
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ReportPlanArn"),
        "name": S("ReportPlanName"),
        "ctime": S("CreationTime"),
        "report_plan_arn": S("ReportPlanArn"),
        "report_plan_name": S("ReportPlanName"),
        "report_plan_description": S("ReportPlanDescription"),
        "report_setting": S("ReportSetting") >> Bend(AwsBackupReportSetting.mapping),
        "report_delivery_channel": S("ReportDeliveryChannel") >> Bend(AwsBackupReportDeliveryChannel.mapping),
        "plan_deployment_status": S("DeploymentStatus"),
        "creation_time": S("CreationTime"),
        "last_attempted_execution_time": S("LastAttemptedExecutionTime"),
        "last_successful_execution_time": S("LastSuccessfulExecutionTime"),
        "arn": S("ReportPlanArn"),
    }
    report_plan_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type."})  # fmt: skip
    report_plan_name: Optional[str] = field(default=None, metadata={"description": "The unique name of the report plan. This name is between 1 and 256 characters starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_)."})  # fmt: skip
    report_plan_description: Optional[str] = field(default=None, metadata={"description": "An optional description of the report plan with a maximum 1,024 characters."})  # fmt: skip
    report_setting: Optional[AwsBackupReportSetting] = field(default=None, metadata={"description": "Identifies the report template for the report. Reports are built using a report template. The report templates are:  RESOURCE_COMPLIANCE_REPORT | CONTROL_COMPLIANCE_REPORT | BACKUP_JOB_REPORT | COPY_JOB_REPORT | RESTORE_JOB_REPORT  If the report template is RESOURCE_COMPLIANCE_REPORT or CONTROL_COMPLIANCE_REPORT, this API resource also describes the report coverage by Amazon Web Services Regions and frameworks."})  # fmt: skip
    report_delivery_channel: Optional[AwsBackupReportDeliveryChannel] = field(default=None, metadata={"description": "Contains information about where and how to deliver your reports, specifically your Amazon S3 bucket name, S3 key prefix, and the formats of your reports."})  # fmt: skip
    plan_deployment_status: Optional[str] = field(default=None, metadata={"description": "The deployment status of a report plan. The statuses are:  CREATE_IN_PROGRESS | UPDATE_IN_PROGRESS | DELETE_IN_PROGRESS | COMPLETED"})  # fmt: skip
    creation_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time that a report plan is created, in Unix format and Coordinated Universal Time (UTC). The value of CreationTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    last_attempted_execution_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time that a report job associated with this report plan last attempted to run, in Unix format and Coordinated Universal Time (UTC). The value of LastAttemptedExecutionTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    last_successful_execution_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time that a report job associated with this report plan last successfully ran, in Unix format and Coordinated Universal Time (UTC). The value of LastSuccessfulExecutionTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-report-plan"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-report-plan",
            result_name=None,
            ReportPlanName=self.name,
        )
        return True

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(report_plan: AwsBackupReportPlan) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags",
                "Tags",
                expected_errors=["ResourceNotFoundException"],
                ResourceArn=report_plan.report_plan_arn,
            )
            if tags:
                for tag in tags:
                    report_plan.tags.update(tag)

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (report_setting := self.report_setting) and (framework_arns := report_setting.framework_arns):
            for framework_arn in framework_arns:
                builder.add_edge(self, reverse=True, clazz=AwsBackupFramework, id=framework_arn)


class AwsBackupRestoreTestingPlan(BackupResourceTaggable, AwsResource):
    kind: ClassVar[str] = "aws_backup_restore_testing_plan"
    _kind_display: ClassVar[str] = "AWS Backup Restore Testing Plan"
    _kind_description: ClassVar[str] = "An AWS Backup Restore Testing Plan outlines procedures for validating backup recovery processes in AWS environments. It specifies test scenarios, recovery objectives, and success criteria for restoring data and applications from AWS Backup. This plan helps organizations verify their backup strategies, identify potential issues, and ensure reliable data recovery capabilities in case of system failures or data loss events."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "plan", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/restoretesting/details/{name}", "arn_tpl": "arn:{partition}:backup:{region}:{account}:restore-testing-plan:{name}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-restore-testing-plans", "RestoreTestingPlans")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("RestoreTestingPlanArn"),
        "name": S("RestoreTestingPlanName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastUpdateTime"),
        "creation_time": S("CreationTime"),
        "last_execution_time": S("LastExecutionTime"),
        "last_update_time": S("LastUpdateTime"),
        "restore_testing_plan_arn": S("RestoreTestingPlanArn"),
        "restore_testing_plan_name": S("RestoreTestingPlanName"),
        "schedule_expression": S("ScheduleExpression"),
        "schedule_expression_timezone": S("ScheduleExpressionTimezone"),
        "start_window_hours": S("StartWindowHours"),
        "arn": S("RestoreTestingPlanArn"),
    }
    creation_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time that a restore testing plan was created, in Unix format and Coordinated Universal Time (UTC). The value of CreationTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    last_execution_time: Optional[datetime] = field(default=None, metadata={"description": "The last time a restore test was run with the specified restore testing plan. A date and time, in Unix format and Coordinated Universal Time (UTC). The value of LastExecutionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    last_update_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time that the restore testing plan was updated. This update is in Unix format and Coordinated Universal Time (UTC). The value of LastUpdateTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    restore_testing_plan_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifiesa restore testing plan."})  # fmt: skip
    restore_testing_plan_name: Optional[str] = field(default=None, metadata={"description": "This is the restore testing plan name."})  # fmt: skip
    schedule_expression: Optional[str] = field(default=None, metadata={"description": "A CRON expression in specified timezone when a restore testing plan is executed."})  # fmt: skip
    schedule_expression_timezone: Optional[str] = field(default=None, metadata={"description": "Optional. This is the timezone in which the schedule expression is set. By default, ScheduleExpressions are in UTC. You can modify this to a specified timezone."})  # fmt: skip
    start_window_hours: Optional[int] = field(default=None, metadata={"description": "Defaults to 24 hours. A value in hours after a restore test is scheduled before a job will be canceled if it doesn't start successfully. This value is optional. If this value is included, this parameter has a maximum value of 168 hours (one week)."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-restore-testing-plan"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-restore-testing-plan",
            result_name=None,
            RestoreTestingPlanName=self.name,
        )
        return True

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(restore_plan: AwsBackupRestoreTestingPlan) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags",
                "Tags",
                expected_errors=["ResourceNotFoundException"],
                ResourceArn=restore_plan.id,
            )
            if tags:
                for tag in tags:
                    restore_plan.tags.update(tag)

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)


@define(eq=False, slots=False)
class AwsBackupLegalHold(BackupResourceTaggable, AwsResource):
    kind: ClassVar[str] = "aws_backup_legal_hold"
    _kind_display: ClassVar[str] = "AWS Backup Legal Hold"
    _kind_description: ClassVar[str] = "AWS Backup Legal Hold is a feature that preserves backup copies of data for legal or compliance purposes. It prevents the deletion or modification of specified backups, ensuring data remains intact and accessible during investigations or litigation. Users can apply legal holds to backups across multiple AWS services, maintaining data integrity and meeting regulatory requirements."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/legal-holds.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/legalholds/details/{id}", "arn_tpl": "arn:{partition}:backup:{region}:{account}:legal-hold:{id}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-legal-holds", "LegalHolds")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("LegalHoldId"),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreationDate"),
        "title": S("Title"),
        "status": S("Status"),
        "description": S("Description"),
        "legal_hold_id": S("LegalHoldId"),
        "legal_hold_arn": S("LegalHoldArn"),
        "creation_date": S("CreationDate"),
        "cancellation_date": S("CancellationDate"),
        "arn": S("LegalHoldArn"),
    }
    title: Optional[str] = field(default=None, metadata={"description": "This is the title of a legal hold."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "This is the status of the legal hold. Statuses can be ACTIVE, CREATING, CANCELED, and CANCELING."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "This is the description of a legal hold."})  # fmt: skip
    legal_hold_id: Optional[str] = field(default=None, metadata={"description": "ID of specific legal hold on one or more recovery points."})  # fmt: skip
    legal_hold_arn: Optional[str] = field(default=None, metadata={"description": "This is an Amazon Resource Number (ARN) that uniquely identifies the legal hold; for example, arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45."})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "This is the time in number format when legal hold was created."})  # fmt: skip
    cancellation_date: Optional[datetime] = field(default=None, metadata={"description": "This is the time in number format when legal hold was cancelled."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(legal_hold: AwsBackupLegalHold) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags",
                "Tags",
                expected_errors=["ResourceNotFoundException"],
                ResourceArn=legal_hold.legal_hold_arn,
            )
            if tags:
                for tag in tags:
                    legal_hold.tags.update(tag)

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)


@define(eq=False, slots=False)
class AwsBackupRestoreJob(AwsResource):
    kind: ClassVar[str] = "aws_backup_restore_job"
    _kind_display: ClassVar[str] = "AWS Backup Restore Job"
    _kind_description: ClassVar[str] = "An AWS Backup Restore Job is a process that retrieves data from an AWS Backup vault and reinstates it to its original or a new location. It recovers backed-up resources, such as databases, file systems, or EC2 instances, to a specified point in time. Users can initiate and monitor restore jobs through the AWS Management Console or API."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-a-backup.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "job", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/jobs/restore/details/{id}"}  # fmt: skip
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_backup_testing_plan", "aws_backup_recovery_point"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-restore-jobs", "RestoreJobs")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("RestoreJobId"),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreationDate"),
        "account_id": S("AccountId"),
        "restore_job_id": S("RestoreJobId"),
        "recovery_point_arn": S("RecoveryPointArn"),
        "creation_date": S("CreationDate"),
        "completion_date": S("CompletionDate"),
        "status": S("Status"),
        "status_message": S("StatusMessage"),
        "percent_done": S("PercentDone"),
        "backup_size_in_bytes": S("BackupSizeInBytes"),
        "iam_role_arn": S("IamRoleArn"),
        "expected_completion_time_minutes": S("ExpectedCompletionTimeMinutes"),
        "created_resource_arn": S("CreatedResourceArn"),
        "resource_type": S("ResourceType"),
        "recovery_point_creation_date": S("RecoveryPointCreationDate"),
        "restore_job_created_by": S("CreatedBy", "RestoreTestingPlanArn"),
        "validation_status": S("ValidationStatus"),
        "validation_status_message": S("ValidationStatusMessage"),
        "deletion_status": S("DeletionStatus"),
        "deletion_status_message": S("DeletionStatusMessage"),
    }
    account_id: Optional[str] = field(default=None, metadata={"description": "The account ID that owns the restore job."})  # fmt: skip
    restore_job_id: Optional[str] = field(default=None, metadata={"description": "Uniquely identifies the job that restores a recovery point."})  # fmt: skip
    recovery_point_arn: Optional[str] = field(default=None, metadata={"description": "An ARN that uniquely identifies a recovery point; for example, arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45."})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a restore job is created, in Unix format and Coordinated Universal Time (UTC). The value of CreationDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    completion_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a job to restore a recovery point is completed, in Unix format and Coordinated Universal Time (UTC). The value of CompletionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "A status code specifying the state of the job initiated by Backup to restore a recovery point."})  # fmt: skip
    status_message: Optional[str] = field(default=None, metadata={"description": "A detailed message explaining the status of the job to restore a recovery point."})  # fmt: skip
    percent_done: Optional[str] = field(default=None, metadata={"description": "Contains an estimated percentage complete of a job at the time the job status was queried."})  # fmt: skip
    backup_size_in_bytes: Optional[int] = field(default=None, metadata={"description": "The size, in bytes, of the restored resource."})  # fmt: skip
    iam_role_arn: Optional[str] = field(default=None, metadata={"description": "Specifies the IAM role ARN used to create the target recovery point; for example, arn:aws:iam::123456789012:role/S3Access."})  # fmt: skip
    expected_completion_time_minutes: Optional[int] = field(default=None, metadata={"description": "The amount of time in minutes that a job restoring a recovery point is expected to take."})  # fmt: skip
    created_resource_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The resource type of the listed restore jobs; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2."})  # fmt: skip
    recovery_point_creation_date: Optional[datetime] = field(default=None, metadata={"description": "The date on which a recovery point was created."})  # fmt: skip
    restore_job_created_by: Optional[str] = field(default=None, metadata={"description": "Contains identifying information about the creation of a restore job."})  # fmt: skip
    validation_status: Optional[str] = field(default=None, metadata={"description": "This is the status of validation run on the indicated restore job."})  # fmt: skip
    validation_status_message: Optional[str] = field(default=None, metadata={"description": "This describes the status of validation run on the indicated restore job."})  # fmt: skip
    deletion_status: Optional[str] = field(default=None, metadata={"description": "This notes the status of the data generated by the restore test. The status may be Deleting, Failed, or Successful."})  # fmt: skip
    deletion_status_message: Optional[str] = field(default=None, metadata={"description": "This describes the restore job deletion status."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if testing_plan_arn := self.restore_job_created_by:
            builder.add_edge(self, reverse=True, clazz=AwsBackupRestoreTestingPlan, id=testing_plan_arn)
        if recovery_point_arn := self.recovery_point_arn:
            builder.add_edge(self, reverse=True, clazz=AwsBackupRecoveryPoint, id=recovery_point_arn)


@define(eq=False, slots=False)
class AwsBackupCopyJob(AwsResource):
    kind: ClassVar[str] = "aws_backup_copy_job"
    _kind_display: ClassVar[str] = "AWS Backup Copy Job"
    _kind_description: ClassVar[str] = "AWS Backup Copy Job is a feature that creates and transfers copies of backup data between AWS Regions or AWS accounts. It automates the process of replicating backups, enhancing disaster recovery capabilities and data protection. Users can specify source and destination locations, schedule copy jobs, and manage retention policies for the copied backups."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/backup-copy-job.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "job", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/jobs/copy/details/{id}"}  # fmt: skip
    _reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_backup_plan"]},
        "successors": {"default": ["aws_backup_vault", "aws_backup_recovery_point"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-copy-jobs", "CopyJobs")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("CopyJobId"),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreationDate"),
        "account_id": S("AccountId"),
        "copy_job_id": S("CopyJobId"),
        "source_backup_vault_arn": S("SourceBackupVaultArn"),
        "source_recovery_point_arn": S("SourceRecoveryPointArn"),
        "destination_backup_vault_arn": S("DestinationBackupVaultArn"),
        "destination_recovery_point_arn": S("DestinationRecoveryPointArn"),
        "resource_arn": S("ResourceArn"),
        "creation_date": S("CreationDate"),
        "completion_date": S("CompletionDate"),
        "state": S("State"),
        "status_message": S("StatusMessage"),
        "backup_size_in_bytes": S("BackupSizeInBytes"),
        "iam_role_arn": S("IamRoleArn"),
        "copy_job_created_by": S("CreatedBy") >> Bend(AwsBackupRecoveryPointCreator.mapping),
        "resource_type": S("ResourceType"),
        "parent_job_id": S("ParentJobId"),
        "is_parent": S("IsParent"),
        "composite_member_identifier": S("CompositeMemberIdentifier"),
        "number_of_child_jobs": S("NumberOfChildJobs"),
        "child_jobs_in_state": S("ChildJobsInState"),
        "resource_name": S("ResourceName"),
        "message_category": S("MessageCategory"),
    }
    account_id: Optional[str] = field(default=None, metadata={"description": "The account ID that owns the copy job."})  # fmt: skip
    copy_job_id: Optional[str] = field(default=None, metadata={"description": "Uniquely identifies a copy job."})  # fmt: skip
    source_backup_vault_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a source copy vault; for example, arn:aws:backup:us-east-1:123456789012:vault:aBackupVault."})  # fmt: skip
    source_recovery_point_arn: Optional[str] = field(default=None, metadata={"description": "An ARN that uniquely identifies a source recovery point; for example, arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45."})  # fmt: skip
    destination_backup_vault_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a destination copy vault; for example, arn:aws:backup:us-east-1:123456789012:vault:aBackupVault."})  # fmt: skip
    destination_recovery_point_arn: Optional[str] = field(default=None, metadata={"description": "An ARN that uniquely identifies a destination recovery point; for example, arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45."})  # fmt: skip
    resource_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services resource to be copied; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database."})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a copy job is created, in Unix format and Coordinated Universal Time (UTC). The value of CreationDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    completion_date: Optional[datetime] = field(default=None, metadata={"description": "The date and time a copy job is completed, in Unix format and Coordinated Universal Time (UTC). The value of CompletionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The current state of a copy job."})  # fmt: skip
    status_message: Optional[str] = field(default=None, metadata={"description": "A detailed message explaining the status of the job to copy a resource."})  # fmt: skip
    backup_size_in_bytes: Optional[int] = field(default=None, metadata={"description": "The size, in bytes, of a copy job."})  # fmt: skip
    iam_role_arn: Optional[str] = field(default=None, metadata={"description": "Specifies the IAM role ARN used to copy the target recovery point; for example, arn:aws:iam::123456789012:role/S3Access."})  # fmt: skip
    copy_job_created_by: Optional[AwsBackupRecoveryPointCreator] = field(default=None, metadata={"description": "Contains information about the backup plan and rule that Backup used to initiate the recovery point backup."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of Amazon Web Services resource to be copied; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database."})  # fmt: skip
    parent_job_id: Optional[str] = field(default=None, metadata={"description": "This uniquely identifies a request to Backup to copy a resource. The return will be the parent (composite) job ID."})  # fmt: skip
    is_parent: Optional[bool] = field(default=None, metadata={"description": "This is a boolean value indicating this is a parent (composite) copy job."})  # fmt: skip
    composite_member_identifier: Optional[str] = field(default=None, metadata={"description": "This is the identifier of a resource within a composite group, such as nested (child) recovery point belonging to a composite (parent) stack. The ID is transferred from the  logical ID within a stack."})  # fmt: skip
    number_of_child_jobs: Optional[int] = field(default=None, metadata={"description": "This is the number of child (nested) copy jobs."})  # fmt: skip
    child_jobs_in_state: Optional[Dict[str, int]] = field(default=None, metadata={"description": "This returns the statistics of the included child (nested) copy jobs."})  # fmt: skip
    resource_name: Optional[str] = field(default=None, metadata={"description": "This is the non-unique name of the resource that belongs to the specified backup."})  # fmt: skip
    message_category: Optional[str] = field(default=None, metadata={"description": "This parameter is the job count for the specified message category. Example strings may include AccessDenied, SUCCESS, AGGREGATE_ALL, and InvalidParameters. See Monitoring for a list of MessageCategory strings. The the value ANY returns count of all message categories.  AGGREGATE_ALL aggregates job counts for all message categories and returns the sum"})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (created_by := self.copy_job_created_by) and (backup_plan_id := created_by.backup_plan_id):
            builder.add_edge(self, reverse=True, clazz=AwsBackupPlan, arn=backup_plan_id)
        if dest_vault_arn := self.destination_backup_vault_arn:
            builder.add_edge(self, clazz=AwsBackupVault, id=dest_vault_arn)
        if dest_recovery_point_arn := self.destination_recovery_point_arn:
            builder.add_edge(self, clazz=AwsBackupRecoveryPoint, id=dest_recovery_point_arn)


@define(eq=False, slots=False)
class AwsBackupFramework(BackupResourceTaggable, AwsResource):
    kind: ClassVar[str] = "aws_backup_framework"
    _kind_display: ClassVar[str] = "AWS Backup Framework"
    _kind_description: ClassVar[str] = "AWS Backup Framework is a set of tools and practices for managing data backups in Amazon Web Services. It provides centralized control for creating, scheduling, and monitoring backups across multiple AWS services. The framework helps organizations implement consistent backup policies, meet compliance requirements, and protect data from accidental deletion, system failures, or disasters."  # fmt: skip
    _docs_url: ClassVar[str] = "https://docs.aws.amazon.com/aws-backup/latest/devguide/aws-backup-framework.html"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "backup", "group": "storage"}
    _aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/backup/home?region={region_id}#/compliance/frameworks/details/{name}", "arn_tpl": "arn:{partition}:backup:{region}:{account}:framework:{name}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "backup", "list-frameworks", "Frameworks", expected_errors=["AccessDeniedException"]
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("FrameworkArn"),
        "name": S("FrameworkName"),
        "ctime": S("CreationTime"),
        "framework_name": S("FrameworkName"),
        "framework_arn": S("FrameworkArn"),
        "framework_description": S("FrameworkDescription"),
        "number_of_controls": S("NumberOfControls"),
        "creation_time": S("CreationTime"),
        "framework_deployment_status": S("DeploymentStatus"),
        "arn": S("FrameworkArn"),
    }
    framework_name: Optional[str] = field(default=None, metadata={"description": "The unique name of a framework. This name is between 1 and 256 characters, starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_)."})  # fmt: skip
    framework_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type."})  # fmt: skip
    framework_description: Optional[str] = field(default=None, metadata={"description": "An optional description of the framework with a maximum 1,024 characters."})  # fmt: skip
    number_of_controls: Optional[int] = field(default=None, metadata={"description": "The number of controls contained by the framework."})  # fmt: skip
    creation_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time that a framework is created, in ISO 8601 representation. The value of CreationTime is accurate to milliseconds. For example, 2020-07-10T15:00:00.000-08:00 represents the 10th of July 2020 at 3:00 PM 8 hours behind UTC."})  # fmt: skip
    framework_deployment_status: Optional[str] = field(default=None, metadata={"description": "The deployment status of a framework. The statuses are:  CREATE_IN_PROGRESS | UPDATE_IN_PROGRESS | DELETE_IN_PROGRESS | COMPLETED | FAILED"})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-framework"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-framework",
            result_name=None,
            FrameworkName=self.name,
        )
        return True

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(framework: AwsBackupFramework) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags",
                "Tags",
                expected_errors=["ResourceNotFoundException"],
                ResourceArn=framework.framework_arn,
            )
            if tags:
                for tag in tags:
                    framework.tags.update(tag)

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)


resources: List[Type[AwsResource]] = [
    AwsBackupJob,
    AwsBackupPlan,
    AwsBackupVault,
    AwsBackupRecoveryPoint,
    AwsBackupProtectedResource,
    AwsBackupReportPlan,
    AwsBackupRestoreTestingPlan,
    AwsBackupLegalHold,
    AwsBackupRestoreJob,
    AwsBackupCopyJob,
    AwsBackupFramework,
]
