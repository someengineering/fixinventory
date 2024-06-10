import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec
from fix_plugin_aws.utils import TagsValue, ToDict
from fixlib.json_bender import K, Bender, S, ForallBend, Bend

log = logging.getLogger("fix.plugins.aws")
service_name = "backup"


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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-backup-jobs", "BackupJobs")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("BackupJobId"),
        "tags": S("Tags", default=[]) >> ToDict(),
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


@define(eq=False, slots=False)
class AwsBackupProtectedResource(AwsResource):
    kind: ClassVar[str] = "aws_backup_protected_resource"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-protected-resources", "Results")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ResourceArn"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
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


@define(eq=False, slots=False)
class AwsBackupAdvancedBackupSetting:
    kind: ClassVar[str] = "aws_backup_advanced_backup_setting"
    mapping: ClassVar[Dict[str, Bender]] = {"resource_type": S("ResourceType"), "backup_options": S("BackupOptions")}
    resource_type: Optional[str] = field(default=None, metadata={"description": "Specifies an object containing resource type and backup options. The only supported resource type is Amazon EC2 instances with Windows Volume Shadow Copy Service (VSS). For a CloudFormation example, see the sample CloudFormation template to enable Windows VSS in the Backup User Guide. Valid values: EC2."})  # fmt: skip
    backup_options: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Specifies the backup option for a selected resource. This option is only available for Windows VSS backup jobs."})  # fmt: skip


@define(eq=False, slots=False)
class AwsBackupPlan(AwsResource):
    kind: ClassVar[str] = "aws_backup_plan"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-backup-plans", "BackupPlansList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("BackupPlanId"),
        "tags": S("Tags", default=[]) >> ToDict(),
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


@define(eq=False, slots=False)
class AwsBackupVault(AwsResource):
    kind: ClassVar[str] = "aws_backup_vault"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-backup-vaults", "BackupVaultList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("BackupVaultArn"),
        "tags": S("Tags", default=[]) >> ToDict(),
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
class AwsBackupReportPlan(AwsResource):
    kind: ClassVar[str] = "aws_backup_report_plan"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-report-plans", "ReportPlans")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ReportPlanArn"),
        "tags": S("Tags", default=[]) >> ToDict(),
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


class AwsBackupRestoreTestingPlan(AwsResource):
    kind: ClassVar[str] = "aws_backup_restore_testing_plan"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-restore-testing-plans", "RestoreTestingPlans")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("RestoreTestingPlanArn"),
        "tags": S("Tags", default=[]) >> ToDict(),
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
    }
    creation_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time that a restore testing plan was created, in Unix format and Coordinated Universal Time (UTC). The value of CreationTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    last_execution_time: Optional[datetime] = field(default=None, metadata={"description": "The last time a restore test was run with the specified restore testing plan. A date and time, in Unix format and Coordinated Universal Time (UTC). The value of LastExecutionDate is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    last_update_time: Optional[datetime] = field(default=None, metadata={"description": "The date and time that the restore testing plan was updated. This update is in Unix format and Coordinated Universal Time (UTC). The value of LastUpdateTime is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM."})  # fmt: skip
    restore_testing_plan_arn: Optional[str] = field(default=None, metadata={"description": "An Amazon Resource Name (ARN) that uniquely identifiesa restore testing plan."})  # fmt: skip
    restore_testing_plan_name: Optional[str] = field(default=None, metadata={"description": "This is the restore testing plan name."})  # fmt: skip
    schedule_expression: Optional[str] = field(default=None, metadata={"description": "A CRON expression in specified timezone when a restore testing plan is executed."})  # fmt: skip
    schedule_expression_timezone: Optional[str] = field(default=None, metadata={"description": "Optional. This is the timezone in which the schedule expression is set. By default, ScheduleExpressions are in UTC. You can modify this to a specified timezone."})  # fmt: skip
    start_window_hours: Optional[int] = field(default=None, metadata={"description": "Defaults to 24 hours. A value in hours after a restore test is scheduled before a job will be canceled if it doesn't start successfully. This value is optional. If this value is included, this parameter has a maximum value of 168 hours (one week)."})  # fmt: skip


@define(eq=False, slots=False)
class AwsBackupLegalHold(AwsResource):
    kind: ClassVar[str] = "aws_backup_legal_hold"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("backup", "list-legal-holds", "LegalHolds")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("LegalHoldId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreationDate"),
        "title": S("Title"),
        "status": S("Status"),
        "description": S("Description"),
        "legal_hold_id": S("LegalHoldId"),
        "legal_hold_arn": S("LegalHoldArn"),
        "creation_date": S("CreationDate"),
        "cancellation_date": S("CancellationDate"),
    }
    title: Optional[str] = field(default=None, metadata={"description": "This is the title of a legal hold."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "This is the status of the legal hold. Statuses can be ACTIVE, CREATING, CANCELED, and CANCELING."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "This is the description of a legal hold."})  # fmt: skip
    legal_hold_id: Optional[str] = field(default=None, metadata={"description": "ID of specific legal hold on one or more recovery points."})  # fmt: skip
    legal_hold_arn: Optional[str] = field(default=None, metadata={"description": "This is an Amazon Resource Number (ARN) that uniquely identifies the legal hold; for example, arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45."})  # fmt: skip
    creation_date: Optional[datetime] = field(default=None, metadata={"description": "This is the time in number format when legal hold was created."})  # fmt: skip
    cancellation_date: Optional[datetime] = field(default=None, metadata={"description": "This is the time in number format when legal hold was cancelled."})  # fmt: skip


resources: List[Type[AwsResource]] = [
    AwsBackupJob,
    AwsBackupPlan,
    AwsBackupVault,
    AwsBackupProtectedResource,
    AwsBackupReportPlan,
    AwsBackupRestoreTestingPlan,
    AwsBackupLegalHold,
]
