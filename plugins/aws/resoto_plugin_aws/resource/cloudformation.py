from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import BaseStack, BaseAccount  # noqa: F401
from resotolib.json_bender import Bender, S, Bend, ForallBend


@define(eq=False, slots=False)
class AwsCloudFormationRollbackTrigger:
    kind: ClassVar[str] = "aws_cloudformation_rollback_trigger"
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "type": S("Type")}
    arn: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationRollbackConfiguration:
    kind: ClassVar[str] = "aws_cloudformation_rollback_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rollback_triggers": S("RollbackTriggers", default=[]) >> ForallBend(AwsCloudFormationRollbackTrigger.mapping),
        "monitoring_time_in_minutes": S("MonitoringTimeInMinutes"),
    }
    rollback_triggers: List[AwsCloudFormationRollbackTrigger] = field(factory=list)
    monitoring_time_in_minutes: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationOutput:
    kind: ClassVar[str] = "aws_cloudformation_output"
    mapping: ClassVar[Dict[str, Bender]] = {
        "output_key": S("OutputKey"),
        "output_value": S("OutputValue"),
        "description": S("Description"),
        "export_name": S("ExportName"),
    }
    output_key: Optional[str] = field(default=None)
    output_value: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    export_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationStackDriftInformation:
    kind: ClassVar[str] = "aws_cloudformation_stack_drift_information"
    mapping: ClassVar[Dict[str, Bender]] = {
        "stack_drift_status": S("StackDriftStatus"),
        "last_check_timestamp": S("LastCheckTimestamp"),
    }
    stack_drift_status: Optional[str] = field(default=None)
    last_check_timestamp: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationStack(AwsResource, BaseStack):
    kind: ClassVar[str] = "aws_cloudformation_stack"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudformation", "describe-stacks", "Stacks")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("StackId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("StackName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastUpdatedTime"),
        "stack_status": S("StackStatus", default=""),
        "stack_status_reason": S("StackStatusReason", default=""),
        "stack_parameters": S("Parameters", default=[]) >> ToDict("ParameterKey", "ParameterValue"),
        "stack_change_set_id": S("ChangeSetId"),
        "description": S("Description"),
        "stack_deletion_time": S("DeletionTime"),
        "stack_rollback_configuration": S("RollbackConfiguration")
        >> Bend(AwsCloudFormationRollbackConfiguration.mapping),
        "stack_disable_rollback": S("DisableRollback"),
        "stack_notification_ar_ns": S("NotificationARNs", default=[]),
        "stack_timeout_in_minutes": S("TimeoutInMinutes"),
        "stack_capabilities": S("Capabilities", default=[]),
        "stack_outputs": S("Outputs", default=[]) >> ForallBend(AwsCloudFormationOutput.mapping),
        "stack_role_arn": S("RoleARN"),
        "stack_enable_termination_protection": S("EnableTerminationProtection"),
        "stack_parent_id": S("ParentId"),
        "stack_root_id": S("RootId"),
        "stack_drift_information": S("DriftInformation") >> Bend(AwsCloudFormationStackDriftInformation.mapping),
    }
    stack_change_set_id: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    stack_deletion_time: Optional[datetime] = field(default=None)
    stack_rollback_configuration: Optional[AwsCloudFormationRollbackConfiguration] = field(default=None)
    stack_disable_rollback: Optional[bool] = field(default=None)
    stack_notification_ar_ns: List[str] = field(factory=list)
    stack_timeout_in_minutes: Optional[int] = field(default=None)
    stack_capabilities: List[str] = field(factory=list)
    stack_outputs: List[AwsCloudFormationOutput] = field(factory=list)
    stack_role_arn: Optional[str] = field(default=None)
    stack_enable_termination_protection: Optional[bool] = field(default=None)
    stack_parent_id: Optional[str] = field(default=None)
    stack_root_id: Optional[str] = field(default=None)
    stack_drift_information: Optional[AwsCloudFormationStackDriftInformation] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationAutoDeployment:
    kind: ClassVar[str] = "aws_cloudformation_auto_deployment"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "retain_stacks_on_account_removal": S("RetainStacksOnAccountRemoval"),
    }
    enabled: Optional[bool] = field(default=None)
    retain_stacks_on_account_removal: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationStackSet(AwsResource):
    kind: ClassVar[str] = "aws_cloudformation_stack_set"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudformation", "list-stack-sets", "Summaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("StackSetId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("StackSetName"),
        "description": S("Description"),
        "stack_set_status": S("Status"),
        "stack_set_auto_deployment": S("AutoDeployment") >> Bend(AwsCloudFormationAutoDeployment.mapping),
        "stack_set_permission_model": S("PermissionModel"),
        "stack_set_drift_status": S("DriftStatus"),
        "stack_set_last_drift_check_timestamp": S("LastDriftCheckTimestamp"),
        "stack_set_managed_execution": S("ManagedExecution", "Active"),
    }
    description: Optional[str] = field(default=None)
    stack_set_status: Optional[str] = field(default=None)
    stack_set_auto_deployment: Optional[AwsCloudFormationAutoDeployment] = field(default=None)
    stack_set_permission_model: Optional[str] = field(default=None)
    stack_set_drift_status: Optional[str] = field(default=None)
    stack_set_last_drift_check_timestamp: Optional[datetime] = field(default=None)
    stack_set_managed_execution: Optional[bool] = field(default=None)


resources: List[Type[AwsResource]] = [AwsCloudFormationStack, AwsCloudFormationStackSet]
