from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import BaseStack
from resotolib.json_bender import Bender, S, Bend, ForallBend


@define(eq=False, slots=False)
class AwsCloudFormationRollbackTrigger:
    kind: ClassVar[str] = "aws_cloud_formation_rollback_trigger"
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "type": S("Type")}
    arn: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationRollbackConfiguration:
    kind: ClassVar[str] = "aws_cloud_formation_rollback_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rollback_triggers": S("RollbackTriggers", default=[]) >> ForallBend(AwsCloudFormationRollbackTrigger.mapping),
        "monitoring_time_in_minutes": S("MonitoringTimeInMinutes"),
    }
    rollback_triggers: List[AwsCloudFormationRollbackTrigger] = field(factory=list)
    monitoring_time_in_minutes: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationOutput:
    kind: ClassVar[str] = "aws_cloud_formation_output"
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
    kind: ClassVar[str] = "aws_cloud_formation_stack_drift_information"
    mapping: ClassVar[Dict[str, Bender]] = {
        "stack_drift_status": S("StackDriftStatus"),
        "last_check_timestamp": S("LastCheckTimestamp"),
    }
    stack_drift_status: Optional[str] = field(default=None)
    last_check_timestamp: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationStack(AwsResource, BaseStack):
    kind: ClassVar[str] = "aws_cloud_formation_stack"
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
        "cloud_formation_change_set_id": S("ChangeSetId"),
        "cloud_formation_description": S("Description"),
        "cloud_formation_deletion_time": S("DeletionTime"),
        "cloud_formation_rollback_configuration": S("RollbackConfiguration")
        >> Bend(AwsCloudFormationRollbackConfiguration.mapping),
        "cloud_formation_disable_rollback": S("DisableRollback"),
        "cloud_formation_notification_ar_ns": S("NotificationARNs", default=[]),
        "cloud_formation_timeout_in_minutes": S("TimeoutInMinutes"),
        "cloud_formation_capabilities": S("Capabilities", default=[]),
        "cloud_formation_outputs": S("Outputs", default=[]) >> ForallBend(AwsCloudFormationOutput.mapping),
        "cloud_formation_role_arn": S("RoleARN"),
        "cloud_formation_enable_termination_protection": S("EnableTerminationProtection"),
        "cloud_formation_parent_id": S("ParentId"),
        "cloud_formation_root_id": S("RootId"),
        "cloud_formation_drift_information": S("DriftInformation")
        >> Bend(AwsCloudFormationStackDriftInformation.mapping),
    }
    cloud_formation_change_set_id: Optional[str] = field(default=None)
    cloud_formation_description: Optional[str] = field(default=None)
    cloud_formation_deletion_time: Optional[datetime] = field(default=None)
    cloud_formation_rollback_configuration: Optional[AwsCloudFormationRollbackConfiguration] = field(default=None)
    cloud_formation_disable_rollback: Optional[bool] = field(default=None)
    cloud_formation_notification_ar_ns: List[str] = field(factory=list)
    cloud_formation_timeout_in_minutes: Optional[int] = field(default=None)
    cloud_formation_capabilities: List[str] = field(factory=list)
    cloud_formation_outputs: List[AwsCloudFormationOutput] = field(factory=list)
    cloud_formation_role_arn: Optional[str] = field(default=None)
    cloud_formation_enable_termination_protection: Optional[bool] = field(default=None)
    cloud_formation_parent_id: Optional[str] = field(default=None)
    cloud_formation_root_id: Optional[str] = field(default=None)
    cloud_formation_drift_information: Optional[AwsCloudFormationStackDriftInformation] = field(default=None)


resources: List[Type[AwsResource]] = [AwsCloudFormationStack]
