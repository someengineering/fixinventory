from datetime import datetime
import time
from typing import Any, ClassVar, Dict, Literal, Optional, List, Type, cast

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import BaseStack
from resotolib.json_bender import Bender, S, Bend, ForallBend
from resoto_plugin_aws.aws_client import AwsClient
from resotolib.types import Json


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

    def _modify_tag(self, client: AwsClient, key: str, value: Optional[str], mode: Literal["delete", "update"]) -> bool:
        tags = dict(self.tags)
        if mode == "delete":
            if not self.tags.get(key):
                raise KeyError(key)
            del tags[key]
        elif mode == "update":
            if self.tags.get(key) == value:
                return True
            tags.update({key: value})
        else:
            return False
        service = self.api_spec.service
        stack = cast(
            Json,
            client.call(aws_service=service, action="describe_stacks", result_name="Stacks", StackName=self.name)[0],
        )
        stack = self._wait_for_completion(client, stack, service)

        try:
            client.call(
                aws_service="cloudformation",
                action="update-stack",
                result_name=None,
                StackName=self.name,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                UsePreviousTemplate=True,
                Tags=[{"Key": label, "Value": value} for label, value in tags.items()],
                Parameters=[
                    {"ParameterKey": parameter, "UsePreviousValue": True} for parameter in self.stack_parameters.keys()
                ],
            )
        except Exception as e:
            raise RuntimeError(f"Error updating AWS Cloudformation Stack {self.dname} for {mode} of tag {key}") from e
        return True

    def _wait_for_completion(self, client: AwsClient, stack: Json, service: str, timeout: int = 300) -> Json:
        start_utime = time.time()
        while stack["StackStatus"].endswith("_IN_PROGRESS"):
            if time.time() > start_utime + timeout:
                raise TimeoutError(
                    (
                        f"AWS Cloudformation Stack {self.dname} tag update timed out "
                        f"after {timeout} seconds with status {stack['StackStatus']}"
                    )
                )
            time.sleep(5)
            stack = cast(
                Json,
                client.call(aws_service=service, action="describe_stacks", result_name="Stacks", StackName=self.name),
            )
        return stack

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return self._modify_tag(client, key, value, "update")

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return self._modify_tag(client, key, None, "delete")

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-stack", result_name=None, StackName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("cloudformation", "update-stack"), AwsApiSpec("cloudformation", "delete-stack")]


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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("cloudformation", "list-stack-sets", "Summaries", dict(Status="ACTIVE"))
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
        "stack_set_parameters": S("Parameters", default=[]) >> ToDict("ParameterKey", "ParameterValue"),
    }
    description: Optional[str] = field(default=None)
    stack_set_status: Optional[str] = field(default=None)
    stack_set_auto_deployment: Optional[AwsCloudFormationAutoDeployment] = field(default=None)
    stack_set_permission_model: Optional[str] = field(default=None)
    stack_set_drift_status: Optional[str] = field(default=None)
    stack_set_last_drift_check_timestamp: Optional[datetime] = field(default=None)
    stack_set_managed_execution: Optional[bool] = field(default=None)
    stack_set_parameters: Optional[Dict[str, Any]] = None

    def _modify_tag(self, client: AwsClient, key: str, value: Optional[str], mode: Literal["update", "delete"]) -> bool:
        tags = dict(self.tags)
        if mode == "delete":
            if not self.tags.get(key):
                raise KeyError(key)
            del tags[key]
        elif mode == "update":
            if self.tags.get(key) == value:
                return True
            tags.update({key: value})
        else:
            return False

        try:
            client.call(
                aws_service="cloudformation",
                action="update-stack-set",
                result_name=None,
                StackSetName=self.name,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                UsePreviousTemplate=True,
                Tags=[{"Key": label, "Value": value} for label, value in tags.items()],
                Parameters=[
                    {"ParameterKey": parameter, "UsePreviousValue": True}
                    for parameter in (self.stack_set_parameters or {}).keys()
                ],
            )
        except Exception as e:
            raise RuntimeError(
                "Error updating AWS Cloudformation Stack Set" f" {self.dname} for {mode} of tag {key}"
            ) from e

        return True

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return self._modify_tag(client, key, value, "update")

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return self._modify_tag(client, key, None, "delete")

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-stack-set",
            result_name=None,
            StackSetName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("cloudformation", "update-stack-set"), AwsApiSpec("cloudformation", "delete-stack-set")]


resources: List[Type[AwsResource]] = [AwsCloudFormationStack, AwsCloudFormationStackSet]
