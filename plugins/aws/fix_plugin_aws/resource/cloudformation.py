import time
from datetime import datetime
from typing import Any, ClassVar, Dict, Literal, Optional, List, Type, cast

from attrs import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import BaseStack, ModelReference
from fixlib.graph import ByNodeId, BySearchCriteria, Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend, F
from fixlib.types import Json

service_name = "cloudformation"


@define(eq=False, slots=False)
class AwsCloudFormationRollbackTrigger:
    kind: ClassVar[str] = "aws_cloudformation_rollback_trigger"
    kind_display: ClassVar[str] = "AWS CloudFormation Rollback Trigger"
    kind_description: ClassVar[str] = (
        "AWS CloudFormation Rollback Trigger is a feature that allows you to specify"
        " criteria to determine when CloudFormation should roll back a stack"
        " operation. When the specified criteria are met, CloudFormation automatically"
        " rolls back any changes made during the stack operation to the previously"
        " deployed state."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "type": S("Type")}
    arn: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationRollbackConfiguration:
    kind: ClassVar[str] = "aws_cloudformation_rollback_configuration"
    kind_display: ClassVar[str] = "AWS CloudFormation Rollback Configuration"
    kind_description: ClassVar[str] = (
        "AWS CloudFormation Rollback Configuration allows users to specify the"
        " conditions under which an AWS CloudFormation stack rollback is triggered."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "rollback_triggers": S("RollbackTriggers", default=[]) >> ForallBend(AwsCloudFormationRollbackTrigger.mapping),
        "monitoring_time_in_minutes": S("MonitoringTimeInMinutes"),
    }
    rollback_triggers: List[AwsCloudFormationRollbackTrigger] = field(factory=list)
    monitoring_time_in_minutes: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationOutput:
    kind: ClassVar[str] = "aws_cloudformation_output"
    kind_display: ClassVar[str] = "AWS CloudFormation Output"
    kind_description: ClassVar[str] = (
        "AWS CloudFormation Output represents the values that are provided by a"
        " CloudFormation stack and can be accessed by other resources in the same"
        " stack."
    )
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
    kind_display: ClassVar[str] = "AWS CloudFormation Stack Drift Information"
    kind_description: ClassVar[str] = (
        "CloudFormation Stack Drift Information provides details about any drift that"
        " has occurred in an AWS CloudFormation stack. Stack drift occurs when the"
        " actual state of the stack resources diverges from their expected state as"
        " defined in the stack template."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "stack_drift_status": S("StackDriftStatus"),
        "last_check_timestamp": S("LastCheckTimestamp"),
    }
    stack_drift_status: Optional[str] = field(default=None)
    last_check_timestamp: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationStack(AwsResource, BaseStack):
    kind: ClassVar[str] = "aws_cloudformation_stack"
    kind_display: ClassVar[str] = "AWS CloudFormation Stack"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/stackinfo?stackId={id}", "arn_tpl": "arn:{partition}:cloudformation:{region}:{account}:stack/{name}/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudFormation Stacks are a collection of AWS resources that are created,"
        " updated, or deleted together as a single unit."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-stacks", "Stacks")
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_resource"]}}
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
    _stack_resources: Optional[List[Json]] = None

    def post_process(self, builder: GraphBuilder, source: Json) -> None:
        def stack_resources() -> None:
            # list all stack resources - we will create edges in connect_in_graph
            self._stack_resources = builder.client.list(
                service_name, "list-stack-resources", "StackResourceSummaries", StackName=self.name
            )

        builder.submit_work(service_name, stack_resources)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self._stack_resources:
            for resource in self._stack_resources:
                if (rid := resource.get("PhysicalResourceId")) and (rt := resource.get("ResourceType")):
                    # we translate the resource type to the internal kind: AWS::IAM::User --> aws_iam_user
                    # there are a lot of exceptions in AWS, that we need to handle.
                    kind = rt.replace("::", "_").lower()
                    # what cloudformation calls "PhysicalResourceId" is the name of the resource
                    builder.add_edge(self, name=rid, kind=kind)

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
            client.list(aws_service=service, action="describe-stacks", result_name="Stacks", StackName=self.name)[0],
        )
        stack = self._wait_for_completion(client, stack, service)

        try:
            client.call(
                aws_service=service_name,
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
                client.list(aws_service=service, action="describe-stacks", result_name="Stacks", StackName=self.name)[
                    0
                ],
            )
        return stack

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return self._modify_tag(client, key, value, "update")

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return self._modify_tag(client, key, None, "delete")

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-stack", result_name=None, StackName=self.name)
        return True

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "list-stacks"), AwsApiSpec(service_name, "list-stack-resources")]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "update-stack"), AwsApiSpec(service_name, "delete-stack")]


@define(eq=False, slots=False)
class AwsCloudFormationAutoDeployment:
    kind: ClassVar[str] = "aws_cloudformation_auto_deployment"
    kind_display: ClassVar[str] = "AWS CloudFormation Auto Deployment"
    kind_description: ClassVar[str] = (
        "AWS CloudFormation Auto Deployment is a setting within AWS CloudFormation that enables the automatic"
        " deployment and updating of stacks or resources, typically in response to direct changes to source"
        " code or a deployment pipeline, streamlining the deployment process."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "retain_stacks_on_account_removal": S("RetainStacksOnAccountRemoval"),
    }
    enabled: Optional[bool] = field(default=None)
    retain_stacks_on_account_removal: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsCloudFormationStackSet(AwsResource):
    kind: ClassVar[str] = "aws_cloudformation_stack_set"
    kind_display: ClassVar[str] = "AWS CloudFormation Stack Set"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/cloudformation/home?region={region}#/stacksets/{name}/info?permissions=self", "arn_tpl": "arn:{partition}:cloudformation:{region}:{account}:stack-set/{name}/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "CloudFormation Stack Set is a feature in AWS CloudFormation that enables you"
        " to create, update, or delete stacks across multiple accounts and regions"
        " with a single CloudFormation template."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-stack-sets", "Summaries", dict(Status="ACTIVE"))
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

    @classmethod
    def collect(cls, json: List[Json], builder: GraphBuilder) -> None:
        def stack_set_instances(ss: AwsCloudFormationStackSet) -> None:
            for sij in builder.client.list(service_name, "list-stack-instances", "Summaries", StackSetName=ss.name):
                if sii := AwsCloudFormationStackInstanceSummary.from_api(sij, builder):
                    builder.add_node(sii, sij)
                    builder.add_edge(ss, node=sii)
                    builder.graph.add_deferred_edge(
                        ByNodeId(ss.chksum),
                        BySearchCriteria(
                            f'is(aws_cloudformation_stack) and reported.id="{sii.stack_instance_stack_id}"'
                        ),
                    )

        for js in json:
            if stack_set := cls.from_api(js, builder):
                builder.add_node(stack_set, js)
                builder.submit_work(service_name, stack_set_instances, stack_set)

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
                aws_service=service_name,
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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-stack-set",
            result_name=None,
            StackSetName=self.name,
        )
        return True

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "list-stack-instances")]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "update-stack-set"), AwsApiSpec(service_name, "delete-stack-set")]


def _stack_instance_id(stack: Json) -> str:
    stack_id = stack.get("StackId", "").rsplit("/", 1)[-1]
    stack_set_id = stack.get("StackSetId", "")
    account = stack.get("Account", "")
    region = stack.get("Region", "")
    return f"{stack_set_id}/{stack_id}/{account}/{region}"


@define(eq=False, slots=False)
class AwsCloudFormationStackInstanceSummary(AwsResource):
    # note: resource is collected via AwsCloudFormationStackSet
    kind: ClassVar[str] = "aws_cloud_formation_stack_instance_summary"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:cloudformation:{region}:{account}:stack-instance/{id}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS CloudFormation Stack Instance Summary"
    kind_description: ClassVar[str] = (
        "CloudFormation Stack Instance Summary provides a summary of the overall stacks in a CloudFormation"
        " deployment. The information includes current status, name, and any associated resources or parameters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": F(_stack_instance_id),
        "stack_instance_stack_set_id": S("StackSetId"),
        "stack_instance_region": S("Region"),
        "stack_instance_account": S("Account"),
        "stack_instance_stack_id": S("StackId"),
        "stack_instance_status": S("Status"),
        "stack_instance_status_reason": S("StatusReason"),
        "stack_instance_stack_instance_status": S("StackInstanceStatus", "DetailedStatus"),
        "stack_instance_organizational_unit_id": S("OrganizationalUnitId"),
        "stack_instance_drift_status": S("DriftStatus"),
        "stack_instance_last_drift_check_timestamp": S("LastDriftCheckTimestamp"),
        "stack_instance_last_operation_id": S("LastOperationId"),
    }
    stack_instance_stack_set_id: Optional[str] = field(default=None)
    stack_instance_region: Optional[str] = field(default=None)
    stack_instance_account: Optional[str] = field(default=None)
    stack_instance_stack_id: Optional[str] = field(default=None)
    stack_instance_status: Optional[str] = field(default=None)
    stack_instance_status_reason: Optional[str] = field(default=None)
    stack_instance_stack_instance_status: Optional[str] = field(default=None)
    stack_instance_organizational_unit_id: Optional[str] = field(default=None)
    stack_instance_drift_status: Optional[str] = field(default=None)
    stack_instance_last_drift_check_timestamp: Optional[datetime] = field(default=None)
    stack_instance_last_operation_id: Optional[str] = field(default=None)

    @classmethod
    def service_name(cls) -> str:
        return service_name


resources: List[Type[AwsResource]] = [
    AwsCloudFormationStack,
    AwsCloudFormationStackSet,
    AwsCloudFormationStackInstanceSummary,
]
