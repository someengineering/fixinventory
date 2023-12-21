from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.ec2 import AwsEc2Instance
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference
from resotolib.json_bender import Bender, S, Bend, AsDateString
from resotolib.types import Json

service_name = "ssm"


@define(eq=False, slots=False)
class AwsSSMInstanceAggregatedAssociationOverview:
    kind: ClassVar[str] = "aws_ssm_instance_aggregated_association_overview"
    mapping: ClassVar[Dict[str, Bender]] = {
        "detailed_status": S("DetailedStatus"),
        "instance_association_status_aggregated_count": S("InstanceAssociationStatusAggregatedCount"),
    }
    detailed_status: Optional[str] = field(default=None, metadata={"description": "Detailed status information about the aggregated associations."})  # fmt: skip
    instance_association_status_aggregated_count: Optional[Dict[str, int]] = field(default=None, metadata={"description": "The number of associations for the managed node(s)."})  # fmt: skip


@define(eq=False, slots=False)
class AwsSSMInstanceInformation(AwsResource):
    kind: ClassVar[str] = "aws_ssm_instance_information"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ssm", "describe-instance-information", "InstanceInformationList")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_ec2_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Name"),
        "instance_id": S("InstanceId"),
        "ping_status": S("PingStatus"),
        "last_ping": S("LastPingDateTime") >> AsDateString(),
        "agent_version": S("AgentVersion"),
        "is_latest_version": S("IsLatestVersion"),
        "platform_type": S("PlatformType"),
        "platform_name": S("PlatformName"),
        "platform_version": S("PlatformVersion"),
        "activation_id": S("ActivationId"),
        "iam_role": S("IamRole"),
        "registration_date": S("RegistrationDate") >> AsDateString(),
        "resource_type": S("ResourceType"),
        "ip_address": S("IPAddress"),
        "computer_name": S("ComputerName"),
        "association_status": S("AssociationStatus"),
        "last_association_execution_date": S("LastAssociationExecutionDate") >> AsDateString(),
        "last_successful_association_execution_date": S("LastSuccessfulAssociationExecutionDate") >> AsDateString(),
        "association_overview": S("AssociationOverview") >> Bend(AwsSSMInstanceAggregatedAssociationOverview.mapping),
        "source_id": S("SourceId"),
        "source_type": S("SourceType"),
    }
    instance_id: Optional[str] = field(default=None, metadata={"description": "The managed node ID."})  # fmt: skip
    ping_status: Optional[str] = field(default=None, metadata={"description": "Connection status of SSM Agent.   The status Inactive has been deprecated and is no longer in use."})  # fmt: skip
    last_ping: Optional[datetime] = field(default=None, metadata={"description": "The date and time when the agent last pinged the Systems Manager service."})  # fmt: skip
    agent_version: Optional[str] = field(default=None, metadata={"description": "The version of SSM Agent running on your Linux managed node."})  # fmt: skip
    is_latest_version: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the latest version of SSM Agent is running on your Linux managed node. This field doesn't indicate whether or not the latest version is installed on Windows managed nodes, because some older versions of Windows Server use the EC2Config service to process Systems Manager requests."})  # fmt: skip
    platform_type: Optional[str] = field(default=None, metadata={"description": "The operating system platform type."})  # fmt: skip
    platform_name: Optional[str] = field(default=None, metadata={"description": "The name of the operating system platform running on your managed node."})  # fmt: skip
    platform_version: Optional[str] = field(default=None, metadata={"description": "The version of the OS platform running on your managed node."})  # fmt: skip
    activation_id: Optional[str] = field(default=None, metadata={"description": "The activation ID created by Amazon Web Services Systems Manager when the server or virtual machine (VM) was registered."})  # fmt: skip
    iam_role: Optional[str] = field(default=None, metadata={"description": "The Identity and Access Management (IAM) role assigned to the on-premises Systems Manager managed node. This call doesn't return the IAM role for Amazon Elastic Compute Cloud (Amazon EC2) instances. To retrieve the IAM role for an EC2 instance, use the Amazon EC2 DescribeInstances operation. For information, see DescribeInstances in the Amazon EC2 API Reference or describe-instances in the Amazon Web Services CLI Command Reference."})  # fmt: skip
    registration_date: Optional[datetime] = field(default=None, metadata={"description": "The date the server or VM was registered with Amazon Web Services as a managed node."})  # fmt: skip
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of instance. Instances are either EC2 instances or managed instances."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name assigned to an on-premises server, edge device, or virtual machine (VM) when it is activated as a Systems Manager managed node. The name is specified as the DefaultInstanceName property using the CreateActivation command. It is applied to the managed node by specifying the Activation Code and Activation ID when you install SSM Agent on the node, as explained in Install SSM Agent for a hybrid environment (Linux) and Install SSM Agent for a hybrid environment (Windows). To retrieve the Name tag of an EC2 instance, use the Amazon EC2 DescribeInstances operation. For information, see DescribeInstances in the Amazon EC2 API Reference or describe-instances in the Amazon Web Services CLI Command Reference."})  # fmt: skip
    ip_address: Optional[str] = field(default=None, metadata={"description": "The IP address of the managed node."})  # fmt: skip
    computer_name: Optional[str] = field(default=None, metadata={"description": "The fully qualified host name of the managed node."})  # fmt: skip
    association_status: Optional[str] = field(default=None, metadata={"description": "The status of the association."})  # fmt: skip
    last_association_execution_date: Optional[datetime] = field(default=None, metadata={"description": "The date the association was last run."})  # fmt: skip
    last_successful_association_execution_date: Optional[datetime] = field(default=None, metadata={"description": "The last date the association was successfully run."})  # fmt: skip
    association_overview: Optional[AwsSSMInstanceAggregatedAssociationOverview] = field(default=None, metadata={"description": "Information about the association."})  # fmt: skip
    source_id: Optional[str] = field(default=None, metadata={"description": "The ID of the source resource. For IoT Greengrass devices, SourceId is the Thing name."})  # fmt: skip
    source_type: Optional[str] = field(default=None, metadata={"description": "The type of the source resource. For IoT Greengrass devices, SourceType is AWS::IoT::Thing."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.resource_type == "EC2Instance" and (instance_id := self.instance_id):
            builder.dependant_node(self, clazz=AwsEc2Instance, id=instance_id)


resources: List[Type[AwsResource]] = [AwsSSMInstanceInformation]
