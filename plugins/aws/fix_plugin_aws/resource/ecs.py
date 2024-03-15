from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.autoscaling import AwsAutoScalingGroup

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from fix_plugin_aws.resource.ec2 import AwsEc2Instance, AwsEc2SecurityGroup, AwsEc2Subnet
from fix_plugin_aws.resource.elb import AwsElb
from fix_plugin_aws.resource.elbv2 import AwsAlbTargetGroup
from fix_plugin_aws.resource.iam import AwsIamRole
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.s3 import AwsS3Bucket
from fixlib.baseresources import EdgeType, ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import F, Bender, S, Bend, ForallBend
from fixlib.types import Json
from fixlib.utils import chunks
from fix_plugin_aws.utils import TagsValue, ToDict

service_name = "ecs"


class EcsTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="tag-resource",
                result_name=None,
                resourceArn=self.arn,
                tags=[{"key": key, "value": value}],
            )
            return True
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="untag-resource",
                result_name=None,
                resourceArn=self.arn,
                tagKeys=[key],
            )
            return True
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "tag-resource"), AwsApiSpec(service_name, "untag-resource")]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsEcsManagedScaling:
    kind: ClassVar[str] = "aws_ecs_managed_scaling"
    kind_display: ClassVar[str] = "AWS ECS Managed Scaling"
    kind_description: ClassVar[str] = (
        "ECS Managed Scaling is a feature of Amazon Elastic Container Service (ECS)"
        " that automatically adjusts the number of running tasks in an ECS service"
        " based on demand or a specified scaling policy."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("status"),
        "target_capacity": S("targetCapacity"),
        "minimum_scaling_step_size": S("minimumScalingStepSize"),
        "maximum_scaling_step_size": S("maximumScalingStepSize"),
        "instance_warmup_period": S("instanceWarmupPeriod"),
    }
    status: Optional[str] = field(default=None)
    target_capacity: Optional[int] = field(default=None)
    minimum_scaling_step_size: Optional[int] = field(default=None)
    maximum_scaling_step_size: Optional[int] = field(default=None)
    instance_warmup_period: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsAutoScalingGroupProvider:
    kind: ClassVar[str] = "aws_ecs_auto_scaling_group_provider"
    kind_display: ClassVar[str] = "AWS ECS Auto Scaling Group Provider"
    kind_description: ClassVar[str] = (
        "ECS Auto Scaling Group Provider is a service in AWS that allows for"
        " automatic scaling of a containerized application deployed on Amazon ECS"
        " (Elastic Container Service) using Auto Scaling Groups."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_scaling_group_arn": S("autoScalingGroupArn"),
        "managed_scaling": S("managedScaling") >> Bend(AwsEcsManagedScaling.mapping),
        "managed_termination_protection": S("managedTerminationProtection"),
    }
    auto_scaling_group_arn: Optional[str] = field(default=None)
    managed_scaling: Optional[AwsEcsManagedScaling] = field(default=None)
    managed_termination_protection: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsCapacityProvider(EcsTaggable, AwsResource):
    # collection of capacity provider resources happens in AwsEcsCluster.collect()
    kind: ClassVar[str] = "aws_ecs_capacity_provider"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:ecs:{region}:{account}:capacity-provider/{name}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS ECS Capacity Provider"
    kind_description: ClassVar[str] = (
        "ECS Capacity Providers are used in Amazon's Elastic Container Service to"
        " manage the capacity and scaling for containerized applications."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_autoscaling_group"]},
        "successors": {"default": ["aws_autoscaling_group"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name"),
        "name": S("name"),
        "tags": S("tags", default=[]) >> ToDict(key="key", value="value"),
        "arn": S("capacityProviderArn"),
        "status": S("status"),
        "capacity_provider_auto_scaling_group_provider": S("autoScalingGroupProvider")
        >> Bend(AwsEcsAutoScalingGroupProvider.mapping),
        "capacity_provider_update_status": S("updateStatus"),
        "capacity_provider_update_status_reason": S("updateStatusReason"),
    }
    status: Optional[str] = field(default=None)
    capacity_provider_auto_scaling_group_provider: Optional[AwsEcsAutoScalingGroupProvider] = field(default=None)
    capacity_provider_update_status: Optional[str] = field(default=None)
    capacity_provider_update_status_reason: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.capacity_provider_auto_scaling_group_provider:
            builder.dependant_node(
                self,
                clazz=AwsAutoScalingGroup,
                arn=self.capacity_provider_auto_scaling_group_provider.auto_scaling_group_arn,
            )

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        for predecessor in self.predecessors(graph=graph, edge_type=EdgeType.default):
            if isinstance(predecessor, AwsEcsService):
                predecessor.purge_capacity_provider(client=client, capacity_provider_name=self.safe_name)
            if isinstance(predecessor, AwsEcsCluster):
                predecessor.disassociate_capacity_provider(client=client, capacity_provider_name=self.safe_name)
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(service_name, "delete-capacity-provider", None, capacityProvider=self.safe_name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "update-service"),
            AwsApiSpec(service_name, "put-cluster-capacity-providers"),
            AwsApiSpec(service_name, "delete-capacity-provider"),
            AwsApiSpec(service_name, "put-cluster-capacity-providers"),
        ]


@define(eq=False, slots=False)
class AwsEcsKeyValuePair:
    kind: ClassVar[str] = "aws_ecs_key_value_pair"
    kind_display: ClassVar[str] = "AWS ECS Key Value Pair"
    kind_description: ClassVar[str] = (
        "A key value pair is a simple data structure used in AWS ECS (Elastic"
        " Container Service) to store and manage the metadata associated with"
        " containers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsAttachment:
    kind: ClassVar[str] = "aws_ecs_attachment"
    kind_display: ClassVar[str] = "AWS ECS Attachment"
    kind_description: ClassVar[str] = (
        "AWS ECS Attachment represents a link between an ECS resource, like a container instance,"
        " and a network or security group. It includes identifiers and status information that"
        " help manage and track the resource's integration and operational state within the ECS environment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "type": S("type"),
        "status": S("status"),
        "details": S("details", default=[]) >> ForallBend(AwsEcsKeyValuePair.mapping),
    }
    id: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    details: List[AwsEcsKeyValuePair] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsAttribute:
    kind: ClassVar[str] = "aws_ecs_attribute"
    kind_display: ClassVar[str] = "AWS ECS Attribute"
    kind_description: ClassVar[str] = (
        "ECS (Elastic Container Service) Attribute is a key-value pair that can be"
        " assigned to a specific ECS resource, such as a task definition or a service,"
        " to provide additional information or configuration settings."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "value": S("value"),
        "target_type": S("targetType"),
        "target_id": S("targetId"),
    }
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)
    target_type: Optional[str] = field(default=None)
    target_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsNetworkBinding:
    kind: ClassVar[str] = "aws_ecs_network_binding"
    kind_display: ClassVar[str] = "AWS ECS Network Binding"
    kind_description: ClassVar[str] = (
        "The AWS ECS Network Binding sets up the networking parameters for an ECS container,"
        " defining how a container port is bound to a host port, the IP address it should bind"
        " to, and the network protocol to be used."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "bind_ip": S("bindIP"),
        "container_port": S("containerPort"),
        "host_port": S("hostPort"),
        "protocol": S("protocol"),
    }
    bind_ip: Optional[str] = field(default=None)
    container_port: Optional[int] = field(default=None)
    host_port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsNetworkInterface:
    kind: ClassVar[str] = "aws_ecs_network_interface"
    kind_display: ClassVar[str] = "AWS ECS Network Interface"
    kind_description: ClassVar[str] = (
        "ECS Network Interface is a networking component used by the Amazon Elastic"
        " Container Service (ECS) to connect containers to network resources within"
        " the AWS cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "attachment_id": S("attachmentId"),
        "private_ipv4_address": S("privateIpv4Address"),
        "ipv6_address": S("ipv6Address"),
    }
    attachment_id: Optional[str] = field(default=None)
    private_ipv4_address: Optional[str] = field(default=None)
    ipv6_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsManagedAgent:
    kind: ClassVar[str] = "aws_ecs_managed_agent"
    kind_display: ClassVar[str] = "AWS ECS Managed Agent"
    kind_description: ClassVar[str] = (
        "The AWS ECS Managed Agent is a component of Amazon Elastic Container Service"
        " (ECS) that runs on each EC2 instance in an ECS cluster and manages the"
        " lifecycle of tasks and container instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "last_started_at": S("lastStartedAt"),
        "name": S("name"),
        "reason": S("reason"),
        "last_status": S("lastStatus"),
    }
    last_started_at: Optional[datetime] = field(default=None)
    name: Optional[str] = field(default=None)
    reason: Optional[str] = field(default=None)
    last_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsContainer:
    kind: ClassVar[str] = "aws_ecs_container"
    kind_display: ClassVar[str] = "AWS ECS Container"
    kind_description: ClassVar[str] = (
        "ECS Containers are a lightweight and portable way to package, deploy, and"
        " run applications in a highly scalable and managed container environment"
        " provided by Amazon Elastic Container Service (ECS)."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_arn": S("containerArn"),
        "task_arn": S("taskArn"),
        "name": S("name"),
        "image": S("image"),
        "image_digest": S("imageDigest"),
        "runtime_id": S("runtimeId"),
        "last_status": S("lastStatus"),
        "exit_code": S("exitCode"),
        "reason": S("reason"),
        "network_bindings": S("networkBindings", default=[]) >> ForallBend(AwsEcsNetworkBinding.mapping),
        "network_interfaces": S("networkInterfaces", default=[]) >> ForallBend(AwsEcsNetworkInterface.mapping),
        "health_status": S("healthStatus"),
        "managed_agents": S("managedAgents", default=[]) >> ForallBend(AwsEcsManagedAgent.mapping),
        "cpu": S("cpu"),
        "memory": S("memory"),
        "memory_reservation": S("memoryReservation"),
        "gpu_ids": S("gpuIds", default=[]),
    }
    container_arn: Optional[str] = field(default=None)
    task_arn: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    image: Optional[str] = field(default=None)
    image_digest: Optional[str] = field(default=None, metadata=dict(ignore_history=True))
    runtime_id: Optional[str] = field(default=None, metadata=dict(ignore_history=True))
    last_status: Optional[str] = field(default=None, metadata=dict(ignore_history=True))
    exit_code: Optional[int] = field(default=None)
    reason: Optional[str] = field(default=None)
    network_bindings: List[AwsEcsNetworkBinding] = field(factory=list)
    network_interfaces: List[AwsEcsNetworkInterface] = field(factory=list)
    health_status: Optional[str] = field(default=None)
    managed_agents: List[AwsEcsManagedAgent] = field(factory=list)
    cpu: Optional[str] = field(default=None)
    memory: Optional[str] = field(default=None)
    memory_reservation: Optional[str] = field(default=None)
    gpu_ids: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsInferenceAccelerator:
    kind: ClassVar[str] = "aws_ecs_inference_accelerator"
    kind_display: ClassVar[str] = "AWS ECS Inference Accelerator"
    kind_description: ClassVar[str] = (
        "The AWS ECS Inference Accelerator is a resource that provides machine learning inference acceleration"
        " for containers. It is specified by a device name and device type to identify the accelerator hardware"
        " to be used by ECS tasks."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"device_name": S("deviceName"), "device_type": S("deviceType")}
    device_name: Optional[str] = field(default=None)
    device_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsEnvironmentFile:
    kind: ClassVar[str] = "aws_ecs_environment_file"
    kind_display: ClassVar[str] = "AWS ECS Environment File"
    kind_description: ClassVar[str] = (
        "ECS Environment Files are used to store environment variables for containers"
        " in Amazon Elastic Container Service (ECS), allowing users to easily manage"
        " and configure these variables for their applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value"), "type": S("type")}
    value: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsResourceRequirement:
    kind: ClassVar[str] = "aws_ecs_resource_requirement"
    kind_display: ClassVar[str] = "AWS ECS Resource Requirement"
    kind_description: ClassVar[str] = (
        "Resource requirements for running containerized applications on Amazon"
        " Elastic Container Service (ECS), including CPU and memory allocation."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value"), "type": S("type")}
    value: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsContainerOverride:
    kind: ClassVar[str] = "aws_ecs_container_override"
    kind_display: ClassVar[str] = "AWS ECS Container Override"
    kind_description: ClassVar[str] = (
        "AWS ECS Container Override allows you to change the settings for a container within a task,"
        " such as command, environment variables, and resource allocation, on a per-task basis."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "command": S("command", default=[]),
        "environment": S("environment", default=[]) >> ForallBend(AwsEcsKeyValuePair.mapping),
        "environment_files": S("environmentFiles", default=[]) >> ForallBend(AwsEcsEnvironmentFile.mapping),
        "cpu": S("cpu"),
        "memory": S("memory"),
        "memory_reservation": S("memoryReservation"),
        "resource_requirements": S("resourceRequirements", default=[]) >> ForallBend(AwsEcsResourceRequirement.mapping),
    }
    name: Optional[str] = field(default=None)
    command: List[str] = field(factory=list)
    environment: List[AwsEcsKeyValuePair] = field(factory=list)
    environment_files: List[AwsEcsEnvironmentFile] = field(factory=list)
    cpu: Optional[int] = field(default=None)
    memory: Optional[int] = field(default=None)
    memory_reservation: Optional[int] = field(default=None)
    resource_requirements: List[AwsEcsResourceRequirement] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsTaskOverride:
    kind: ClassVar[str] = "aws_ecs_task_override"
    kind_display: ClassVar[str] = "AWS ECS Task Override"
    kind_description: ClassVar[str] = (
        "ECS Task Overrides allow you to change the default values of a task definition when running an ECS task."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_overrides": S("containerOverrides", default=[]) >> ForallBend(AwsEcsContainerOverride.mapping),
        "cpu": S("cpu"),
        "inference_accelerator_overrides": S("inferenceAcceleratorOverrides", default=[])
        >> ForallBend(AwsEcsInferenceAccelerator.mapping),
        "execution_role_arn": S("executionRoleArn"),
        "memory": S("memory"),
        "task_role_arn": S("taskRoleArn"),
        "ephemeral_storage": S("ephemeralStorage", "sizeInGiB"),
    }
    container_overrides: List[AwsEcsContainerOverride] = field(factory=list)
    cpu: Optional[str] = field(default=None)
    inference_accelerator_overrides: List[AwsEcsInferenceAccelerator] = field(factory=list)
    execution_role_arn: Optional[str] = field(default=None)
    memory: Optional[str] = field(default=None)
    task_role_arn: Optional[str] = field(default=None)
    ephemeral_storage: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsTask(EcsTaggable, AwsResource):
    # collection of task resources happens in AwsEcsCluster.collect()
    kind: ClassVar[str] = "aws_ecs_task"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ecs/v2/clusters/{clusterArn}/tasks/{id}/configuration?region={region}", "arn_tpl": "arn:{partition}:ecs:{region}:{account}:task/{name}"}  # fmt: skip

    kind_display: ClassVar[str] = "AWS ECS Task"
    kind_description: ClassVar[str] = (
        "ECS Tasks are containers managed by Amazon Elastic Container Service, which"
        " allow users to run and scale applications easily using Docker containers."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_ecs_task_definition"],
            "delete": ["aws_iam_role"],
        },
        "successors": {
            "default": ["aws_ecs_container_instance", "aws_ecs_capacity_provider"],
            "delete": ["aws_ecs_container_instance"],
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("taskArn") >> F(AwsResource.id_from_arn),
        "tags": S("tags", default=[]) >> ToDict(key="key", value="value"),
        "ctime": S("createdAt"),
        "arn": S("taskArn"),
        "task_attachments": S("attachments", default=[]) >> ForallBend(AwsEcsAttachment.mapping),
        "task_attributes": S("attributes", default=[]) >> ForallBend(AwsEcsAttribute.mapping),
        "task_availability_zone": S("availabilityZone"),
        "task_capacity_provider_name": S("capacityProviderName"),
        "task_cluster_arn": S("clusterArn"),
        "task_connectivity": S("connectivity"),
        "task_connectivity_at": S("connectivityAt"),
        "task_container_instance_arn": S("containerInstanceArn"),
        "task_containers": S("containers", default=[]) >> ForallBend(AwsEcsContainer.mapping),
        "task_cpu": S("cpu"),
        "task_desired_status": S("desiredStatus"),
        "task_enable_execute_command": S("enableExecuteCommand"),
        "task_execution_stopped_at": S("executionStoppedAt"),
        "task_group": S("group"),
        "task_health_status": S("healthStatus"),
        "task_inference_accelerators": S("inferenceAccelerators", default=[])
        >> ForallBend(AwsEcsInferenceAccelerator.mapping),
        "task_last_status": S("lastStatus"),
        "task_launch_type": S("launchType"),
        "task_memory": S("memory"),
        "task_overrides": S("overrides") >> Bend(AwsEcsTaskOverride.mapping),
        "task_platform_version": S("platformVersion"),
        "task_platform_family": S("platformFamily"),
        "task_pull_started_at": S("pullStartedAt"),
        "task_pull_stopped_at": S("pullStoppedAt"),
        "task_started_at": S("startedAt"),
        "task_started_by": S("startedBy"),
        "task_stop_code": S("stopCode"),
        "task_stopped_at": S("stoppedAt"),
        "task_stopped_reason": S("stoppedReason"),
        "task_stopping_at": S("stoppingAt"),
        "task_definition_arn": S("taskDefinitionArn"),
        "task_version": S("version"),
        "task_ephemeral_storage": S("ephemeralStorage", "sizeInGiB"),
    }
    task_attachments: List[AwsEcsAttachment] = field(factory=list)
    task_attributes: List[AwsEcsAttribute] = field(factory=list)
    task_availability_zone: Optional[str] = field(default=None)
    task_capacity_provider_name: Optional[str] = field(default=None)
    task_cluster_arn: Optional[str] = field(default=None)
    task_connectivity: Optional[str] = field(default=None, metadata=dict(ignore_history=True))
    task_connectivity_at: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    task_container_instance_arn: Optional[str] = field(default=None)
    task_containers: List[AwsEcsContainer] = field(factory=list)
    task_cpu: Optional[str] = field(default=None)
    task_desired_status: Optional[str] = field(default=None)
    task_enable_execute_command: Optional[bool] = field(default=None)
    task_execution_stopped_at: Optional[datetime] = field(default=None)
    task_group: Optional[str] = field(default=None)
    task_health_status: Optional[str] = field(default=None)
    task_inference_accelerators: List[AwsEcsInferenceAccelerator] = field(factory=list)
    task_last_status: Optional[str] = field(default=None)
    task_launch_type: Optional[str] = field(default=None)
    task_memory: Optional[str] = field(default=None)
    task_overrides: Optional[AwsEcsTaskOverride] = field(default=None)
    task_platform_version: Optional[str] = field(default=None)
    task_platform_family: Optional[str] = field(default=None)
    task_pull_started_at: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    task_pull_stopped_at: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    task_started_at: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    task_started_by: Optional[str] = field(default=None, metadata=dict(ignore_history=True))
    task_stop_code: Optional[str] = field(default=None, metadata=dict(ignore_history=True))
    task_stopped_at: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    task_stopped_reason: Optional[str] = field(default=None, metadata=dict(ignore_history=True))
    task_stopping_at: Optional[datetime] = field(default=None, metadata=dict(ignore_history=True))
    task_definition_arn: Optional[str] = field(default=None)
    task_version: Optional[int] = field(default=None)
    task_ephemeral_storage: Optional[int] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.task_overrides:
            for role in [self.task_overrides.execution_role_arn, self.task_overrides.task_role_arn]:
                builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role)
        if self.task_definition_arn:
            builder.add_edge(
                self, edge_type=EdgeType.default, reverse=True, clazz=AwsEcsTaskDefinition, arn=self.task_definition_arn
            )
        if self.task_container_instance_arn:
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=AwsEcsContainerInstance,
                arn=self.task_container_instance_arn,
            )
        if self.task_capacity_provider_name:
            builder.add_edge(
                self, edge_type=EdgeType.default, clazz=AwsEcsCapacityProvider, name=self.task_capacity_provider_name
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name, action="stop-task", result_name=None, cluster=self.task_cluster_arn, task=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "stop-task")]


@define(eq=False, slots=False)
class AwsEcsPortMapping:
    kind: ClassVar[str] = "aws_ecs_port_mapping"
    kind_display: ClassVar[str] = "AWS ECS Port Mapping"
    kind_description: ClassVar[str] = (
        "Port mapping in Amazon Elastic Container Service (ECS) allows containers"
        " running within a task to receive inbound traffic on specified port numbers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_port": S("containerPort"),
        "host_port": S("hostPort"),
        "protocol": S("protocol"),
    }
    container_port: Optional[int] = field(default=None)
    host_port: Optional[int] = field(default=None)
    protocol: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsMountPoint:
    kind: ClassVar[str] = "aws_ecs_mount_point"
    kind_display: ClassVar[str] = "AWS ECS Mount Point"
    kind_description: ClassVar[str] = (
        "ECS Mount Points are used in Amazon EC2 Container Service to attach"
        " persistent storage volumes to containers in a task definition."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "source_volume": S("sourceVolume"),
        "container_path": S("containerPath"),
        "read_only": S("readOnly"),
    }
    source_volume: Optional[str] = field(default=None)
    container_path: Optional[str] = field(default=None)
    read_only: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsVolumeFrom:
    kind: ClassVar[str] = "aws_ecs_volume_from"
    kind_display: ClassVar[str] = "AWS ECS Volume From"
    kind_description: ClassVar[str] = (
        "Volume From is a feature in Amazon Elastic Container Service (ECS) that"
        " allows a container to access the contents of another container's mounted"
        " volumes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"source_container": S("sourceContainer"), "read_only": S("readOnly")}
    source_container: Optional[str] = field(default=None)
    read_only: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsKernelCapabilities:
    kind: ClassVar[str] = "aws_ecs_kernel_capabilities"
    kind_display: ClassVar[str] = "AWS ECS Kernel Capabilities"
    kind_description: ClassVar[str] = (
        "Kernel capabilities allow fine-grained control over privileged operations,"
        " such as modifying network settings or accessing hardware resources, for"
        " tasks running in Amazon ECS."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"add": S("add", default=[]), "drop": S("drop", default=[])}
    add: List[str] = field(factory=list)
    drop: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsDevice:
    kind: ClassVar[str] = "aws_ecs_device"
    kind_display: ClassVar[str] = "AWS ECS Device"
    kind_description: ClassVar[str] = (
        "The AWS ECS Device configuration specifies a host machine's device to be mapped to a container,"
        " along with the path it should be mounted to inside the container and the permissions the"
        " container has on the device."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "host_path": S("hostPath"),
        "container_path": S("containerPath"),
        "permissions": S("permissions", default=[]),
    }
    host_path: Optional[str] = field(default=None)
    container_path: Optional[str] = field(default=None)
    permissions: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsTmpfs:
    kind: ClassVar[str] = "aws_ecs_tmpfs"
    kind_display: ClassVar[str] = "AWS ECS Tmpfs"
    kind_description: ClassVar[str] = (
        "Tmpfs is a temporary file storage system in AWS Elastic Container Service"
        " (ECS) that can be mounted as a memory-backed file system for containers. It"
        " provides fast and volatile storage for temporary files during container"
        " runtime."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_path": S("containerPath"),
        "size": S("size"),
        "mount_options": S("mountOptions", default=[]),
    }
    container_path: Optional[str] = field(default=None)
    size: Optional[int] = field(default=None)
    mount_options: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsLinuxParameters:
    kind: ClassVar[str] = "aws_ecs_linux_parameters"
    kind_display: ClassVar[str] = "AWS ECS Linux Parameters"
    kind_description: ClassVar[str] = (
        "ECS Linux Parameters are configuration settings for Amazon Elastic Container"
        " Service (ECS) that enable you to modify container behavior on Linux"
        " instances within an ECS cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "capabilities": S("capabilities") >> Bend(AwsEcsKernelCapabilities.mapping),
        "devices": S("devices", default=[]) >> ForallBend(AwsEcsDevice.mapping),
        "init_process_enabled": S("initProcessEnabled"),
        "shared_memory_size": S("sharedMemorySize"),
        "tmpfs": S("tmpfs", default=[]) >> ForallBend(AwsEcsTmpfs.mapping),
        "max_swap": S("maxSwap"),
        "swappiness": S("swappiness"),
    }
    capabilities: Optional[AwsEcsKernelCapabilities] = field(default=None)
    devices: List[AwsEcsDevice] = field(factory=list)
    init_process_enabled: Optional[bool] = field(default=None)
    shared_memory_size: Optional[int] = field(default=None)
    tmpfs: List[AwsEcsTmpfs] = field(factory=list)
    max_swap: Optional[int] = field(default=None)
    swappiness: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsSecret:
    kind: ClassVar[str] = "aws_ecs_secret"
    kind_display: ClassVar[str] = "AWS ECS Secret"
    kind_description: ClassVar[str] = (
        "ECS Secrets provide a secure way to store and manage sensitive information,"
        " such as database credentials or API keys, for use by applications running on"
        " AWS Elastic Container Service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value_from": S("valueFrom")}
    name: Optional[str] = field(default=None)
    value_from: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsContainerDependency:
    kind: ClassVar[str] = "aws_ecs_container_dependency"
    kind_display: ClassVar[str] = "AWS ECS Container Dependency"
    kind_description: ClassVar[str] = (
        "ECS Container Dependency is a feature in AWS ECS (Elastic Container Service)"
        " that allows you to define dependencies between containers within a task"
        " definition to ensure proper sequencing and synchronization of container"
        " startup and shutdown."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"container_name": S("containerName"), "condition": S("condition")}
    container_name: Optional[str] = field(default=None)
    condition: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsHostEntry:
    kind: ClassVar[str] = "aws_ecs_host_entry"
    kind_display: ClassVar[str] = "AWS ECS Host Entry"
    kind_description: ClassVar[str] = (
        "The AWS ECS Host Entry configuration specifies a custom host-to-IP address mapping to be added"
        " to a container's `/etc/hosts` file, allowing for custom hostname resolutions within the container."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"hostname": S("hostname"), "ip_address": S("ipAddress")}
    hostname: Optional[str] = field(default=None)
    ip_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsUlimit:
    kind: ClassVar[str] = "aws_ecs_ulimit"
    kind_display: ClassVar[str] = "AWS ECS Ulimit"
    kind_description: ClassVar[str] = (
        "ECS Ulimit is a resource limit configuration for Amazon Elastic Container"
        " Service (ECS) tasks, which allows users to set specific limits on various"
        " system resources such as the number of open files or maximum memory usage"
        " for each container."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "soft_limit": S("softLimit"),
        "hard_limit": S("hardLimit"),
    }
    name: Optional[str] = field(default=None)
    soft_limit: Optional[int] = field(default=None)
    hard_limit: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsLogConfiguration:
    kind: ClassVar[str] = "aws_ecs_log_configuration"
    kind_display: ClassVar[str] = "AWS ECS Log Configuration"
    kind_description: ClassVar[str] = (
        "ECS Log Configuration is a feature of Amazon Elastic Container Service that"
        " allows you to configure logging for your containerized applications and view"
        " the logs in various destinations such as CloudWatch Logs or Amazon S3."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "log_driver": S("logDriver"),
        "options": S("options"),
        "secret_options": S("secretOptions", default=[]) >> ForallBend(AwsEcsSecret.mapping),
    }
    log_driver: Optional[str] = field(default=None)
    options: Optional[Dict[str, str]] = field(default=None)
    secret_options: List[AwsEcsSecret] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsHealthCheck:
    kind: ClassVar[str] = "aws_ecs_health_check"
    kind_display: ClassVar[str] = "AWS ECS Health Check"
    kind_description: ClassVar[str] = (
        "ECS Health Check is a feature of Amazon Elastic Container Service (ECS) that"
        " allows you to monitor the health of your containers by conducting periodic"
        " health checks and reporting the results."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "command": S("command", default=[]),
        "interval": S("interval"),
        "timeout": S("timeout"),
        "retries": S("retries"),
        "start_period": S("startPeriod"),
    }
    command: List[str] = field(factory=list)
    interval: Optional[int] = field(default=None)
    timeout: Optional[int] = field(default=None)
    retries: Optional[int] = field(default=None)
    start_period: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsSystemControl:
    kind: ClassVar[str] = "aws_ecs_system_control"
    kind_display: ClassVar[str] = "AWS ECS System Control"
    kind_description: ClassVar[str] = (
        "The AWS ECS System Control is a configuration that allows you to set namespaced kernel parameters"
        " for containers, controlling system-level behaviors at runtime by specifying the namespace"
        " and the corresponding value."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"namespace": S("namespace"), "value": S("value")}
    namespace: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsFirelensConfiguration:
    kind: ClassVar[str] = "aws_ecs_firelens_configuration"
    kind_display: ClassVar[str] = "AWS ECS FireLens Configuration"
    kind_description: ClassVar[str] = (
        "AWS ECS FireLens Configuration is a feature of Amazon Elastic Container"
        " Service (ECS) that allows you to collect, process, and route logs from your"
        " containers to different storage and analytics services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "options": S("options")}
    type: Optional[str] = field(default=None)
    options: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsContainerDefinition:
    kind: ClassVar[str] = "aws_ecs_container_definition"
    kind_display: ClassVar[str] = "AWS ECS Container Definition"
    kind_description: ClassVar[str] = (
        "ECS Container Definition is a configuration that defines how a container"
        " should be run within an Amazon ECS cluster. It includes details such as"
        " image, CPU and memory resources, environment variables, and networking"
        " settings."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "image": S("image"),
        "repository_credentials": S("repositoryCredentials", "credentialsParameter"),
        "cpu": S("cpu"),
        "memory": S("memory"),
        "memory_reservation": S("memoryReservation"),
        "links": S("links", default=[]),
        "port_mappings": S("portMappings", default=[]) >> ForallBend(AwsEcsPortMapping.mapping),
        "essential": S("essential"),
        "entry_point": S("entryPoint", default=[]),
        "command": S("command", default=[]),
        "environment": S("environment", default=[]) >> ForallBend(AwsEcsKeyValuePair.mapping),
        "environment_files": S("environmentFiles", default=[]) >> ForallBend(AwsEcsEnvironmentFile.mapping),
        "mount_points": S("mountPoints", default=[]) >> ForallBend(AwsEcsMountPoint.mapping),
        "volumes_from": S("volumesFrom", default=[]) >> ForallBend(AwsEcsVolumeFrom.mapping),
        "linux_parameters": S("linuxParameters") >> Bend(AwsEcsLinuxParameters.mapping),
        "secrets": S("secrets", default=[]) >> ForallBend(AwsEcsSecret.mapping),
        "depends_on": S("dependsOn", default=[]) >> ForallBend(AwsEcsContainerDependency.mapping),
        "start_timeout": S("startTimeout"),
        "stop_timeout": S("stopTimeout"),
        "hostname": S("hostname"),
        "user": S("user"),
        "working_directory": S("workingDirectory"),
        "disable_networking": S("disableNetworking"),
        "privileged": S("privileged"),
        "readonly_root_filesystem": S("readonlyRootFilesystem"),
        "dns_servers": S("dnsServers", default=[]),
        "dns_search_domains": S("dnsSearchDomains", default=[]),
        "extra_hosts": S("extraHosts", default=[]) >> ForallBend(AwsEcsHostEntry.mapping),
        "docker_security_options": S("dockerSecurityOptions", default=[]),
        "interactive": S("interactive"),
        "pseudo_terminal": S("pseudoTerminal"),
        "docker_labels": S("dockerLabels"),
        "ulimits": S("ulimits", default=[]) >> ForallBend(AwsEcsUlimit.mapping),
        "log_configuration": S("logConfiguration") >> Bend(AwsEcsLogConfiguration.mapping),
        "health_check": S("healthCheck") >> Bend(AwsEcsHealthCheck.mapping),
        "system_controls": S("systemControls", default=[]) >> ForallBend(AwsEcsSystemControl.mapping),
        "resource_requirements": S("resourceRequirements", default=[]) >> ForallBend(AwsEcsResourceRequirement.mapping),
        "firelens_configuration": S("firelensConfiguration") >> Bend(AwsEcsFirelensConfiguration.mapping),
    }
    name: Optional[str] = field(default=None)
    image: Optional[str] = field(default=None)
    repository_credentials: Optional[str] = field(default=None)
    cpu: Optional[int] = field(default=None)
    memory: Optional[int] = field(default=None)
    memory_reservation: Optional[int] = field(default=None)
    links: List[str] = field(factory=list)
    port_mappings: List[AwsEcsPortMapping] = field(factory=list)
    essential: Optional[bool] = field(default=None)
    entry_point: List[str] = field(factory=list)
    command: List[str] = field(factory=list)
    environment: List[AwsEcsKeyValuePair] = field(factory=list)
    environment_files: List[AwsEcsEnvironmentFile] = field(factory=list)
    mount_points: List[AwsEcsMountPoint] = field(factory=list)
    volumes_from: List[AwsEcsVolumeFrom] = field(factory=list)
    linux_parameters: Optional[AwsEcsLinuxParameters] = field(default=None)
    secrets: List[AwsEcsSecret] = field(factory=list)
    depends_on: List[AwsEcsContainerDependency] = field(factory=list)
    start_timeout: Optional[int] = field(default=None)
    stop_timeout: Optional[int] = field(default=None)
    hostname: Optional[str] = field(default=None)
    user: Optional[str] = field(default=None)
    working_directory: Optional[str] = field(default=None)
    disable_networking: Optional[bool] = field(default=None)
    privileged: Optional[bool] = field(default=None)
    readonly_root_filesystem: Optional[bool] = field(default=None)
    dns_servers: List[str] = field(factory=list)
    dns_search_domains: List[str] = field(factory=list)
    extra_hosts: List[AwsEcsHostEntry] = field(factory=list)
    docker_security_options: List[str] = field(factory=list)
    interactive: Optional[bool] = field(default=None)
    pseudo_terminal: Optional[bool] = field(default=None)
    docker_labels: Optional[Dict[str, str]] = field(default=None)
    ulimits: List[AwsEcsUlimit] = field(factory=list)
    log_configuration: Optional[AwsEcsLogConfiguration] = field(default=None)
    health_check: Optional[AwsEcsHealthCheck] = field(default=None)
    system_controls: List[AwsEcsSystemControl] = field(factory=list)
    resource_requirements: List[AwsEcsResourceRequirement] = field(factory=list)
    firelens_configuration: Optional[AwsEcsFirelensConfiguration] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsDockerVolumeConfiguration:
    kind: ClassVar[str] = "aws_ecs_docker_volume_configuration"
    kind_display: ClassVar[str] = "AWS ECS Docker Volume Configuration"
    kind_description: ClassVar[str] = (
        "ECS Docker Volume Configuration is a feature in Amazon ECS (Elastic"
        " Container Service) that allows you to specify how Docker volumes should be"
        " configured for containers running in an ECS cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "scope": S("scope"),
        "autoprovision": S("autoprovision"),
        "driver": S("driver"),
        "driver_opts": S("driverOpts"),
        "labels": S("labels"),
    }
    scope: Optional[str] = field(default=None)
    autoprovision: Optional[bool] = field(default=None)
    driver: Optional[str] = field(default=None)
    driver_opts: Optional[Dict[str, str]] = field(default=None)
    labels: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsEFSAuthorizationConfig:
    kind: ClassVar[str] = "aws_ecs_efs_authorization_config"
    kind_display: ClassVar[str] = "AWS ECS EFS Authorization Config"
    kind_description: ClassVar[str] = (
        "The AWS ECS EFS Authorization Config is a setting that allows ECS tasks to use an Amazon EFS file system,"
        " specifying the EFS access point ID and whether or not IAM authorization should be used for access control."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"access_point_id": S("accessPointId"), "iam": S("iam")}
    access_point_id: Optional[str] = field(default=None)
    iam: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsEFSVolumeConfiguration:
    kind: ClassVar[str] = "aws_ecs_efs_volume_configuration"
    kind_display: ClassVar[str] = "AWS ECS EFS Volume Configuration"
    kind_description: ClassVar[str] = (
        "ECS EFS Volume Configuration is a feature in AWS Elastic Container Service"
        " (ECS) that allows you to configure volumes using Amazon Elastic File System"
        " (EFS) for storing persistent data in containers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "file_system_id": S("fileSystemId"),
        "root_directory": S("rootDirectory"),
        "transit_encryption": S("transitEncryption"),
        "transit_encryption_port": S("transitEncryptionPort"),
        "authorization_config": S("authorizationConfig") >> Bend(AwsEcsEFSAuthorizationConfig.mapping),
    }
    file_system_id: Optional[str] = field(default=None)
    root_directory: Optional[str] = field(default=None)
    transit_encryption: Optional[str] = field(default=None)
    transit_encryption_port: Optional[int] = field(default=None)
    authorization_config: Optional[AwsEcsEFSAuthorizationConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsFSxWindowsFileServerAuthorizationConfig:
    kind: ClassVar[str] = "aws_ecs_f_sx_windows_file_server_authorization_config"
    kind_display: ClassVar[str] = "AWS ECS FSx Windows File Server Authorization Config"
    kind_description: ClassVar[str] = (
        "ECS FSx Windows File Server Authorization Config is a configuration resource"
        " in AWS Elastic Container Service (ECS) that allows secure access to an FSx"
        " for Windows File Server from ECS tasks running on Amazon EC2 instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"credentials_parameter": S("credentialsParameter"), "domain": S("domain")}
    credentials_parameter: Optional[str] = field(default=None)
    domain: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsFSxWindowsFileServerVolumeConfiguration:
    kind: ClassVar[str] = "aws_ecs_f_sx_windows_file_server_volume_configuration"
    kind_display: ClassVar[str] = "AWS ECS FSx Windows File Server Volume Configuration"
    kind_description: ClassVar[str] = (
        "FSx Windows File Server Volume Configuration provides persistent and"
        " scalable storage for ECS tasks running on Windows instances in Amazon's"
        " cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "file_system_id": S("fileSystemId"),
        "root_directory": S("rootDirectory"),
        "authorization_config": S("authorizationConfig") >> Bend(AwsEcsFSxWindowsFileServerAuthorizationConfig.mapping),
    }
    file_system_id: Optional[str] = field(default=None)
    root_directory: Optional[str] = field(default=None)
    authorization_config: Optional[AwsEcsFSxWindowsFileServerAuthorizationConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsVolume:
    kind: ClassVar[str] = "aws_ecs_volume"
    kind_display: ClassVar[str] = "AWS ECS Volume"
    kind_description: ClassVar[str] = (
        "ECS Volumes are container volumes that can be used for persistent data storage and"
        " sharing in Amazon Elastic Container Service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "host": S("host", "sourcePath"),
        "docker_volume_configuration": S("dockerVolumeConfiguration") >> Bend(AwsEcsDockerVolumeConfiguration.mapping),
        "efs_volume_configuration": S("efsVolumeConfiguration") >> Bend(AwsEcsEFSVolumeConfiguration.mapping),
        "fsx_windows_file_server_volume_configuration": S("fsxWindowsFileServerVolumeConfiguration")
        >> Bend(AwsEcsFSxWindowsFileServerVolumeConfiguration.mapping),
    }
    name: Optional[str] = field(default=None)
    host: Optional[str] = field(default=None)
    docker_volume_configuration: Optional[AwsEcsDockerVolumeConfiguration] = field(default=None)
    efs_volume_configuration: Optional[AwsEcsEFSVolumeConfiguration] = field(default=None)
    fsx_windows_file_server_volume_configuration: Optional[AwsEcsFSxWindowsFileServerVolumeConfiguration] = field(
        default=None
    )


@define(eq=False, slots=False)
class AwsEcsTaskDefinitionPlacementConstraint:
    kind: ClassVar[str] = "aws_ecs_task_definition_placement_constraint"
    kind_display: ClassVar[str] = "AWS ECS Task Definition Placement Constraint"
    kind_description: ClassVar[str] = (
        "ECS Task Definition Placement Constraints are rules that specify the"
        " placement of tasks within an Amazon ECS cluster based on resource"
        " requirements or custom expressions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "expression": S("expression")}
    type: Optional[str] = field(default=None)
    expression: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsRuntimePlatform:
    kind: ClassVar[str] = "aws_ecs_runtime_platform"
    kind_display: ClassVar[str] = "AWS ECS Runtime Platform"
    kind_description: ClassVar[str] = (
        "The AWS ECS Runtime Platform is a container management service provided by"
        " Amazon Web Services, allowing users to easily run and scale containerized"
        " applications on AWS."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cpu_architecture": S("cpuArchitecture"),
        "operating_system_family": S("operatingSystemFamily"),
    }
    cpu_architecture: Optional[str] = field(default=None)
    operating_system_family: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsProxyConfiguration:
    kind: ClassVar[str] = "aws_ecs_proxy_configuration"
    kind_display: ClassVar[str] = "AWS ECS Proxy Configuration"
    kind_description: ClassVar[str] = (
        "ECS Proxy Configuration is a feature in Amazon Elastic Container Service"
        " that allows for configuring the proxy settings for containers running in an"
        " ECS cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "type": S("type"),
        "container_name": S("containerName"),
        "properties": S("properties", default=[]) >> ForallBend(AwsEcsKeyValuePair.mapping),
    }
    type: Optional[str] = field(default=None)
    container_name: Optional[str] = field(default=None)
    properties: List[AwsEcsKeyValuePair] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsTaskDefinition(EcsTaggable, AwsResource):
    kind: ClassVar[str] = "aws_ecs_task_definition"
    kind_display: ClassVar[str] = "AWS ECS Task Definition"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ecs/v2/task-definitions/{name}?region={region}", "arn_tpl": "arn:{partition}:ecs:{region}:{account}:task-definition/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An ECS Task Definition is a blueprint for running tasks in AWS Elastic"
        " Container Service (ECS), providing information such as the Docker image,"
        " CPU, memory, network configuration, and other parameters."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-task-definitions", "taskDefinitionArns")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_iam_role"], "delete": ["aws_iam_role"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("taskDefinitionArn") >> F(AwsResource.id_from_arn),
        "tags": S("tags", default=[]) >> ToDict(key="key", value="value"),
        "name": S("tags", default=[]) >> TagsValue("Name").or_else(S("taskDefinitionArn")),
        "ctime": S("registeredAt"),
        "arn": S("taskDefinitionArn"),
        "container_definitions": S("containerDefinitions", default=[]) >> ForallBend(AwsEcsContainerDefinition.mapping),
        "family": S("family"),
        "task_role_arn": S("taskRoleArn"),
        "execution_role_arn": S("executionRoleArn"),
        "network_mode": S("networkMode"),
        "revision": S("revision"),
        "volumes": S("volumes", default=[]) >> ForallBend(AwsEcsVolume.mapping),
        "status": S("status"),
        "requires_attributes": S("requiresAttributes", default=[]) >> ForallBend(AwsEcsAttribute.mapping),
        "placement_constraints": S("placementConstraints", default=[])
        >> ForallBend(AwsEcsTaskDefinitionPlacementConstraint.mapping),
        "compatibilities": S("compatibilities", default=[]),
        "runtime_platform": S("runtimePlatform") >> Bend(AwsEcsRuntimePlatform.mapping),
        "requires_compatibilities": S("requiresCompatibilities", default=[]),
        "cpu": S("cpu"),
        "memory": S("memory"),
        "inference_accelerators": S("inferenceAccelerators", default=[])
        >> ForallBend(AwsEcsInferenceAccelerator.mapping),
        "pid_mode": S("pidMode"),
        "ipc_mode": S("ipcMode"),
        "proxy_configuration": S("proxyConfiguration") >> Bend(AwsEcsProxyConfiguration.mapping),
        "deregistered_at": S("deregisteredAt"),
        "registered_by": S("registeredBy"),
        "ephemeral_storage": S("ephemeralStorage", "sizeInGiB"),
    }
    container_definitions: List[AwsEcsContainerDefinition] = field(factory=list)
    family: Optional[str] = field(default=None)
    task_role_arn: Optional[str] = field(default=None)
    execution_role_arn: Optional[str] = field(default=None)
    network_mode: Optional[str] = field(default=None)
    revision: Optional[int] = field(default=None)
    volumes: List[AwsEcsVolume] = field(factory=list)
    status: Optional[str] = field(default=None)
    requires_attributes: List[AwsEcsAttribute] = field(factory=list)
    placement_constraints: List[AwsEcsTaskDefinitionPlacementConstraint] = field(factory=list)
    compatibilities: List[str] = field(factory=list)
    runtime_platform: Optional[AwsEcsRuntimePlatform] = field(default=None)
    requires_compatibilities: List[str] = field(factory=list)
    cpu: Optional[str] = field(default=None)
    memory: Optional[str] = field(default=None)
    inference_accelerators: List[AwsEcsInferenceAccelerator] = field(factory=list)
    pid_mode: Optional[str] = field(default=None)
    ipc_mode: Optional[str] = field(default=None)
    proxy_configuration: Optional[AwsEcsProxyConfiguration] = field(default=None)
    registered_by: Optional[str] = field(default=None)
    ephemeral_storage: Optional[int] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-task-definition"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for task_def_arn in json:
            response = builder.client.get(
                service_name,
                "describe-task-definition",
                None,
                taskDefinition=task_def_arn,
                include=["TAGS"],
            )
            if response is not None:
                task_definition = response["taskDefinition"]
                tags = response["tags"]
                task_definition["tags"] = tags
                if task_definition_instance := cls.from_api(task_definition, builder):
                    builder.add_node(task_definition_instance, task_def_arn)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for role in [self.task_role_arn, self.execution_role_arn]:
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=AwsIamRole,
                arn=role,
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="deregister-task-definition",
            result_name=None,
            taskDefinition=f"{self.family}:{self.revision}",
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "deregister-task-definition")]


@define(eq=False, slots=False)
class AwsEcsLoadBalancer:
    kind: ClassVar[str] = "aws_ecs_load_balancer"
    kind_display: ClassVar[str] = "AWS ECS Load Balancer"
    kind_description: ClassVar[str] = (
        "ECS Load Balancers are elastic load balancing services provided by AWS for"
        " distributing incoming traffic to multiple targets within an Amazon Elastic"
        " Container Service (ECS) cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "target_group_arn": S("targetGroupArn"),
        "load_balancer_name": S("loadBalancerName"),
        "container_name": S("containerName"),
        "container_port": S("containerPort"),
    }
    target_group_arn: Optional[str] = field(default=None)
    load_balancer_name: Optional[str] = field(default=None)
    container_name: Optional[str] = field(default=None)
    container_port: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsServiceRegistry:
    kind: ClassVar[str] = "aws_ecs_service_registry"
    kind_display: ClassVar[str] = "AWS ECS Service Registry"
    kind_description: ClassVar[str] = (
        "The AWS ECS Service Registry is a service provided by Amazon Web Services"
        " for managing the registry of services in ECS (Elastic Container Service)"
        " tasks and clusters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "registry_arn": S("registryArn"),
        "port": S("port"),
        "container_name": S("containerName"),
        "container_port": S("containerPort"),
    }
    registry_arn: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    container_name: Optional[str] = field(default=None)
    container_port: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsCapacityProviderStrategyItem:
    kind: ClassVar[str] = "aws_ecs_capacity_provider_strategy_item"
    kind_display: ClassVar[str] = "AWS ECS Capacity Provider Strategy Item"
    kind_description: ClassVar[str] = (
        "ECS Capacity Provider Strategy Item is a configuration option used in Amazon"
        " Elastic Container Service (ECS) for managing the capacity of EC2 instances"
        " in an ECS cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_provider": S("capacityProvider"),
        "weight": S("weight"),
        "base": S("base"),
    }
    capacity_provider: Optional[str] = field(default=None)
    weight: Optional[int] = field(default=None)
    base: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsDeploymentCircuitBreaker:
    kind: ClassVar[str] = "aws_ecs_deployment_circuit_breaker"
    kind_display: ClassVar[str] = "AWS ECS Deployment Circuit Breaker"
    kind_description: ClassVar[str] = (
        "The AWS ECS Deployment Circuit Breaker is a feature that can automatically stop and rollback"
        " a deployment if it's not proceeding as expected, helping to maintain service stability and"
        " minimize downtime during updates."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"enable": S("enable"), "rollback": S("rollback")}
    enable: Optional[bool] = field(default=None)
    rollback: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsDeploymentConfiguration:
    kind: ClassVar[str] = "aws_ecs_deployment_configuration"
    kind_display: ClassVar[str] = "AWS ECS Deployment Configuration"
    kind_description: ClassVar[str] = (
        "ECS Deployment Configurations are used to manage the deployment of"
        " containers in Amazon ECS, allowing users to specify various properties and"
        " settings for their container deployments."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "deployment_circuit_breaker": S("deploymentCircuitBreaker") >> Bend(AwsEcsDeploymentCircuitBreaker.mapping),
        "maximum_percent": S("maximumPercent"),
        "minimum_healthy_percent": S("minimumHealthyPercent"),
    }
    deployment_circuit_breaker: Optional[AwsEcsDeploymentCircuitBreaker] = field(default=None)
    maximum_percent: Optional[int] = field(default=None)
    minimum_healthy_percent: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsAwsVpcConfiguration:
    kind: ClassVar[str] = "aws_ecs_aws_vpc_configuration"
    kind_display: ClassVar[str] = "AWS ECS AWS VPC Configuration"
    kind_description: ClassVar[str] = (
        "ECS AWS VPC Configuration is a configuration setting for Amazon Elastic"
        " Container Service (ECS) that allows you to specify the virtual private cloud"
        " (VPC) configuration for your ECS tasks and services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "subnets": S("subnets", default=[]),
        "security_groups": S("securityGroups", default=[]),
        "assign_public_ip": S("assignPublicIp"),
    }
    subnets: List[str] = field(factory=list)
    security_groups: List[str] = field(factory=list)
    assign_public_ip: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsNetworkConfiguration:
    kind: ClassVar[str] = "aws_ecs_network_configuration"
    kind_display: ClassVar[str] = "AWS ECS Network Configuration"
    kind_description: ClassVar[str] = (
        "ECS Network Configuration is a feature in Amazon Elastic Container Service"
        " (ECS) that allows users to configure networking settings for their"
        " containerized applications running on ECS. It includes specifications for"
        " the VPC, subnet, security groups, and other network resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "awsvpc_configuration": S("awsvpcConfiguration") >> Bend(AwsEcsAwsVpcConfiguration.mapping)
    }
    awsvpc_configuration: Optional[AwsEcsAwsVpcConfiguration] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsScale:
    kind: ClassVar[str] = "aws_ecs_scale"
    kind_display: ClassVar[str] = "AWS ECS Scale"
    kind_description: ClassVar[str] = (
        "ECS Scale is a feature in AWS Elastic Container Service (ECS) that allows"
        " you to automatically scale the number of containers running in a cluster"
        " based on application load and resource utilization."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value"), "unit": S("unit")}
    value: Optional[float] = field(default=None)
    unit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsTaskSet:
    kind: ClassVar[str] = "aws_ecs_task_set"
    kind_display: ClassVar[str] = "AWS ECS Task Set"
    kind_description: ClassVar[str] = (
        "ECS Task Sets are a way to manage multiple versions of a task definition in"
        " Amazon ECS, allowing users to create and manage a set of tasks running in a"
        " service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "task_set_arn": S("taskSetArn"),
        "service_arn": S("serviceArn"),
        "cluster_arn": S("clusterArn"),
        "started_by": S("startedBy"),
        "external_id": S("externalId"),
        "status": S("status"),
        "task_definition": S("taskDefinition"),
        "computed_desired_count": S("computedDesiredCount"),
        "pending_count": S("pendingCount"),
        "running_count": S("runningCount"),
        "created_at": S("createdAt"),
        "updated_at": S("updatedAt"),
        "launch_type": S("launchType"),
        "capacity_provider_strategy": S("capacityProviderStrategy", default=[])
        >> ForallBend(AwsEcsCapacityProviderStrategyItem.mapping),
        "platform_version": S("platformVersion"),
        "platform_family": S("platformFamily"),
        "network_configuration": S("networkConfiguration") >> Bend(AwsEcsNetworkConfiguration.mapping),
        "load_balancers": S("loadBalancers", default=[]) >> ForallBend(AwsEcsLoadBalancer.mapping),
        "service_registries": S("serviceRegistries", default=[]) >> ForallBend(AwsEcsServiceRegistry.mapping),
        "scale": S("scale") >> Bend(AwsEcsScale.mapping),
        "stability_status": S("stabilityStatus"),
        "stability_status_at": S("stabilityStatusAt"),
    }
    id: Optional[str] = field(default=None)
    task_set_arn: Optional[str] = field(default=None)
    service_arn: Optional[str] = field(default=None)
    cluster_arn: Optional[str] = field(default=None)
    started_by: Optional[str] = field(default=None)
    external_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    task_definition: Optional[str] = field(default=None)
    computed_desired_count: Optional[int] = field(default=None)
    pending_count: Optional[int] = field(default=None)
    running_count: Optional[int] = field(default=None)
    created_at: Optional[datetime] = field(default=None)
    updated_at: Optional[datetime] = field(default=None)
    launch_type: Optional[str] = field(default=None)
    capacity_provider_strategy: List[AwsEcsCapacityProviderStrategyItem] = field(factory=list)
    platform_version: Optional[str] = field(default=None)
    platform_family: Optional[str] = field(default=None)
    network_configuration: Optional[AwsEcsNetworkConfiguration] = field(default=None)
    load_balancers: List[AwsEcsLoadBalancer] = field(factory=list)
    service_registries: List[AwsEcsServiceRegistry] = field(factory=list)
    scale: Optional[AwsEcsScale] = field(default=None)
    stability_status: Optional[str] = field(default=None)
    stability_status_at: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsDeployment:
    kind: ClassVar[str] = "aws_ecs_deployment"
    kind_display: ClassVar[str] = "AWS ECS Deployment"
    kind_description: ClassVar[str] = (
        "ECS (Elastic Container Service) Deployment is a service provided by AWS that"
        " allows you to run and manage Docker containers on a cluster of EC2"
        " instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "status": S("status"),
        "task_definition": S("taskDefinition"),
        "desired_count": S("desiredCount"),
        "pending_count": S("pendingCount"),
        "running_count": S("runningCount"),
        "failed_tasks": S("failedTasks"),
        "created_at": S("createdAt"),
        "updated_at": S("updatedAt"),
        "capacity_provider_strategy": S("capacityProviderStrategy", default=[])
        >> ForallBend(AwsEcsCapacityProviderStrategyItem.mapping),
        "launch_type": S("launchType"),
        "platform_version": S("platformVersion"),
        "platform_family": S("platformFamily"),
        "network_configuration": S("networkConfiguration") >> Bend(AwsEcsNetworkConfiguration.mapping),
        "rollout_state": S("rolloutState"),
        "rollout_state_reason": S("rolloutStateReason"),
    }
    id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    task_definition: Optional[str] = field(default=None)
    desired_count: Optional[int] = field(default=None)
    pending_count: Optional[int] = field(default=None)
    running_count: Optional[int] = field(default=None)
    failed_tasks: Optional[int] = field(default=None)
    created_at: Optional[datetime] = field(default=None)
    updated_at: Optional[datetime] = field(default=None)
    capacity_provider_strategy: List[AwsEcsCapacityProviderStrategyItem] = field(factory=list)
    launch_type: Optional[str] = field(default=None)
    platform_version: Optional[str] = field(default=None)
    platform_family: Optional[str] = field(default=None)
    network_configuration: Optional[AwsEcsNetworkConfiguration] = field(default=None)
    rollout_state: Optional[str] = field(default=None)
    rollout_state_reason: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsServiceEvent:
    kind: ClassVar[str] = "aws_ecs_service_event"
    kind_display: ClassVar[str] = "AWS ECS Service Event"
    kind_description: ClassVar[str] = (
        "ECS service events are used to monitor and track changes in the state of"
        " Amazon Elastic Container Service (ECS) services, such as task placement or"
        " service scaling events."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "created_at": S("createdAt"), "message": S("message")}
    id: Optional[str] = field(default=None)
    created_at: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsPlacementConstraint:
    kind: ClassVar[str] = "aws_ecs_placement_constraint"
    kind_display: ClassVar[str] = "AWS ECS Placement Constraint"
    kind_description: ClassVar[str] = (
        "ECS Placement Constraints are rules used to define where tasks or services"
        " can be placed within an Amazon ECS cluster, based on attributes such as"
        " instance type, availability zone, or custom metadata."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "expression": S("expression")}
    type: Optional[str] = field(default=None)
    expression: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsPlacementStrategy:
    kind: ClassVar[str] = "aws_ecs_placement_strategy"
    kind_display: ClassVar[str] = "AWS ECS Placement Strategy"
    kind_description: ClassVar[str] = (
        "ECS Placement Strategies help you define how tasks in Amazon Elastic"
        " Container Service (ECS) are placed on container instances within a cluster,"
        " taking into consideration factors like instance attributes, availability"
        " zones, and task resource requirements."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "field": S("field")}
    type: Optional[str] = field(default=None)
    field: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsService(EcsTaggable, AwsResource):
    # collection of service resources happens in AwsEcsCluster.collect()
    kind: ClassVar[str] = "aws_ecs_service"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ecs/v2/clusters/{clusterArn}/services/{name}/health?region={region}", "arn_tpl": "arn:{partition}:ecs:{region}:{account}:service/{name}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS ECS Service"
    kind_description: ClassVar[str] = (
        "ECS (Elastic Container Service) is a scalable container orchestration"
        " service provided by AWS, allowing users to easily manage, deploy, and scale"
        " containerized applications."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
            "delete": ["aws_alb_target_group", "aws_elb", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {
            "default": [
                "aws_alb_target_group",
                "aws_elb",
                "aws_ecs_capacity_provider",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("serviceName"),
        "tags": S("tags", default=[]) >> ToDict(),
        "name": S("serviceName"),
        "ctime": S("createdAt"),
        "arn": S("serviceArn"),
        "cluster_arn": S("clusterArn"),
        "service_load_balancers": S("loadBalancers", default=[]) >> ForallBend(AwsEcsLoadBalancer.mapping),
        "service_registries": S("serviceRegistries", default=[]) >> ForallBend(AwsEcsServiceRegistry.mapping),
        "status": S("status"),
        "service_desired_count": S("desiredCount"),
        "service_running_count": S("runningCount"),
        "service_pending_count": S("pendingCount"),
        "service_launch_type": S("launchType"),
        "service_capacity_provider_strategy": S("capacityProviderStrategy", default=[])
        >> ForallBend(AwsEcsCapacityProviderStrategyItem.mapping),
        "service_platform_version": S("platformVersion"),
        "service_platform_family": S("platformFamily"),
        "service_task_definition": S("taskDefinition"),
        "service_deployment_configuration": S("deploymentConfiguration") >> Bend(AwsEcsDeploymentConfiguration.mapping),
        "service_task_sets": S("taskSets", default=[]) >> ForallBend(AwsEcsTaskSet.mapping),
        "service_deployments": S("deployments", default=[]) >> ForallBend(AwsEcsDeployment.mapping),
        "service_role_arn": S("roleArn"),
        "service_events": S("events", default=[]) >> ForallBend(AwsEcsServiceEvent.mapping),
        "service_placement_constraints": S("placementConstraints", default=[])
        >> ForallBend(AwsEcsPlacementConstraint.mapping),
        "service_placement_strategy": S("placementStrategy", default=[]) >> ForallBend(AwsEcsPlacementStrategy.mapping),
        "service_network_configuration": S("networkConfiguration") >> Bend(AwsEcsNetworkConfiguration.mapping),
        "service_health_check_grace_period_seconds": S("healthCheckGracePeriodSeconds"),
        "service_scheduling_strategy": S("schedulingStrategy"),
        "service_deployment_controller": S("deploymentController", "type"),
        "service_created_by": S("createdBy"),
        "service_enable_ecs_managed_tags": S("enableECSManagedTags"),
        "service_propagate_tags": S("propagateTags"),
        "service_enable_execute_command": S("enableExecuteCommand"),
    }
    arn: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    cluster_arn: Optional[str] = field(default=None)
    service_load_balancers: List[AwsEcsLoadBalancer] = field(factory=list)
    service_registries: List[AwsEcsServiceRegistry] = field(factory=list)
    service_desired_count: Optional[int] = field(default=None)
    service_running_count: Optional[int] = field(default=None)
    service_pending_count: Optional[int] = field(default=None)
    service_launch_type: Optional[str] = field(default=None)
    service_capacity_provider_strategy: List[AwsEcsCapacityProviderStrategyItem] = field(factory=list)
    service_platform_version: Optional[str] = field(default=None)
    service_platform_family: Optional[str] = field(default=None)
    service_task_definition: Optional[str] = field(default=None)
    service_deployment_configuration: Optional[AwsEcsDeploymentConfiguration] = field(default=None)
    service_task_sets: List[AwsEcsTaskSet] = field(factory=list)
    service_deployments: List[AwsEcsDeployment] = field(factory=list)
    service_role_arn: Optional[str] = field(default=None)
    service_events: List[AwsEcsServiceEvent] = field(factory=list, metadata=dict(ignore_history=True))
    service_placement_constraints: List[AwsEcsPlacementConstraint] = field(factory=list)
    service_placement_strategy: List[AwsEcsPlacementStrategy] = field(factory=list)
    service_network_configuration: Optional[AwsEcsNetworkConfiguration] = field(default=None)
    service_health_check_grace_period_seconds: Optional[int] = field(default=None)
    service_scheduling_strategy: Optional[str] = field(default=None)
    service_deployment_controller: Optional[str] = field(default=None)
    service_created_by: Optional[str] = field(default=None)
    service_enable_ecs_managed_tags: Optional[bool] = field(default=None)
    service_propagate_tags: Optional[str] = field(default=None)
    service_enable_execute_command: Optional[bool] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # TODO add edge to Cloud Map service registry when applicable
        if self.service_load_balancers:
            for lb in self.service_load_balancers:
                if lb.target_group_arn:
                    builder.dependant_node(
                        self,
                        clazz=AwsAlbTargetGroup,
                        arn=lb.target_group_arn,
                    )
                if lb.load_balancer_name:
                    builder.dependant_node(
                        self,
                        clazz=AwsElb,
                        name=lb.load_balancer_name,
                    )

        if self.service_task_definition:
            task_def = self.service_task_definition
            # task_def is either full arn OR "family:revision"
            if task_def.startswith("arn:"):
                builder.add_edge(self, edge_type=EdgeType.default, clazz=AwsEcsTaskDefinition, arn=task_def)
            else:
                builder.add_edge(
                    self,
                    edge_type=EdgeType.default,
                    clazz=AwsEcsTaskDefinition,
                    family=task_def.split(":")[0],
                    revision=int(task_def.split(":")[1]),
                )

        if self.service_role_arn:
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=AwsIamRole,
                arn=self.service_role_arn,
            )

        all_sec_groups = []
        all_subnets = []
        if self.service_network_configuration and self.service_network_configuration.awsvpc_configuration:
            all_sec_groups.append(self.service_network_configuration.awsvpc_configuration.security_groups)
            all_subnets.append(self.service_network_configuration.awsvpc_configuration.subnets)
        for task_set in self.service_task_sets:
            if task_set.network_configuration and task_set.network_configuration.awsvpc_configuration:
                all_sec_groups.append(task_set.network_configuration.awsvpc_configuration.security_groups)
                all_subnets.append(task_set.network_configuration.awsvpc_configuration.subnets)
        for deployment in self.service_deployments:
            if deployment.network_configuration and deployment.network_configuration.awsvpc_configuration:
                all_sec_groups.append(deployment.network_configuration.awsvpc_configuration.security_groups)
                all_subnets.append(deployment.network_configuration.awsvpc_configuration.subnets)
        for group in sum(all_sec_groups, []):
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=AwsEc2SecurityGroup,
                id=group,
            )
        for subnet in sum(all_subnets, []):
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=AwsEc2Subnet,
                id=subnet,
            )

        all_capacity_providers = []
        for entry in self.service_capacity_provider_strategy:
            all_capacity_providers.append(entry.capacity_provider)
        for task_set in self.service_task_sets:
            for entry in task_set.capacity_provider_strategy:
                all_capacity_providers.append(entry.capacity_provider)
        for deployment in self.service_deployments:
            for entry in deployment.capacity_provider_strategy:
                all_capacity_providers.append(entry.capacity_provider)
        for provider in all_capacity_providers:
            builder.add_edge(self, edge_type=EdgeType.default, clazz=AwsEcsCapacityProvider, name=provider)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-service",
            result_name=None,
            cluster=self.cluster_arn,
            service=self.name,
            force=True,
        )
        return True

    def purge_capacity_provider(self, client: AwsClient, capacity_provider_name: str) -> bool:
        strategy = self.service_capacity_provider_strategy
        try:
            strategy.remove(next(item for item in strategy if item.capacity_provider == capacity_provider_name))
            client.call(
                service_name,
                "update-service",
                None,
                cluster=self.cluster_arn,
                service=self.name,
                capacityProviderStrategy=strategy,
                forceNewDeployment=True,
            )
            return True
        except ValueError:
            return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "update-service"),
            AwsApiSpec(service_name, "delete-service"),
        ]


@define(eq=False, slots=False)
class AwsEcsVersionInfo:
    kind: ClassVar[str] = "aws_ecs_version_info"
    kind_display: ClassVar[str] = "AWS ECS Version Info"
    kind_description: ClassVar[str] = (
        "AWS ECS Version Info provides details about the software versions running on the ECS container agent,"
        " including the version of the ECS agent itself, its hash identifier, and the version of Docker"
        " that is being used."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "agent_version": S("agentVersion"),
        "agent_hash": S("agentHash"),
        "docker_version": S("dockerVersion"),
    }
    agent_version: Optional[str] = field(default=None)
    agent_hash: Optional[str] = field(default=None)
    docker_version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsResource:
    kind: ClassVar[str] = "aws_ecs_resource"
    kind_display: ClassVar[str] = "AWS ECS Resource"
    kind_description: ClassVar[str] = (
        "ECS Resources are computing resources that can be used in Amazon Elastic"
        " Container Service (ECS) to deploy and run containerized applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "type": S("type"),
        "double_value": S("doubleValue"),
        "long_value": S("longValue"),
        "integer_value": S("integerValue"),
        "string_set_value": S("stringSetValue", default=[]),
    }
    name: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    double_value: Optional[float] = field(default=None)
    long_value: Optional[int] = field(default=None)
    integer_value: Optional[int] = field(default=None)
    string_set_value: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsInstanceHealthCheckResult:
    kind: ClassVar[str] = "aws_ecs_instance_health_check_result"
    kind_display: ClassVar[str] = "AWS ECS Instance Health Check Result"
    kind_description: ClassVar[str] = (
        "ECS Instance Health Check Result is the outcome of the health check"
        " performed on an Amazon ECS instance, indicating whether the instance is"
        " healthy or not."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "type": S("type"),
        "status": S("status"),
        "last_updated": S("lastUpdated"),
        "last_status_change": S("lastStatusChange"),
    }
    type: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    last_updated: Optional[datetime] = field(default=None)
    last_status_change: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsContainerInstanceHealthStatus:
    kind: ClassVar[str] = "aws_ecs_container_instance_health_status"
    kind_display: ClassVar[str] = "AWS ECS Container Instance Health Status"
    kind_description: ClassVar[str] = (
        "ECS Container Instance Health Status represents the health status of a"
        " container instance in Amazon ECS (Elastic Container Service). It indicates"
        " whether the container instance is healthy or not based on the reported"
        " health status of the underlying resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "overall_status": S("overallStatus"),
        "details": S("details", default=[]) >> ForallBend(AwsEcsInstanceHealthCheckResult.mapping),
    }
    overall_status: Optional[str] = field(default=None)
    details: List[AwsEcsInstanceHealthCheckResult] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsContainerInstance(EcsTaggable, AwsResource):
    # collection of container instance resources happens in AwsEcsCluster.collect()
    kind: ClassVar[str] = "aws_ecs_container_instance"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:ecs:{region}:{account}:container-instance/{id}"}  # fmt: skip
    kind_display: ClassVar[str] = "AWS ECS Container Instance"
    kind_description: ClassVar[str] = (
        "ECS Container Instances are virtual servers in Amazon's Elastic Container"
        " Service (ECS) that are used to run and manage containers within the ECS"
        " environment."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_ec2_instance"], "delete": ["aws_ec2_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("containerInstanceArn") >> F(AwsResource.id_from_arn),
        "tags": S("tags", default=[]) >> ToDict(),
        "name": S("containerInstanceArn"),
        "ctime": S("registeredAt"),
        "arn": S("containerInstanceArn"),
        "ec2_instance_id": S("ec2InstanceId"),
        "capacity_provider_name": S("capacityProviderName"),
        "version": S("version") >> F(str),
        "version_info": S("versionInfo") >> Bend(AwsEcsVersionInfo.mapping),
        "remaining_resources": S("remainingResources", default=[]) >> ForallBend(AwsEcsResource.mapping),
        "registered_resources": S("registeredResources", default=[]) >> ForallBend(AwsEcsResource.mapping),
        "status": S("status"),
        "status_reason": S("statusReason"),
        "agent_connected": S("agentConnected"),
        "running_tasks_count": S("runningTasksCount"),
        "pending_tasks_count": S("pendingTasksCount"),
        "agent_update_status": S("agentUpdateStatus"),
        "attributes": S("attributes", default=[]) >> ForallBend(AwsEcsAttribute.mapping),
        "attachments": S("attachments", default=[]) >> ForallBend(AwsEcsAttachment.mapping),
        "health_status": S("healthStatus") >> Bend(AwsEcsContainerInstanceHealthStatus.mapping),
    }
    ec2_instance_id: Optional[str] = field(default=None)
    capacity_provider_name: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)
    version_info: Optional[AwsEcsVersionInfo] = field(default=None)
    remaining_resources: List[AwsEcsResource] = field(factory=list)
    registered_resources: List[AwsEcsResource] = field(factory=list)
    status: Optional[str] = field(default=None)
    status_reason: Optional[str] = field(default=None)
    agent_connected: Optional[bool] = field(default=None)
    running_tasks_count: Optional[int] = field(default=None)
    pending_tasks_count: Optional[int] = field(default=None)
    agent_update_status: Optional[str] = field(default=None)
    attributes: List[AwsEcsAttribute] = field(factory=list)
    attachments: List[AwsEcsAttachment] = field(factory=list)
    health_status: Optional[AwsEcsContainerInstanceHealthStatus] = field(default=None)
    cluster_link: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.ec2_instance_id:
            builder.dependant_node(
                self,
                delete_same_as_default=True,
                clazz=AwsEc2Instance,
                id=self.ec2_instance_id,
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            service_name, "deregister-container-instance", None, cluster=self.cluster_link, containerInstance=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "deregister-container-instance")]


@define(eq=False, slots=False)
class AwsEcsExecuteCommandLogConfiguration:
    kind: ClassVar[str] = "aws_ecs_execute_command_log_configuration"
    kind_display: ClassVar[str] = "AWS ECS Execute Command Log Configuration"
    kind_description: ClassVar[str] = (
        "ECS Execute Command Log Configuration is used to configure the logging for"
        " Execute Command feature in Amazon Elastic Container Service (ECS)."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloud_watch_log_group_name": S("cloudWatchLogGroupName"),
        "cloud_watch_encryption_enabled": S("cloudWatchEncryptionEnabled"),
        "s3_bucket_name": S("s3BucketName"),
        "s3_encryption_enabled": S("s3EncryptionEnabled"),
        "s3_key_prefix": S("s3KeyPrefix"),
    }
    cloud_watch_log_group_name: Optional[str] = field(default=None)
    cloud_watch_encryption_enabled: Optional[bool] = field(default=None)
    s3_bucket_name: Optional[str] = field(default=None)
    s3_encryption_enabled: Optional[bool] = field(default=None)
    s3_key_prefix: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsExecuteCommandConfiguration:
    kind: ClassVar[str] = "aws_ecs_execute_command_configuration"
    kind_display: ClassVar[str] = "AWS ECS Execute Command Configuration"
    kind_description: ClassVar[str] = (
        "ECS Execute Command Configuration is a feature in AWS ECS that allows users"
        " to run commands on their ECS containers for debugging and troubleshooting"
        " purposes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "kms_key_id": S("kmsKeyId"),
        "logging": S("logging"),
        "log_configuration": S("logConfiguration") >> Bend(AwsEcsExecuteCommandLogConfiguration.mapping),
    }
    kms_key_id: Optional[str] = field(default=None)
    logging: Optional[str] = field(default=None)
    log_configuration: Optional[AwsEcsExecuteCommandLogConfiguration] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsClusterConfiguration:
    kind: ClassVar[str] = "aws_ecs_cluster_configuration"
    kind_display: ClassVar[str] = "AWS ECS Cluster Configuration"
    kind_description: ClassVar[str] = (
        "ECS Cluster Configuration is a service provided by Amazon Web Services that"
        " allows users to define and configure a cluster of container instances using"
        " Amazon Elastic Container Service (ECS). It enables the management and"
        " orchestration of containerized applications in a scalable and highly"
        " available manner."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "execute_command_configuration": S("executeCommandConfiguration")
        >> Bend(AwsEcsExecuteCommandConfiguration.mapping)
    }
    execute_command_configuration: Optional[AwsEcsExecuteCommandConfiguration] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsClusterSetting:
    kind: ClassVar[str] = "aws_ecs_cluster_setting"
    kind_display: ClassVar[str] = "AWS ECS Cluster Setting"
    kind_description: ClassVar[str] = (
        "ECS Cluster Settings are configurations that define the properties and"
        " behavior of an Amazon ECS cluster, allowing users to customize and manage"
        " their containerized applications efficiently."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsCluster(EcsTaggable, AwsResource):
    kind: ClassVar[str] = "aws_ecs_cluster"
    kind_display: ClassVar[str] = "AWS ECS Cluster"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ecs/v2/clusters/{name}/services?region={region}", "arn_tpl": "arn:{partition}:ecs:{region}:{account}:cluster/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "ECS (Elastic Container Service) Cluster is a managed cluster of Amazon EC2"
        " instances used to deploy and manage Docker containers."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-clusters", "clusterArns")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_kms_key", "aws_s3_bucket"]},
        "successors": {
            "default": [
                "aws_kms_key",
                "aws_s3_bucket",
                "aws_ecs_container_instance",
                "aws_ecs_service",
                "aws_ecs_task",
                "aws_ecs_capacity_provider",
            ]
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("clusterName"),
        "tags": S("tags", default=[]) >> ToDict(),
        "name": S("clusterName"),
        "arn": S("clusterArn"),
        "cluster_configuration": S("configuration") >> Bend(AwsEcsClusterConfiguration.mapping),
        "cluster_status": S("status"),
        "cluster_registered_container_instances_count": S("registeredContainerInstancesCount"),
        "cluster_running_tasks_count": S("runningTasksCount"),
        "cluster_pending_tasks_count": S("pendingTasksCount"),
        "cluster_active_services_count": S("activeServicesCount"),
        "cluster_statistics": S("statistics", default=[]) >> ForallBend(AwsEcsKeyValuePair.mapping),
        "cluster_settings": S("settings", default=[]) >> ForallBend(AwsEcsClusterSetting.mapping),
        "cluster_capacity_providers": S("capacityProviders", default=[]),
        "cluster_default_capacity_provider_strategy": S("defaultCapacityProviderStrategy", default=[])
        >> ForallBend(AwsEcsCapacityProviderStrategyItem.mapping),
        "cluster_attachments": S("attachments", default=[]) >> ForallBend(AwsEcsAttachment.mapping),
        "cluster_attachments_status": S("attachmentsStatus"),
    }
    cluster_configuration: Optional[AwsEcsClusterConfiguration] = field(default=None)
    cluster_status: Optional[str] = field(default=None)
    cluster_registered_container_instances_count: Optional[int] = field(
        default=None, metadata=dict(ignore_history=True)
    )
    cluster_running_tasks_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    cluster_pending_tasks_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    cluster_active_services_count: Optional[int] = field(default=None)
    cluster_statistics: List[AwsEcsKeyValuePair] = field(factory=list, metadata=dict(ignore_history=True))
    cluster_settings: List[AwsEcsClusterSetting] = field(factory=list)
    cluster_capacity_providers: List[str] = field(factory=list)
    cluster_default_capacity_provider_strategy: List[AwsEcsCapacityProviderStrategyItem] = field(factory=list)
    cluster_attachments: List[AwsEcsAttachment] = field(factory=list)
    cluster_attachments_status: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-clusters"),
            AwsApiSpec(service_name, "list-container-instances"),
            AwsApiSpec(service_name, "describe-container-instances"),
            AwsApiSpec(service_name, "list-services"),
            AwsApiSpec(service_name, "describe-services"),
            AwsApiSpec(service_name, "list-tasks"),
            AwsApiSpec(service_name, "describe-tasks"),
            AwsApiSpec(service_name, "describe-capacity-providers"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        instances = []
        for cluster_arn in json:
            cluster = builder.client.list(
                service_name,
                "describe-clusters",
                "clusters",
                clusters=[cluster_arn],
                include=["ATTACHMENTS", "CONFIGURATIONS", "SETTINGS", "STATISTICS", "TAGS"],
            )
            if cluster_instance := AwsEcsCluster.from_api(cluster[0], builder):
                builder.add_node(cluster_instance, cluster_arn)
                instances.append(cluster_instance)

                container_arns = builder.client.list(
                    service_name, "list-container-instances", "containerInstanceArns", cluster=cluster_arn
                )
                for chunk in chunks(container_arns, 100):
                    containers = builder.client.list(
                        service_name,
                        "describe-container-instances",
                        "containerInstances",
                        cluster=cluster_arn,
                        containerInstances=chunk,
                        include=["TAGS", "CONTAINER_INSTANCE_HEALTH"],
                    )
                    for container in containers:
                        if container_instance := AwsEcsContainerInstance.from_api(container, builder):
                            container_instance.cluster_link = cluster_instance.arn
                            builder.add_node(container_instance, container)
                            builder.add_edge(cluster_instance, edge_type=EdgeType.default, node=container_instance)

                service_arns = builder.client.list(service_name, "list-services", "serviceArns", cluster=cluster_arn)
                for chunk in chunks(service_arns, 10):
                    services = builder.client.list(
                        service_name,
                        "describe-services",
                        "services",
                        cluster=cluster_arn,
                        services=chunk,
                        include=["TAGS"],
                    )
                    for service in services:
                        if service_instance := AwsEcsService.from_api(service, builder):
                            builder.add_node(service_instance, service)
                            builder.add_edge(cluster_instance, edge_type=EdgeType.default, node=service_instance)

                task_arns = builder.client.list(service_name, "list-tasks", "taskArns", cluster=cluster_arn)
                for chunk in chunks(task_arns, 100):
                    tasks = builder.client.list(
                        service_name,
                        "describe-tasks",
                        "tasks",
                        cluster=cluster_arn,
                        tasks=chunk,
                        include=["TAGS"],
                    )
                    for task in tasks:
                        if task_instance := AwsEcsTask.from_api(task, builder):
                            builder.add_node(task_instance, task)
                            builder.add_edge(cluster_instance, edge_type=EdgeType.default, node=task_instance)

        # once all clusters are collected, collect capacity providers
        provider_names = {name for instance in instances for name in instance.cluster_capacity_providers}
        providers: Dict[str, AwsEcsCapacityProvider] = {}
        for chunk in chunks(list(provider_names), 100):
            for provider in builder.client.list(
                service_name,
                "describe-capacity-providers",
                "capacityProviders",
                capacityProviders=chunk,
                include=["TAGS"],
            ):
                if provider_instance := AwsEcsCapacityProvider.from_api(provider, builder):
                    builder.add_node(provider_instance, provider)
                    providers[provider_instance.safe_name] = provider_instance

        # connect clusters to providers
        for instance in instances:
            for name in instance.cluster_capacity_providers:
                if provider := providers.get(name):
                    builder.add_edge(instance, edge_type=EdgeType.default, node=provider)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # TODO add edge to CloudWatchLogs LogGroup when applicable
        if ccf := self.cluster_configuration:
            if exc := ccf.execute_command_configuration:
                if exc.kms_key_id:
                    builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(exc.kms_key_id))
                if exc.log_configuration and exc.log_configuration.s3_bucket_name:
                    builder.add_edge(self, clazz=AwsS3Bucket, name=exc.log_configuration.s3_bucket_name)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-cluster", result_name=None, cluster=self.arn)
        return True

    def disassociate_capacity_provider(self, client: AwsClient, capacity_provider_name: str) -> bool:
        try:
            strategy = self.cluster_default_capacity_provider_strategy
            strategy.remove(next(item for item in strategy if item.capacity_provider == capacity_provider_name))
            self.cluster_capacity_providers.remove(capacity_provider_name)
            client.call(
                service_name,
                "put-cluster-capacity-providers",
                None,
                cluster=self.arn,
                capacityProviders=self.cluster_capacity_providers,
                defaultCapacityProviderStrategy=strategy,
            )
            return True
        except ValueError:
            return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-cluster")]


resources: List[Type[AwsResource]] = [
    AwsEcsCluster,
    AwsEcsContainerInstance,
    AwsEcsService,
    AwsEcsTaskDefinition,
    AwsEcsTask,
    AwsEcsCapacityProvider,
]
