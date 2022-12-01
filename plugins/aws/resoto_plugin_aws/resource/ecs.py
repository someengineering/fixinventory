from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.autoscaling import AwsAutoScalingGroup

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2Instance, AwsEc2SecurityGroup, AwsEc2Subnet
from resoto_plugin_aws.resource.elb import AwsElb
from resoto_plugin_aws.resource.elbv2 import AwsAlbTargetGroup
from resoto_plugin_aws.resource.iam import AwsIamRole
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.resource.s3 import AwsS3Bucket
from resotolib.baseresources import EdgeType, ModelReference
from resotolib.graph import Graph
from resotolib.json_bender import F, Bender, S, Bend, ForallBend
from resotolib.types import Json
from resotolib.utils import chunks
from resoto_plugin_aws.utils import TagsValue, ToDict


class EcsTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    service=spec.service,
                    action="tag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tags=[{"key": key, "value": value}],
                )
                return True
            return False
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    service=spec.service,
                    action="untag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tagKeys=[key],
                )
                return True
            return False
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("ecs", "tag-resource"), AwsApiSpec("ecs", "untag-resource")]


@define(eq=False, slots=False)
class AwsEcsManagedScaling:
    kind: ClassVar[str] = "aws_ecs_managed_scaling"
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call("ecs", "delete-capacity-provider", None, capacityProvider=self.safe_name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:

        return super().called_mutator_apis() + [
            AwsApiSpec("ecs", "update-service"),
            AwsApiSpec("ecs", "put-cluster-capacity-providers"),
            AwsApiSpec("ecs", "delete-capacity-provider"),
            AwsApiSpec("ecs", "put-cluster-capacity-providers"),
        ]


@define(eq=False, slots=False)
class AwsEcsKeyValuePair:
    kind: ClassVar[str] = "aws_ecs_key_value_pair"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsAttachment:
    kind: ClassVar[str] = "aws_ecs_attachment"
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
    image_digest: Optional[str] = field(default=None)
    runtime_id: Optional[str] = field(default=None)
    last_status: Optional[str] = field(default=None)
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
    mapping: ClassVar[Dict[str, Bender]] = {"device_name": S("deviceName"), "device_type": S("deviceType")}
    device_name: Optional[str] = field(default=None)
    device_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsEnvironmentFile:
    kind: ClassVar[str] = "aws_ecs_environment_file"
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value"), "type": S("type")}
    value: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsResourceRequirement:
    kind: ClassVar[str] = "aws_ecs_resource_requirement"
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value"), "type": S("type")}
    value: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsContainerOverride:
    kind: ClassVar[str] = "aws_ecs_container_override"
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
    task_connectivity: Optional[str] = field(default=None)
    task_connectivity_at: Optional[datetime] = field(default=None)
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
    task_pull_started_at: Optional[datetime] = field(default=None)
    task_pull_stopped_at: Optional[datetime] = field(default=None)
    task_started_at: Optional[datetime] = field(default=None)
    task_started_by: Optional[str] = field(default=None)
    task_stop_code: Optional[str] = field(default=None)
    task_stopped_at: Optional[datetime] = field(default=None)
    task_stopped_reason: Optional[str] = field(default=None)
    task_stopping_at: Optional[datetime] = field(default=None)
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="ecs", action="stop-task", result_name=None, cluster=self.task_cluster_arn, task=self.arn
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec("ecs", "stop-task")]


@define(eq=False, slots=False)
class AwsEcsPortMapping:
    kind: ClassVar[str] = "aws_ecs_port_mapping"
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
    mapping: ClassVar[Dict[str, Bender]] = {"source_container": S("sourceContainer"), "read_only": S("readOnly")}
    source_container: Optional[str] = field(default=None)
    read_only: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsKernelCapabilities:
    kind: ClassVar[str] = "aws_ecs_kernel_capabilities"
    mapping: ClassVar[Dict[str, Bender]] = {"add": S("add", default=[]), "drop": S("drop", default=[])}
    add: List[str] = field(factory=list)
    drop: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEcsDevice:
    kind: ClassVar[str] = "aws_ecs_device"
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
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value_from": S("valueFrom")}
    name: Optional[str] = field(default=None)
    value_from: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsContainerDependency:
    kind: ClassVar[str] = "aws_ecs_container_dependency"
    mapping: ClassVar[Dict[str, Bender]] = {"container_name": S("containerName"), "condition": S("condition")}
    container_name: Optional[str] = field(default=None)
    condition: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsHostEntry:
    kind: ClassVar[str] = "aws_ecs_host_entry"
    mapping: ClassVar[Dict[str, Bender]] = {"hostname": S("hostname"), "ip_address": S("ipAddress")}
    hostname: Optional[str] = field(default=None)
    ip_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsUlimit:
    kind: ClassVar[str] = "aws_ecs_ulimit"
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
    mapping: ClassVar[Dict[str, Bender]] = {"namespace": S("namespace"), "value": S("value")}
    namespace: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsFirelensConfiguration:
    kind: ClassVar[str] = "aws_ecs_firelens_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "options": S("options")}
    type: Optional[str] = field(default=None)
    options: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsContainerDefinition:
    kind: ClassVar[str] = "aws_ecs_container_definition"
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
    mapping: ClassVar[Dict[str, Bender]] = {"access_point_id": S("accessPointId"), "iam": S("iam")}
    access_point_id: Optional[str] = field(default=None)
    iam: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsEFSVolumeConfiguration:
    kind: ClassVar[str] = "aws_ecs_efs_volume_configuration"
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
    mapping: ClassVar[Dict[str, Bender]] = {"credentials_parameter": S("credentialsParameter"), "domain": S("domain")}
    credentials_parameter: Optional[str] = field(default=None)
    domain: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsFSxWindowsFileServerVolumeConfiguration:
    kind: ClassVar[str] = "aws_ecs_f_sx_windows_file_server_volume_configuration"
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
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "expression": S("expression")}
    type: Optional[str] = field(default=None)
    expression: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsRuntimePlatform:
    kind: ClassVar[str] = "aws_ecs_runtime_platform"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cpu_architecture": S("cpuArchitecture"),
        "operating_system_family": S("operatingSystemFamily"),
    }
    cpu_architecture: Optional[str] = field(default=None)
    operating_system_family: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsProxyConfiguration:
    kind: ClassVar[str] = "aws_ecs_proxy_configuration"
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
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ecs", "list-task-definitions", "taskDefinitionArns")
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
            AwsApiSpec("ecs", "describe-task-definition"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for task_def_arn in json:
            response = builder.client.list(
                "ecs",
                "describe-task-definition",
                None,
                taskDefinition=task_def_arn,
                include=["TAGS"],
            )
            task_definition = response[0]["taskDefinition"]
            tags = response[0]["tags"]
            task_definition["tags"] = tags
            task_definition_instance = cls.from_api(task_definition)
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="ecs",
            action="deregister-task-definition",
            result_name=None,
            taskDefinition=f"{self.family}:{self.revision}",
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec("ecs", "deregister-task-definition")]


@define(eq=False, slots=False)
class AwsEcsLoadBalancer:
    kind: ClassVar[str] = "aws_ecs_load_balancer"
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
    mapping: ClassVar[Dict[str, Bender]] = {"enable": S("enable"), "rollback": S("rollback")}
    enable: Optional[bool] = field(default=None)
    rollback: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsDeploymentConfiguration:
    kind: ClassVar[str] = "aws_ecs_deployment_configuration"
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "awsvpc_configuration": S("awsvpcConfiguration") >> Bend(AwsEcsAwsVpcConfiguration.mapping)
    }
    awsvpc_configuration: Optional[AwsEcsAwsVpcConfiguration] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsScale:
    kind: ClassVar[str] = "aws_ecs_scale"
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value"), "unit": S("unit")}
    value: Optional[float] = field(default=None)
    unit: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsTaskSet:
    kind: ClassVar[str] = "aws_ecs_task_set"
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
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "created_at": S("createdAt"), "message": S("message")}
    id: Optional[str] = field(default=None)
    created_at: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsPlacementConstraint:
    kind: ClassVar[str] = "aws_ecs_placement_constraint"
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "expression": S("expression")}
    type: Optional[str] = field(default=None)
    expression: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsPlacementStrategy:
    kind: ClassVar[str] = "aws_ecs_placement_strategy"
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("type"), "field": S("field")}
    type: Optional[str] = field(default=None)
    field: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsService(EcsTaggable, AwsResource):
    # collection of service resources happens in AwsEcsCluster.collect()
    kind: ClassVar[str] = "aws_ecs_service"
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role"],
            "delete": ["aws_alb_target_group", "aws_elb", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {
            "default": [
                "aws_alb_target_group",
                "aws_elb",
                "aws_ec2_subnet",
                "aws_ec2_security_group",
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
    service_events: List[AwsEcsServiceEvent] = field(factory=list)
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
                clazz=AwsEc2SecurityGroup,
                id=group,
            )
        for subnet in sum(all_subnets, []):
            builder.dependant_node(
                self,
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="ecs",
            action="delete-service",
            result_name=None,
            cluster=self.cluster_arn,
            service=self.name,
        )
        return True

    def purge_capacity_provider(self, client: AwsClient, capacity_provider_name: str) -> bool:
        strategy = self.service_capacity_provider_strategy
        try:
            strategy.remove(next(item for item in strategy if item.capacity_provider == capacity_provider_name))
            client.call(
                "ecs",
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
            AwsApiSpec("ecs", "update-service"),
            AwsApiSpec("ecs", "delete-service"),
        ]


@define(eq=False, slots=False)
class AwsEcsVersionInfo:
    kind: ClassVar[str] = "aws_ecs_version_info"
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
        "version": S("version"),
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
    version: Optional[int] = field(default=None)
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

    def delete_resource(self, client: AwsClient) -> bool:
        client.call("ecs", "deregister-container-instance", None, cluster=self.cluster_link, containerInstance=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec("ecs", "deregister-container-instance")]


@define(eq=False, slots=False)
class AwsEcsExecuteCommandLogConfiguration:
    kind: ClassVar[str] = "aws_ecs_execute_command_log_configuration"
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "execute_command_configuration": S("executeCommandConfiguration")
        >> Bend(AwsEcsExecuteCommandConfiguration.mapping)
    }
    execute_command_configuration: AwsEcsExecuteCommandConfiguration = field(default=None)


@define(eq=False, slots=False)
class AwsEcsClusterSetting:
    kind: ClassVar[str] = "aws_ecs_cluster_setting"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsCluster(EcsTaggable, AwsResource):
    kind: ClassVar[str] = "aws_ecs_cluster"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ecs", "list-clusters", "clusterArns")
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
    cluster_registered_container_instances_count: Optional[int] = field(default=None)
    cluster_running_tasks_count: Optional[int] = field(default=None)
    cluster_pending_tasks_count: Optional[int] = field(default=None)
    cluster_active_services_count: Optional[int] = field(default=None)
    cluster_statistics: List[AwsEcsKeyValuePair] = field(factory=list)
    cluster_settings: List[AwsEcsClusterSetting] = field(factory=list)
    cluster_capacity_providers: List[str] = field(factory=list)
    cluster_default_capacity_provider_strategy: List[AwsEcsCapacityProviderStrategyItem] = field(factory=list)
    cluster_attachments: List[AwsEcsAttachment] = field(factory=list)
    cluster_attachments_status: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec("ecs", "describe-clusters"),
            AwsApiSpec("ecs", "list-container-instances"),
            AwsApiSpec("ecs", "describe-container-instances"),
            AwsApiSpec("ecs", "list-services"),
            AwsApiSpec("ecs", "describe-services"),
            AwsApiSpec("ecs", "list-tasks"),
            AwsApiSpec("ecs", "describe-tasks"),
            AwsApiSpec("ecs", "describe-capacity-providers"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for cluster_arn in json:
            cluster = builder.client.list(
                "ecs",
                "describe-clusters",
                "clusters",
                clusters=[cluster_arn],
                include=["ATTACHMENTS", "CONFIGURATIONS", "SETTINGS", "STATISTICS", "TAGS"],
            )
            cluster_instance = AwsEcsCluster.from_api(cluster[0])
            builder.add_node(cluster_instance, cluster_arn)

            container_arns = builder.client.list(
                "ecs", "list-container-instances", "containerInstanceArns", cluster=cluster_arn
            )
            for chunk in chunks(container_arns, 100):
                containers = builder.client.list(
                    "ecs",
                    "describe-container-instances",
                    "containerInstances",
                    cluster=cluster_arn,
                    containerInstances=chunk,
                    include=["TAGS", "CONTAINER_INSTANCE_HEALTH"],
                )
                for container in containers:
                    container_instance = AwsEcsContainerInstance.from_api(container)
                    container_instance.cluster_link = cluster_instance.arn
                    builder.add_node(container_instance, container)
                    builder.add_edge(cluster_instance, edge_type=EdgeType.default, node=container_instance)

            service_arns = builder.client.list("ecs", "list-services", "serviceArns", cluster=cluster_arn)
            for chunk in chunks(service_arns, 10):
                services = builder.client.list(
                    "ecs",
                    "describe-services",
                    "services",
                    cluster=cluster_arn,
                    services=chunk,
                    include=["TAGS"],
                )
                for service in services:
                    service_instance = AwsEcsService.from_api(service)
                    builder.add_node(service_instance, service)
                    builder.add_edge(cluster_instance, edge_type=EdgeType.default, node=service_instance)

            task_arns = builder.client.list("ecs", "list-tasks", "taskArns", cluster=cluster_arn)
            for chunk in chunks(task_arns, 100):
                tasks = builder.client.list(
                    "ecs",
                    "describe-tasks",
                    "tasks",
                    cluster=cluster_arn,
                    tasks=chunk,
                    include=["TAGS"],
                )
                for task in tasks:
                    task_instance = AwsEcsTask.from_api(task)
                    builder.add_node(task_instance, task)
                    builder.add_edge(cluster_instance, edge_type=EdgeType.default, node=task_instance)

            provider_names = cluster_instance.cluster_capacity_providers
            for chunk in chunks(provider_names, 100):
                providers = builder.client.list(
                    "ecs", "describe-capacity-providers", "capacityProviders", capacityProviders=chunk, include=["TAGS"]
                )
                for provider in providers:
                    provider_instance = AwsEcsCapacityProvider.from_api(provider)
                    builder.add_node(provider_instance, provider)
                    builder.add_edge(cluster_instance, edge_type=EdgeType.default, node=provider_instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # TODO add edge to CloudWatchLogs LogGroup when applicable
        if self.cluster_configuration:
            if self.cluster_configuration.execute_command_configuration.kms_key_id:
                builder.dependant_node(
                    self,
                    clazz=AwsKmsKey,
                    id=AwsKmsKey.normalise_id(self.cluster_configuration.execute_command_configuration.kms_key_id),
                )
            if (
                self.cluster_configuration.execute_command_configuration.log_configuration
                and self.cluster_configuration.execute_command_configuration.log_configuration.s3_bucket_name
            ):
                builder.dependant_node(
                    self,
                    clazz=AwsS3Bucket,
                    name=self.cluster_configuration.execute_command_configuration.log_configuration.s3_bucket_name,
                )

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(service=self.api_spec.service, action="delete-cluster", result_name=None, cluster=self.arn)
        return True

    def disassociate_capacity_provider(self, client: AwsClient, capacity_provider_name: str) -> bool:
        try:
            strategy = self.cluster_default_capacity_provider_strategy
            strategy.remove(next(item for item in strategy if item.capacity_provider == capacity_provider_name))
            self.cluster_capacity_providers.remove(capacity_provider_name)
            client.call(
                "ecs",
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
        return super().called_mutator_apis() + [AwsApiSpec("ecs", "delete-cluster")]


resources: List[Type[AwsResource]] = [
    AwsEcsCluster,
    AwsEcsContainerInstance,
    AwsEcsService,
    AwsEcsTaskDefinition,
    AwsEcsTask,
    AwsEcsCapacityProvider,
]
