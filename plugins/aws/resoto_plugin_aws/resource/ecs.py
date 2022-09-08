from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient

from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.ec2 import AwsEc2Instance
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.resource.s3 import AwsS3Bucket
from resotolib.baseresources import EdgeType, ModelReference
from resotolib.json_bender import Bender, S, Bend, ForallBend
from resotolib.types import Json
from resotolib.utils import chunks
from resoto_plugin_aws.utils import ToDict


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


@define(eq=False, slots=False)
class AwsEcsLoadBalancer:
    kind: ClassVar[str] = "aws_ecs_load_balancer"
    mapping: ClassVar[Dict[str, Bender]] = {
        "target_group_arn": S("targetGroupArn"),
        "load_balancer_name": S("loadBalancerName"),
        "container_name": S("containerName"),
        "container_port": S("containerPort")
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
        "container_port": S("containerPort")
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
        "base": S("base")
    }
    capacity_provider: Optional[str] = field(default=None)
    weight: Optional[int] = field(default=None)
    base: Optional[int] = field(default=None)

@define(eq=False, slots=False)
class AwsEcsDeploymentCircuitBreaker:
    kind: ClassVar[str] = "aws_ecs_deployment_circuit_breaker"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable": S("enable"),
        "rollback": S("rollback")
    }
    enable: Optional[bool] = field(default=None)
    rollback: Optional[bool] = field(default=None)

@define(eq=False, slots=False)
class AwsEcsDeploymentConfiguration:
    kind: ClassVar[str] = "aws_ecs_deployment_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "deployment_circuit_breaker": S("deploymentCircuitBreaker") >> Bend(AwsEcsDeploymentCircuitBreaker.mapping),
        "maximum_percent": S("maximumPercent"),
        "minimum_healthy_percent": S("minimumHealthyPercent")
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
        "assign_public_ip": S("assignPublicIp")
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "value": S("value"),
        "unit": S("unit")
    }
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
        "capacity_provider_strategy": S("capacityProviderStrategy", default=[]) >> ForallBend(AwsEcsCapacityProviderStrategyItem.mapping),
        "platform_version": S("platformVersion"),
        "platform_family": S("platformFamily"),
        "network_configuration": S("networkConfiguration") >> Bend(AwsEcsNetworkConfiguration.mapping),
        "load_balancers": S("loadBalancers", default=[]) >> ForallBend(AwsEcsLoadBalancer.mapping),
        "service_registries": S("serviceRegistries", default=[]) >> ForallBend(AwsEcsServiceRegistry.mapping),
        "scale": S("scale") >> Bend(AwsEcsScale.mapping),
        "stability_status": S("stabilityStatus"),
        "stability_status_at": S("stabilityStatusAt")
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
        "capacity_provider_strategy": S("capacityProviderStrategy", default=[]) >> ForallBend(AwsEcsCapacityProviderStrategyItem.mapping),
        "launch_type": S("launchType"),
        "platform_version": S("platformVersion"),
        "platform_family": S("platformFamily"),
        "network_configuration": S("networkConfiguration") >> Bend(AwsEcsNetworkConfiguration.mapping),
        "rollout_state": S("rolloutState"),
        "rollout_state_reason": S("rolloutStateReason")
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "created_at": S("createdAt"),
        "message": S("message")
    }
    id: Optional[str] = field(default=None)
    created_at: Optional[datetime] = field(default=None)
    message: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsEcsPlacementConstraint:
    kind: ClassVar[str] = "aws_ecs_placement_constraint"
    mapping: ClassVar[Dict[str, Bender]] = {
        "type": S("type"),
        "expression": S("expression")
    }
    type: Optional[str] = field(default=None)
    expression: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsEcsPlacementStrategy:
    kind: ClassVar[str] = "aws_ecs_placement_strategy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "type": S("type"),
        "field": S("field")
    }
    type: Optional[str] = field(default=None)
    field: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEcsService(EcsTaggable, AwsResource):
    # collection of service resources happens in AwsEcsCluster.collect()
    kind: ClassVar[str] = "aws_ecs_service"
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
        "service_capacity_provider_strategy": S("capacityProviderStrategy", default=[]) >> ForallBend(AwsEcsCapacityProviderStrategyItem.mapping),
        "service_platform_version": S("platformVersion"),
        "service_platform_family": S("platformFamily"),
        "service_task_definition": S("taskDefinition"),
        "service_deployment_configuration": S("deploymentConfiguration") >> Bend(AwsEcsDeploymentConfiguration.mapping),
        "service_task_sets": S("taskSets", default=[]) >> ForallBend(AwsEcsTaskSet.mapping),
        "service_deployments": S("deployments", default=[]) >> ForallBend(AwsEcsDeployment.mapping),
        "service_role_arn": S("roleArn"),
        "service_events": S("events", default=[]) >> ForallBend(AwsEcsServiceEvent.mapping),
        "service_placement_constraints": S("placementConstraints", default=[]) >> ForallBend(AwsEcsPlacementConstraint.mapping),
        "service_placement_strategy": S("placementStrategy", default=[]) >> ForallBend(AwsEcsPlacementStrategy.mapping),
        "service_network_configuration": S("networkConfiguration") >> Bend(AwsEcsNetworkConfiguration.mapping),
        "service_health_check_grace_period_seconds": S("healthCheckGracePeriodSeconds"),
        "service_scheduling_strategy": S("schedulingStrategy"),
        "service_deployment_controller": S("deploymentController","type"),
        "service_created_by": S("createdBy"),
        "service_enable_ecs_managed_tags": S("enableECSManagedTags"),
        "service_propagate_tags": S("propagateTags"),
        "service_enable_execute_command": S("enableExecuteCommand")
    }
    arn: Optional[str] = field(default=None)
    cluster_arn: Optional[str] = field(default=None)
    service_load_balancers: List[AwsEcsLoadBalancer] = field(factory=list)
    service_registries: List[AwsEcsServiceRegistry] = field(factory=list)
    service_status: Optional[str] = field(default=None)
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
        "predecessors": {"delete": ["aws_ec2_instance"]},
        "successors": {"default": ["aws_ec2_instance"]}
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("containerInstanceArn"),
        "tags": S("tags", default=[]) >> ToDict(),
        "name": S("containerInstanceArn"),  # S("Tags", default=[]) >> TagsValue("Name"),
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
    container_instance_arn: Optional[str] = field(default=None)
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

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.ec2_instance_id:
            builder.dependant_node(
                self,
                clazz=AwsEc2Instance,
                id=self.ec2_instance_id,
            )


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
class AwsEcsCluster(EcsTaggable, AwsResource):
    kind: ClassVar[str] = "aws_ecs_cluster"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ecs", "list-clusters", "clusterArns")  # list?
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_kms_key", "aws_s3_bucket"]},
        "successors": {"default": ["aws_kms_key", "aws_s3_bucket", "aws_ecs_container_instance"]},
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
    def called_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec("ecs", "describe-clusters"),
            AwsApiSpec("ecs", "list-container-instances"),
            AwsApiSpec("ecs", "describe-container-instances"),
            AwsApiSpec("ecs", "list-services"),
            AwsApiSpec("ecs", "describe-services"),
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
            cluster_instance = cls.from_api(cluster[0])
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
                    builder.add_node(container_instance, container)
                    builder.add_edge(cluster_instance, edge_type=EdgeType.default, node=container_instance)

            service_arns = builder.client.list(
                "ecs", "list-services", "serviceArns", cluster=cluster_arn
            )
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


    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
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
        # TODO add edge to CloudWatchLogs LogGroup when applicable

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(service=self.api_spec.service, action="delete-cluster", result_name=None, cluster=self.arn)
        return True


resources: List[Type[AwsResource]] = [AwsEcsCluster, AwsEcsContainerInstance, AwsEcsService]
