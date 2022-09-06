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


resources: List[Type[AwsResource]] = [AwsEcsCluster, AwsEcsContainerInstance]
