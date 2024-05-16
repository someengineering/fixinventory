from typing import ClassVar, Dict, Optional, List, Any

from attrs import define, field

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.sns import AwsSnsTopic
from fixlib.baseresources import ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend, K, bend
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.utils import ToDict
from typing import Type
from datetime import datetime
from fixlib.types import Json
from fix_plugin_aws.resource.ec2 import AwsEc2SecurityGroup

service_name = "elasticache"


# noinspection PyUnresolvedReferences
class ElastiCacheTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="add-tags-to-resource",
                result_name=None,
                ResourceName=self.arn,
                Tags=[{"Key": key, "Value": value}],
            )
            return True
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="remove-tags-from-resource",
                result_name=None,
                ResourceName=self.arn,
                TagKeys=[key],
            )
            return True
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "add-tags-to-resource"),
            AwsApiSpec(service_name, "remove-tags-from-resource"),
        ]


@define(eq=False, slots=False)
class AwsElastiCacheEndpoint:
    kind: ClassVar[str] = "aws_elasticache_endpoint"
    kind_display: ClassVar[str] = "AWS ElastiCache Endpoint"
    kind_description: ClassVar[str] = (
        "ElastiCache is a web service that makes it easy to deploy, operate, and"
        " scale an in-memory cache in the cloud. The Elasticache endpoint refers to"
        " the endpoint URL that is used to connect to the ElastiCache cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"address": S("Address"), "port": S("Port")}
    address: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheDestinationDetails:
    kind: ClassVar[str] = "aws_elasticache_destination_details"
    kind_display: ClassVar[str] = "AWS ElastiCache Destination Details"
    kind_description: ClassVar[str] = (
        "AWS ElastiCache Destination Details encompass the configuration specifics for where ElastiCache"
        " can send logs, including details for both Amazon CloudWatch Logs and Amazon Kinesis Firehose"
        " as potential log delivery destinations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloud_watch_logs_details": S("CloudWatchLogsDetails", "LogGroup"),
        "kinesis_firehose_details": S("KinesisFirehoseDetails", "DeliveryStream"),
    }
    cloud_watch_logs_details: Optional[str] = field(default=None)
    kinesis_firehose_details: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCachePendingLogDeliveryConfiguration:
    kind: ClassVar[str] = "aws_elasticache_pending_log_delivery_configuration"
    kind_display: ClassVar[str] = "AWS ElastiCache Pending Log Delivery Configuration"
    kind_description: ClassVar[str] = (
        "The AWS ElastiCache Pending Log Delivery Configuration details the configurations for log delivery"
        " that are awaiting activation. It specifies the type of logs to deliver, the intended destination"
        " service, the format of the logs, and additional details about the destination."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "log_type": S("LogType"),
        "destination_type": S("DestinationType"),
        "destination_details": S("DestinationDetails") >> Bend(AwsElastiCacheDestinationDetails.mapping),
        "log_format": S("LogFormat"),
    }
    log_type: Optional[str] = field(default=None)
    destination_type: Optional[str] = field(default=None)
    destination_details: Optional[AwsElastiCacheDestinationDetails] = field(default=None)
    log_format: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCachePendingModifiedValues:
    kind: ClassVar[str] = "aws_elasticache_pending_modified_values"
    kind_display: ClassVar[str] = "AWS ElastiCache Pending Modified Values"
    kind_description: ClassVar[str] = (
        "ElastiCache Pending Modified Values is a feature in Amazon ElastiCache,"
        " which allows users to view the configuration modifications that are waiting"
        " to be applied to a cache cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "num_cache_nodes": S("NumCacheNodes"),
        "cache_node_ids_to_remove": S("CacheNodeIdsToRemove", default=[]),
        "engine_version": S("EngineVersion"),
        "cache_node_type": S("CacheNodeType"),
        "auth_token_status": S("AuthTokenStatus"),
        "log_delivery_configurations": S("LogDeliveryConfigurations", default=[])
        >> ForallBend(AwsElastiCachePendingLogDeliveryConfiguration.mapping),
    }
    num_cache_nodes: Optional[int] = field(default=None)
    cache_node_ids_to_remove: List[str] = field(factory=list)
    engine_version: Optional[str] = field(default=None)
    cache_node_type: Optional[str] = field(default=None)
    auth_token_status: Optional[str] = field(default=None)
    log_delivery_configurations: List[AwsElastiCachePendingLogDeliveryConfiguration] = field(factory=list)


@define(eq=False, slots=False)
class AwsElastiCacheNotificationConfiguration:
    kind: ClassVar[str] = "aws_elasticache_notification_configuration"
    kind_display: ClassVar[str] = "AWS ElastiCache Notification Configuration"
    kind_description: ClassVar[str] = (
        "The AWS ElastiCache Notification Configuration specifies settings for sending notifications related to an"
        " ElastiCache instance, including the Amazon Resource Name (ARN) of the notification topic and the status"
        " of notification delivery."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"topic_arn": S("TopicArn"), "topic_status": S("TopicStatus")}
    topic_arn: Optional[str] = field(default=None)
    topic_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheCacheSecurityGroupMembership:
    kind: ClassVar[str] = "aws_elasticache_cache_security_group_membership"
    kind_display: ClassVar[str] = "AWS ElastiCache Cache Security Group Membership"
    kind_description: ClassVar[str] = (
        "ElastiCache Cache Security Group Membership allows you to control access to"
        " your ElastiCache resources by managing the cache security group memberships."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cache_security_group_name": S("CacheSecurityGroupName"),
        "status": S("Status"),
    }
    cache_security_group_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheCacheParameterGroupStatus:
    kind: ClassVar[str] = "aws_elasticache_cache_parameter_group_status"
    kind_display: ClassVar[str] = "AWS Elasticache Cache Parameter Group Status"
    kind_description: ClassVar[str] = (
        "AWS Elasticache Cache Parameter Group Status represents the current status"
        " of a cache parameter group in AWS Elasticache. It provides information about"
        " the configuration settings that control the behavior of the cache cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cache_parameter_group_name": S("CacheParameterGroupName"),
        "parameter_apply_status": S("ParameterApplyStatus"),
        "cache_node_ids_to_reboot": S("CacheNodeIdsToReboot", default=[]),
    }
    cache_parameter_group_name: Optional[str] = field(default=None)
    parameter_apply_status: Optional[str] = field(default=None)
    cache_node_ids_to_reboot: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsElastiCacheCacheNode:
    kind: ClassVar[str] = "aws_elasticache_cache_node"
    kind_display: ClassVar[str] = "AWS ElastiCache Cache Node"
    kind_description: ClassVar[str] = (
        "ElastiCache Cache Nodes are the compute resources in AWS ElastiCache used"
        " for running an in-memory caching system, such as Redis or Memcached, to"
        " improve application performance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cache_node_id": S("CacheNodeId"),
        "cache_node_status": S("CacheNodeStatus"),
        "cache_node_create_time": S("CacheNodeCreateTime"),
        "endpoint": S("Endpoint") >> Bend(AwsElastiCacheEndpoint.mapping),
        "parameter_group_status": S("ParameterGroupStatus"),
        "source_cache_node_id": S("SourceCacheNodeId"),
        "customer_availability_zone": S("CustomerAvailabilityZone"),
        "customer_outpost_arn": S("CustomerOutpostArn"),
    }
    cache_node_id: Optional[str] = field(default=None)
    cache_node_status: Optional[str] = field(default=None)
    cache_node_create_time: Optional[datetime] = field(default=None)
    endpoint: Optional[AwsElastiCacheEndpoint] = field(default=None)
    parameter_group_status: Optional[str] = field(default=None)
    source_cache_node_id: Optional[str] = field(default=None)
    customer_availability_zone: Optional[str] = field(default=None)
    customer_outpost_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheSecurityGroupMembership:
    kind: ClassVar[str] = "aws_elasticache_security_group_membership"
    kind_display: ClassVar[str] = "AWS ElastiCache Security Group Membership"
    kind_description: ClassVar[str] = (
        "The AWS ElastiCache Security Group Membership manages an ElastiCache cluster's access permissions"
        " by linking it with a security group to control network traffic to and from the cache nodes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"security_group_id": S("SecurityGroupId"), "status": S("Status")}
    security_group_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheLogDeliveryConfiguration:
    kind: ClassVar[str] = "aws_elasticache_log_delivery_configuration"
    kind_display: ClassVar[str] = "AWS ElastiCache Log Delivery Configuration"
    kind_description: ClassVar[str] = (
        "The AWS ElastiCache Log Delivery Configuration controls the export and formatting of logs"
        " from ElastiCache to designated AWS services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "log_type": S("LogType"),
        "destination_type": S("DestinationType"),
        "destination_details": S("DestinationDetails") >> Bend(AwsElastiCacheDestinationDetails.mapping),
        "log_format": S("LogFormat"),
        "status": S("Status"),
        "message": S("Message"),
    }
    log_type: Optional[str] = field(default=None)
    destination_type: Optional[str] = field(default=None)
    destination_details: Optional[AwsElastiCacheDestinationDetails] = field(default=None)
    log_format: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheCacheCluster(ElastiCacheTaggable, AwsResource):
    kind: ClassVar[str] = "aws_elasticache_cache_cluster"
    kind_display: ClassVar[str] = "AWS ElastiCache Cache Cluster"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/elasticache/home?region={region}#/{Engine}/{name}", "arn_tpl": "arn:{partition}:elasticache:{region}:{account}:cache-cluster/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "ElastiCache is a web service that makes it easy to set up, manage, and scale"
        " a distributed in-memory cache environment in the cloud. A cache cluster is a"
        " collection of one or more cache nodes that work together to provide a highly"
        " scalable and available cache solution."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_ec2_security_group"],
            "delete": ["aws_ec2_security_group"],
        },
        "successors": {"default": ["aws_sns_topic"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-cache-clusters", "CacheClusters")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("CacheClusterId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("CacheClusterId"),
        "arn": S("ARN"),
        "ctime": S("CacheClusterCreateTime"),
        "cluster_configuration_endpoint": S("ConfigurationEndpoint") >> Bend(AwsElastiCacheEndpoint.mapping),
        "cluster_client_download_landing_page": S("ClientDownloadLandingPage"),
        "cluster_cache_node_type": S("CacheNodeType"),
        "cluster_engine": S("Engine"),
        "cluster_engine_version": S("EngineVersion"),
        "cluster_cache_cluster_status": S("CacheClusterStatus"),
        "cluster_num_cache_nodes": S("NumCacheNodes"),
        "cluster_preferred_availability_zone": S("PreferredAvailabilityZone"),
        "cluster_preferred_outpost_arn": S("PreferredOutpostArn"),
        "cluster_cache_cluster_create_time": S("CacheClusterCreateTime"),
        "cluster_preferred_maintenance_window": S("PreferredMaintenanceWindow"),
        "cluster_pending_modified_values": S("PendingModifiedValues")
        >> Bend(AwsElastiCachePendingModifiedValues.mapping),
        "cluster_notification_configuration": S("NotificationConfiguration")
        >> Bend(AwsElastiCacheNotificationConfiguration.mapping),
        "cluster_cache_security_groups": S("CacheSecurityGroups", default=[])
        >> ForallBend(AwsElastiCacheCacheSecurityGroupMembership.mapping),
        "cluster_cache_parameter_group": S("CacheParameterGroup")
        >> Bend(AwsElastiCacheCacheParameterGroupStatus.mapping),
        "cluster_cache_subnet_group_name": S("CacheSubnetGroupName"),
        "cluster_cache_nodes": S("CacheNodes", default=[]) >> ForallBend(AwsElastiCacheCacheNode.mapping),
        "cluster_auto_minor_version_upgrade": S("AutoMinorVersionUpgrade"),
        "cluster_security_groups": S("SecurityGroups", default=[])
        >> ForallBend(AwsElastiCacheSecurityGroupMembership.mapping),
        "cluster_replication_group_id": S("ReplicationGroupId"),
        "cluster_snapshot_retention_limit": S("SnapshotRetentionLimit"),
        "cluster_snapshot_window": S("SnapshotWindow"),
        "cluster_auth_token_enabled": S("AuthTokenEnabled"),
        "cluster_auth_token_last_modified_date": S("AuthTokenLastModifiedDate"),
        "cluster_transit_encryption_enabled": S("TransitEncryptionEnabled"),
        "cluster_at_rest_encryption_enabled": S("AtRestEncryptionEnabled"),
        "cluster_replication_group_log_delivery_enabled": S("ReplicationGroupLogDeliveryEnabled"),
        "cluster_log_delivery_configurations": S("LogDeliveryConfigurations", default=[])
        >> ForallBend(AwsElastiCacheLogDeliveryConfiguration.mapping),
    }
    cluster_configuration_endpoint: Optional[AwsElastiCacheEndpoint] = field(default=None)
    cluster_client_download_landing_page: Optional[str] = field(default=None)
    cluster_cache_node_type: Optional[str] = field(default=None)
    cluster_engine: Optional[str] = field(default=None)
    cluster_engine_version: Optional[str] = field(default=None)
    cluster_cache_cluster_status: Optional[str] = field(default=None)
    cluster_num_cache_nodes: Optional[int] = field(default=None)
    cluster_preferred_availability_zone: Optional[str] = field(default=None)
    cluster_preferred_outpost_arn: Optional[str] = field(default=None)
    cluster_preferred_maintenance_window: Optional[str] = field(default=None)
    cluster_pending_modified_values: Optional[AwsElastiCachePendingModifiedValues] = field(default=None)
    cluster_notification_configuration: Optional[AwsElastiCacheNotificationConfiguration] = field(default=None)
    cluster_cache_security_groups: List[AwsElastiCacheCacheSecurityGroupMembership] = field(factory=list)
    cluster_cache_parameter_group: Optional[AwsElastiCacheCacheParameterGroupStatus] = field(default=None)
    cluster_cache_subnet_group_name: Optional[str] = field(default=None)
    cluster_cache_nodes: List[AwsElastiCacheCacheNode] = field(factory=list)
    cluster_auto_minor_version_upgrade: Optional[bool] = field(default=None)
    cluster_security_groups: List[AwsElastiCacheSecurityGroupMembership] = field(factory=list)
    cluster_replication_group_id: Optional[str] = field(default=None)
    cluster_snapshot_retention_limit: Optional[int] = field(default=None)
    cluster_snapshot_window: Optional[str] = field(default=None)
    cluster_auth_token_enabled: Optional[bool] = field(default=None)
    cluster_auth_token_last_modified_date: Optional[datetime] = field(default=None)
    cluster_transit_encryption_enabled: Optional[bool] = field(default=None)
    cluster_at_rest_encryption_enabled: Optional[bool] = field(default=None)
    cluster_replication_group_log_delivery_enabled: Optional[bool] = field(default=None)
    cluster_log_delivery_configurations: List[AwsElastiCacheLogDeliveryConfiguration] = field(factory=list)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-cache-cluster", result_name=None, CacheClusterId=self.id
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-cache-cluster")]

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(cls.api_spec.service, "list-tags-for-resource")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(resource: AwsElastiCacheCacheCluster) -> None:
            tags = builder.client.list(
                resource.api_spec.service, "list-tags-for-resource", "TagList", ResourceName=resource.arn
            )
            if tags:
                resource.tags = bend(ToDict(), tags)

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # TODO add edge to outpost when applicable
        for sg in self.cluster_security_groups:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=sg.security_group_id
            )
        if cnc := self.cluster_notification_configuration:
            if cnc.topic_arn:
                builder.add_edge(self, clazz=AwsSnsTopic, arn=cnc.topic_arn)


@define(eq=False, slots=False)
class AwsElastiCacheGlobalReplicationGroupInfo:
    kind: ClassVar[str] = "aws_elasticache_global_replication_group_info"
    kind_display: ClassVar[str] = "AWS ElastiCache Global Replication Group Info"
    kind_description: ClassVar[str] = (
        "ElastiCache Global Replication Group Info provides information about a"
        " global replication group in Amazon ElastiCache, which enables automatic and"
        " fast cross-regional data replication for caching purposes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "global_replication_group_id": S("GlobalReplicationGroupId"),
        "global_replication_group_member_role": S("GlobalReplicationGroupMemberRole"),
    }
    global_replication_group_id: Optional[str] = field(default=None)
    global_replication_group_member_role: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheReshardingStatus:
    kind: ClassVar[str] = "aws_elasticache_resharding_status"
    kind_display: ClassVar[str] = "AWS ElastiCache Resharding Status"
    kind_description: ClassVar[str] = (
        "ElastiCache resharding status provides information about the status of the"
        " data resharding process in AWS ElastiCache, which is a fully managed in-"
        " memory data store service for caching frequently accessed data."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"slot_migration": S("SlotMigration", "ProgressPercentage")}
    slot_migration: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheUserGroupsUpdateStatus:
    kind: ClassVar[str] = "aws_elasticache_user_groups_update_status"
    kind_display: ClassVar[str] = "AWS ElastiCache User Groups Update Status"
    kind_description: ClassVar[str] = (
        "The AWS ElastiCache User Groups Update Status reflects the progress of adding or removing user group"
        " associations to an ElastiCache cluster, helping to manage access rights and permissions for users."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "user_group_ids_to_add": S("UserGroupIdsToAdd", default=[]),
        "user_group_ids_to_remove": S("UserGroupIdsToRemove", default=[]),
    }
    user_group_ids_to_add: List[str] = field(factory=list)
    user_group_ids_to_remove: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsElastiCacheReplicationGroupPendingModifiedValues:
    kind: ClassVar[str] = "aws_elasticache_replication_group_pending_modified_values"
    kind_display: ClassVar[str] = "AWS ElastiCache Replication Group Pending Modified Values"
    kind_description: ClassVar[str] = (
        "ElastiCache Replication Group Pending Modified Values is a feature in AWS"
        " ElastiCache that shows the modified values for a replication group that are"
        " in the process of being applied."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "primary_cluster_id": S("PrimaryClusterId"),
        "automatic_failover_status": S("AutomaticFailoverStatus"),
        "resharding": S("Resharding") >> Bend(AwsElastiCacheReshardingStatus.mapping),
        "auth_token_status": S("AuthTokenStatus"),
        "user_groups": S("UserGroups") >> Bend(AwsElastiCacheUserGroupsUpdateStatus.mapping),
        "log_delivery_configurations": S("LogDeliveryConfigurations", default=[])
        >> ForallBend(AwsElastiCachePendingLogDeliveryConfiguration.mapping),
    }
    primary_cluster_id: Optional[str] = field(default=None)
    automatic_failover_status: Optional[str] = field(default=None)
    resharding: Optional[AwsElastiCacheReshardingStatus] = field(default=None)
    auth_token_status: Optional[str] = field(default=None)
    user_groups: Optional[AwsElastiCacheUserGroupsUpdateStatus] = field(default=None)
    log_delivery_configurations: List[AwsElastiCachePendingLogDeliveryConfiguration] = field(factory=list)


@define(eq=False, slots=False)
class AwsElastiCacheNodeGroupMember:
    kind: ClassVar[str] = "aws_elasticache_node_group_member"
    kind_display: ClassVar[str] = "AWS ElastiCache Node Group Member"
    kind_description: ClassVar[str] = (
        "ElastiCache Node Group Members are individual cache nodes within a node"
        " group in AWS ElastiCache, providing in-memory caching for faster performance"
        " of applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cache_cluster_id": S("CacheClusterId"),
        "cache_node_id": S("CacheNodeId"),
        "read_endpoint": S("ReadEndpoint") >> Bend(AwsElastiCacheEndpoint.mapping),
        "preferred_availability_zone": S("PreferredAvailabilityZone"),
        "preferred_outpost_arn": S("PreferredOutpostArn"),
        "current_role": S("CurrentRole"),
    }
    cache_cluster_id: Optional[str] = field(default=None)
    cache_node_id: Optional[str] = field(default=None)
    read_endpoint: Optional[AwsElastiCacheEndpoint] = field(default=None)
    preferred_availability_zone: Optional[str] = field(default=None)
    preferred_outpost_arn: Optional[str] = field(default=None)
    current_role: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsElastiCacheNodeGroup:
    kind: ClassVar[str] = "aws_elasticache_node_group"
    kind_display: ClassVar[str] = "AWS ElastiCache Node Group"
    kind_description: ClassVar[str] = (
        "ElastiCache Node Group is a feature in AWS ElastiCache that allows you to"
        " scale out horizontally by adding multiple cache nodes to a cache cluster. It"
        " improves performance and provides high availability for caching data in your"
        " applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "node_group_id": S("NodeGroupId"),
        "status": S("Status"),
        "primary_endpoint": S("PrimaryEndpoint") >> Bend(AwsElastiCacheEndpoint.mapping),
        "reader_endpoint": S("ReaderEndpoint") >> Bend(AwsElastiCacheEndpoint.mapping),
        "slots": S("Slots"),
        "node_group_members": S("NodeGroupMembers", default=[]) >> ForallBend(AwsElastiCacheNodeGroupMember.mapping),
    }
    node_group_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    primary_endpoint: Optional[AwsElastiCacheEndpoint] = field(default=None)
    reader_endpoint: Optional[AwsElastiCacheEndpoint] = field(default=None)
    slots: Optional[str] = field(default=None)
    node_group_members: List[AwsElastiCacheNodeGroupMember] = field(factory=list)


@define(eq=False, slots=False)
class AwsElastiCacheReplicationGroup(ElastiCacheTaggable, AwsResource):
    kind: ClassVar[str] = "aws_elasticache_replication_group"
    kind_display: ClassVar[str] = "AWS ElastiCache Replication Group"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:elasticache:{region}:{account}:replication-group/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "ElastiCache Replication Groups in AWS are used to store and retrieve data in"
        " memory to improve the performance of web applications and reduce the load on"
        " databases."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-replication-groups", "ReplicationGroups")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_elasticache_cache_cluster", "aws_kms_key"]},
        "successors": {"default": ["aws_elasticache_cache_cluster", "aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ReplicationGroupId"),
        "name": S("ReplicationGroupId"),
        "arn": S("ARN"),
        "ctime": S("ReplicationGroupCreateTime"),
        "mtime": K(None),
        "atime": K(None),
        "replication_group_description": S("Description"),
        "replication_group_global_replication_group_info": S("GlobalReplicationGroupInfo")
        >> Bend(AwsElastiCacheGlobalReplicationGroupInfo.mapping),
        "replication_group_status": S("Status"),
        "replication_group_pending_modified_values": S("PendingModifiedValues")
        >> Bend(AwsElastiCacheReplicationGroupPendingModifiedValues.mapping),
        "replication_group_member_clusters": S("MemberClusters", default=[]),
        "replication_group_node_groups": S("NodeGroups", default=[]) >> ForallBend(AwsElastiCacheNodeGroup.mapping),
        "replication_group_snapshotting_cluster_id": S("SnapshottingClusterId"),
        "replication_group_automatic_failover": S("AutomaticFailover"),
        "replication_group_multi_az": S("MultiAZ"),
        "replication_group_configuration_endpoint": S("ConfigurationEndpoint") >> Bend(AwsElastiCacheEndpoint.mapping),
        "replication_group_snapshot_retention_limit": S("SnapshotRetentionLimit"),
        "replication_group_snapshot_window": S("SnapshotWindow"),
        "replication_group_cluster_enabled": S("ClusterEnabled"),
        "replication_group_cache_node_type": S("CacheNodeType"),
        "replication_group_auth_token_enabled": S("AuthTokenEnabled"),
        "replication_group_auth_token_last_modified_date": S("AuthTokenLastModifiedDate"),
        "replication_group_transit_encryption_enabled": S("TransitEncryptionEnabled"),
        "replication_group_at_rest_encryption_enabled": S("AtRestEncryptionEnabled"),
        "replication_group_member_clusters_outpost_arns": S("MemberClustersOutpostArns", default=[]),
        "replication_group_kms_key_id": S("KmsKeyId"),
        "replication_group_arn": S("ARN"),
        "replication_group_user_group_ids": S("UserGroupIds", default=[]),
        "replication_group_log_delivery_configurations": S("LogDeliveryConfigurations", default=[])
        >> ForallBend(AwsElastiCacheLogDeliveryConfiguration.mapping),
        "replication_group_data_tiering": S("DataTiering"),
    }
    replication_group_description: Optional[str] = field(default=None)
    replication_group_global_replication_group_info: Optional[AwsElastiCacheGlobalReplicationGroupInfo] = field(
        default=None
    )
    replication_group_status: Optional[str] = field(default=None)
    replication_group_pending_modified_values: Optional[AwsElastiCacheReplicationGroupPendingModifiedValues] = field(
        default=None
    )
    replication_group_member_clusters: List[str] = field(factory=list)
    replication_group_node_groups: List[AwsElastiCacheNodeGroup] = field(factory=list)
    replication_group_snapshotting_cluster_id: Optional[str] = field(default=None)
    replication_group_automatic_failover: Optional[str] = field(default=None)
    replication_group_multi_az: Optional[str] = field(default=None)
    replication_group_configuration_endpoint: Optional[AwsElastiCacheEndpoint] = field(default=None)
    replication_group_snapshot_retention_limit: Optional[int] = field(default=None)
    replication_group_snapshot_window: Optional[str] = field(default=None)
    replication_group_cluster_enabled: Optional[bool] = field(default=None)
    replication_group_cache_node_type: Optional[str] = field(default=None)
    replication_group_auth_token_enabled: Optional[bool] = field(default=None)
    replication_group_auth_token_last_modified_date: Optional[datetime] = field(default=None)
    replication_group_transit_encryption_enabled: Optional[bool] = field(default=None)
    replication_group_at_rest_encryption_enabled: Optional[bool] = field(default=None)
    replication_group_member_clusters_outpost_arns: List[str] = field(factory=list)
    replication_group_kms_key_id: Optional[str] = field(default=None)
    replication_group_arn: Optional[str] = field(default=None)
    replication_group_user_group_ids: List[str] = field(factory=list)
    replication_group_log_delivery_configurations: List[AwsElastiCacheLogDeliveryConfiguration] = field(factory=list)
    replication_group_data_tiering: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(cls.api_spec.service, "list-tags-for-resource")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(resource: AwsElastiCacheReplicationGroup) -> None:
            tags = builder.client.list(
                resource.api_spec.service, "list-tags-for-resource", "TagList", ResourceName=resource.arn
            )
            if tags:
                resource.tags = bend(ToDict(), tags)

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for cluster_name in self.replication_group_member_clusters:
            builder.dependant_node(
                self,
                clazz=AwsElastiCacheCacheCluster,
                name=cluster_name,
            )
        if self.replication_group_kms_key_id:
            builder.dependant_node(self, clazz=AwsKmsKey, id=self.replication_group_kms_key_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-replication-group",
            result_name=None,
            ReplicationGroupId=self.id,
            RetainPrimaryCluster=False,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-replication-group")]


resources: List[Type[AwsResource]] = [AwsElastiCacheReplicationGroup, AwsElastiCacheCacheCluster]
