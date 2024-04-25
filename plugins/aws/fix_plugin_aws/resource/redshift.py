from typing import ClassVar, Dict, Optional, List, Any, Type

from attrs import define, field
from datetime import datetime

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder, parse_json
from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchMetricData,
    AwsCloudwatchQuery,
    update_resource_metrics,
)
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.ec2 import AwsEc2Vpc, AwsEc2SecurityGroup, AwsEc2Subnet
from fix_plugin_aws.resource.iam import AwsIamRole
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.utils import MetricNormalization, ToDict
from fixlib.baseresources import MetricName, MetricUnit, ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend, K
from fixlib.types import Json

service_name = "redshift"


@define(eq=False, slots=False)
class AwsRedshiftNetworkInterface:
    kind: ClassVar[str] = "aws_redshift_network_interface"
    kind_display: ClassVar[str] = "AWS Redshift Network Interface"
    kind_description: ClassVar[str] = (
        "Redshift Network Interface is a network interface attached to an Amazon"
        " Redshift cluster, providing connectivity to the cluster from other resources"
        " in the same VPC."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_interface_id": S("NetworkInterfaceId"),
        "subnet_id": S("SubnetId"),
        "private_ip_address": S("PrivateIpAddress"),
        "availability_zone": S("AvailabilityZone"),
    }
    network_interface_id: Optional[str] = field(default=None)
    subnet_id: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)
    availability_zone: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftVpcEndpoint:
    kind: ClassVar[str] = "aws_redshift_vpc_endpoint"
    kind_display: ClassVar[str] = "AWS Redshift VPC Endpoint"
    kind_description: ClassVar[str] = (
        "Redshift VPC Endpoint is a secure and private connection between Amazon"
        " Redshift and an Amazon Virtual Private Cloud (VPC). It allows data to be"
        " transferred between the VPC and Redshift cluster without going through the"
        " internet."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "vpc_endpoint_id": S("VpcEndpointId"),
        "vpc_id": S("VpcId"),
        "network_interfaces": S("NetworkInterfaces", default=[]) >> ForallBend(AwsRedshiftNetworkInterface.mapping),
    }
    vpc_endpoint_id: Optional[str] = field(default=None)
    vpc_id: Optional[str] = field(default=None)
    network_interfaces: List[AwsRedshiftNetworkInterface] = field(factory=list)


@define(eq=False, slots=False)
class AwsRedshiftEndpoint:
    kind: ClassVar[str] = "aws_redshift_endpoint"
    kind_display: ClassVar[str] = "AWS Redshift Endpoint"
    kind_description: ClassVar[str] = (
        "An AWS Redshift Endpoint is the unique network address for connecting to an"
        " Amazon Redshift cluster, allowing users to run queries and perform data"
        " analysis on large datasets."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "address": S("Address"),
        "port": S("Port"),
        "vpc_endpoints": S("VpcEndpoints", default=[]) >> ForallBend(AwsRedshiftVpcEndpoint.mapping),
    }
    address: Optional[str] = field(default=None)
    port: Optional[int] = field(default=None)
    vpc_endpoints: List[AwsRedshiftVpcEndpoint] = field(factory=list)


@define(eq=False, slots=False)
class AwsRedshiftClusterSecurityGroupMembership:
    kind: ClassVar[str] = "aws_redshift_cluster_security_group_membership"
    kind_display: ClassVar[str] = "AWS Redshift Cluster Security Group Membership"
    kind_description: ClassVar[str] = (
        "Redshift Cluster Security Group Membership allows you to manage the security"
        " group membership for an Amazon Redshift cluster. Security groups control"
        " inbound and outbound traffic to your cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_security_group_name": S("ClusterSecurityGroupName"),
        "status": S("Status"),
    }
    cluster_security_group_name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftVpcSecurityGroupMembership:
    kind: ClassVar[str] = "aws_redshift_vpc_security_group_membership"
    kind_display: ClassVar[str] = "AWS Redshift VPC Security Group Membership"
    kind_description: ClassVar[str] = (
        "Redshift VPC Security Group Membership is a feature in Amazon Redshift that"
        " allows you to associate Redshift clusters with Amazon Virtual Private Cloud"
        " (VPC) security groups for enhanced network security."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"vpc_security_group_id": S("VpcSecurityGroupId"), "status": S("Status")}
    vpc_security_group_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftClusterParameterStatus:
    kind: ClassVar[str] = "aws_redshift_cluster_parameter_status"
    kind_display: ClassVar[str] = "AWS Redshift Cluster Parameter Status"
    kind_description: ClassVar[str] = (
        "AWS Redshift Cluster Parameter Status provides information about the status"
        " and configuration of parameters for an Amazon Redshift cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "parameter_name": S("ParameterName"),
        "parameter_apply_status": S("ParameterApplyStatus"),
        "parameter_apply_error_description": S("ParameterApplyErrorDescription"),
    }
    parameter_name: Optional[str] = field(default=None)
    parameter_apply_status: Optional[str] = field(default=None)
    parameter_apply_error_description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftClusterParameterGroupStatus:
    kind: ClassVar[str] = "aws_redshift_cluster_parameter_group_status"
    kind_display: ClassVar[str] = "AWS Redshift Cluster Parameter Group Status"
    kind_description: ClassVar[str] = (
        "Redshift Cluster Parameter Group Status provides information about the"
        " status of a parameter group in Amazon Redshift, which is used to manage the"
        " configuration settings for a Redshift cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "parameter_group_name": S("ParameterGroupName"),
        "parameter_apply_status": S("ParameterApplyStatus"),
        "cluster_parameter_status_list": S("ClusterParameterStatusList", default=[])
        >> ForallBend(AwsRedshiftClusterParameterStatus.mapping),
    }
    parameter_group_name: Optional[str] = field(default=None)
    parameter_apply_status: Optional[str] = field(default=None)
    cluster_parameter_status_list: List[AwsRedshiftClusterParameterStatus] = field(factory=list)


@define(eq=False, slots=False)
class AwsRedshiftPendingModifiedValues:
    kind: ClassVar[str] = "aws_redshift_pending_modified_values"
    kind_display: ClassVar[str] = "AWS Redshift Pending Modified Values"
    kind_description: ClassVar[str] = (
        "Redshift Pending Modified Values represents the configuration changes that"
        " are currently pending for an Amazon Redshift cluster."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "master_user_password": S("MasterUserPassword"),
        "node_type": S("NodeType"),
        "number_of_nodes": S("NumberOfNodes"),
        "cluster_type": S("ClusterType"),
        "cluster_version": S("ClusterVersion"),
        "automated_snapshot_retention_period": S("AutomatedSnapshotRetentionPeriod"),
        "cluster_identifier": S("ClusterIdentifier"),
        "publicly_accessible": S("PubliclyAccessible"),
        "enhanced_vpc_routing": S("EnhancedVpcRouting"),
        "maintenance_track_name": S("MaintenanceTrackName"),
        "encryption_type": S("EncryptionType"),
    }
    master_user_password: Optional[str] = field(default=None)
    node_type: Optional[str] = field(default=None)
    number_of_nodes: Optional[int] = field(default=None)
    cluster_type: Optional[str] = field(default=None)
    cluster_version: Optional[str] = field(default=None)
    automated_snapshot_retention_period: Optional[int] = field(default=None)
    cluster_identifier: Optional[str] = field(default=None)
    publicly_accessible: Optional[bool] = field(default=None)
    enhanced_vpc_routing: Optional[bool] = field(default=None)
    maintenance_track_name: Optional[str] = field(default=None)
    encryption_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftRestoreStatus:
    kind: ClassVar[str] = "aws_redshift_restore_status"
    kind_display: ClassVar[str] = "AWS Redshift Restore Status"
    kind_description: ClassVar[str] = (
        "Redshift Restore Status refers to the current status of a restore operation"
        " in Amazon Redshift, which is a fully managed data warehouse service in the"
        " cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("Status"),
        "current_restore_rate_in_mega_bytes_per_second": S("CurrentRestoreRateInMegaBytesPerSecond"),
        "snapshot_size_in_mega_bytes": S("SnapshotSizeInMegaBytes"),
        "progress_in_mega_bytes": S("ProgressInMegaBytes"),
        "elapsed_time_in_seconds": S("ElapsedTimeInSeconds"),
        "estimated_time_to_completion_in_seconds": S("EstimatedTimeToCompletionInSeconds"),
    }
    status: Optional[str] = field(default=None)
    current_restore_rate_in_mega_bytes_per_second: Optional[float] = field(default=None)
    snapshot_size_in_mega_bytes: Optional[int] = field(default=None)
    progress_in_mega_bytes: Optional[int] = field(default=None)
    elapsed_time_in_seconds: Optional[int] = field(default=None)
    estimated_time_to_completion_in_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftDataTransferProgress:
    kind: ClassVar[str] = "aws_redshift_data_transfer_progress"
    kind_display: ClassVar[str] = "AWS Redshift Data Transfer Progress"
    kind_description: ClassVar[str] = (
        "AWS Redshift Data Transfer Progress provides information about the progress"
        " of data transfer operations in Amazon Redshift, a fully-managed data"
        " warehouse service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("Status"),
        "current_rate_in_mega_bytes_per_second": S("CurrentRateInMegaBytesPerSecond"),
        "total_data_in_mega_bytes": S("TotalDataInMegaBytes"),
        "data_transferred_in_mega_bytes": S("DataTransferredInMegaBytes"),
        "estimated_time_to_completion_in_seconds": S("EstimatedTimeToCompletionInSeconds"),
        "elapsed_time_in_seconds": S("ElapsedTimeInSeconds"),
    }
    status: Optional[str] = field(default=None)
    current_rate_in_mega_bytes_per_second: Optional[float] = field(default=None)
    total_data_in_mega_bytes: Optional[int] = field(default=None)
    data_transferred_in_mega_bytes: Optional[int] = field(default=None)
    estimated_time_to_completion_in_seconds: Optional[int] = field(default=None)
    elapsed_time_in_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftHsmStatus:
    kind: ClassVar[str] = "aws_redshift_hsm_status"
    kind_display: ClassVar[str] = "AWS Redshift HSM Status"
    kind_description: ClassVar[str] = (
        "The AWS Redshift HSM Status provides information about the status of the"
        " Hardware Security Module (HSM) used to encrypt data in Amazon Redshift."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hsm_client_certificate_identifier": S("HsmClientCertificateIdentifier"),
        "hsm_configuration_identifier": S("HsmConfigurationIdentifier"),
        "status": S("Status"),
    }
    hsm_client_certificate_identifier: Optional[str] = field(default=None)
    hsm_configuration_identifier: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftClusterSnapshotCopyStatus:
    kind: ClassVar[str] = "aws_redshift_cluster_snapshot_copy_status"
    kind_display: ClassVar[str] = "AWS Redshift Cluster Snapshot Copy Status"
    kind_description: ClassVar[str] = "The status of the copy operation for a snapshot of an Amazon Redshift cluster."
    mapping: ClassVar[Dict[str, Bender]] = {
        "destination_region": S("DestinationRegion"),
        "retention_period": S("RetentionPeriod"),
        "manual_snapshot_retention_period": S("ManualSnapshotRetentionPeriod"),
        "snapshot_copy_grant_name": S("SnapshotCopyGrantName"),
    }
    destination_region: Optional[str] = field(default=None)
    retention_period: Optional[int] = field(default=None)
    manual_snapshot_retention_period: Optional[int] = field(default=None)
    snapshot_copy_grant_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftClusterNode:
    kind: ClassVar[str] = "aws_redshift_cluster_node"
    kind_display: ClassVar[str] = "AWS Redshift Cluster Node"
    kind_description: ClassVar[str] = (
        "Redshift Cluster Node is a compute resource within an Amazon Redshift"
        " cluster that runs the database queries and stores the data in Redshift data"
        " warehouse."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "node_role": S("NodeRole"),
        "private_ip_address": S("PrivateIPAddress"),
        "public_ip_address": S("PublicIPAddress"),
    }
    node_role: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)
    public_ip_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftElasticIpStatus:
    kind: ClassVar[str] = "aws_redshift_elastic_ip_status"
    kind_display: ClassVar[str] = "AWS Redshift Elastic IP Status"
    kind_description: ClassVar[str] = "The status of an Elastic IP assigned to an Amazon Redshift cluster."
    mapping: ClassVar[Dict[str, Bender]] = {"elastic_ip": S("ElasticIp"), "status": S("Status")}
    elastic_ip: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftClusterIamRole:
    kind: ClassVar[str] = "aws_redshift_cluster_iam_role"
    kind_display: ClassVar[str] = "AWS Redshift Cluster IAM Role"
    kind_description: ClassVar[str] = (
        "An IAM role that is used to grant permissions to an Amazon Redshift cluster to access other AWS services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"iam_role_arn": S("IamRoleArn"), "apply_status": S("ApplyStatus")}
    iam_role_arn: Optional[str] = field(default=None)
    apply_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftDeferredMaintenanceWindow:
    kind: ClassVar[str] = "aws_redshift_deferred_maintenance_window"
    kind_display: ClassVar[str] = "AWS Redshift Deferred Maintenance Window"
    kind_description: ClassVar[str] = (
        "Deferred Maintenance Window is a feature in AWS Redshift that allows users"
        " to postpone maintenance activities for their Redshift clusters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "defer_maintenance_identifier": S("DeferMaintenanceIdentifier"),
        "defer_maintenance_start_time": S("DeferMaintenanceStartTime"),
        "defer_maintenance_end_time": S("DeferMaintenanceEndTime"),
    }
    defer_maintenance_identifier: Optional[str] = field(default=None)
    defer_maintenance_start_time: Optional[datetime] = field(default=None)
    defer_maintenance_end_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftResizeInfo:
    kind: ClassVar[str] = "aws_redshift_resize_info"
    kind_display: ClassVar[str] = "AWS Redshift Resize Info"
    kind_description: ClassVar[str] = (
        "Redshift Resize Info provides information about the resizing process of an"
        " AWS Redshift cluster, which allows users to easily scale their data"
        " warehouse to handle larger workloads."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "resize_type": S("ResizeType"),
        "allow_cancel_resize": S("AllowCancelResize"),
    }
    resize_type: Optional[str] = field(default=None)
    allow_cancel_resize: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftAquaConfiguration:
    kind: ClassVar[str] = "aws_redshift_aqua_configuration"
    kind_display: ClassVar[str] = "AWS Redshift Aqua Configuration"
    kind_description: ClassVar[str] = (
        "The AWS Redshift Aqua Configuration relates to the status and management settings of AQUA"
        " (Advanced Query Accelerator), which enhances the performance of certain types of queries in Amazon Redshift."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "aqua_status": S("AquaStatus"),
        "aqua_configuration_status": S("AquaConfigurationStatus"),
    }
    aqua_status: Optional[str] = field(default=None)
    aqua_configuration_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftReservedNodeExchangeStatus:
    kind: ClassVar[str] = "aws_redshift_reserved_node_exchange_status"
    kind_display: ClassVar[str] = "AWS Redshift Reserved Node Exchange Status"
    kind_description: ClassVar[str] = (
        "Reserved Node Exchange Status provides information about the status of a"
        " reserved node exchange in Amazon Redshift, a fully managed data warehouse"
        " service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "reserved_node_exchange_request_id": S("ReservedNodeExchangeRequestId"),
        "status": S("Status"),
        "request_time": S("RequestTime"),
        "source_reserved_node_id": S("SourceReservedNodeId"),
        "source_reserved_node_type": S("SourceReservedNodeType"),
        "source_reserved_node_count": S("SourceReservedNodeCount"),
        "target_reserved_node_offering_id": S("TargetReservedNodeOfferingId"),
        "target_reserved_node_type": S("TargetReservedNodeType"),
        "target_reserved_node_count": S("TargetReservedNodeCount"),
    }
    reserved_node_exchange_request_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    request_time: Optional[datetime] = field(default=None)
    source_reserved_node_id: Optional[str] = field(default=None)
    source_reserved_node_type: Optional[str] = field(default=None)
    source_reserved_node_count: Optional[int] = field(default=None)
    target_reserved_node_offering_id: Optional[str] = field(default=None)
    target_reserved_node_type: Optional[str] = field(default=None)
    target_reserved_node_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsRedshiftLoggingStatus:
    kind: ClassVar[str] = "aws_redshift_logging_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "logging_enabled": S("LoggingEnabled"),
        "bucket_name": S("BucketName"),
        "s3_key_prefix": S("S3KeyPrefix"),
        "last_successful_delivery_time": S("LastSuccessfulDeliveryTime"),
        "last_failure_time": S("LastFailureTime"),
        "last_failure_message": S("LastFailureMessage"),
        "log_destination_type": S("LogDestinationType"),
        "log_exports": S("LogExports", default=[]),
    }
    logging_enabled: Optional[bool] = field(default=None, metadata={"description": "true if logging is on, false if logging is off."})  # fmt: skip
    bucket_name: Optional[str] = field(default=None, metadata={"description": "The name of the S3 bucket where the log files are stored."})  # fmt: skip
    s3_key_prefix: Optional[str] = field(default=None, metadata={"description": "The prefix applied to the log file names."})  # fmt: skip
    last_successful_delivery_time: Optional[datetime] = field(default=None, metadata={"description": "The last time that logs were delivered."})  # fmt: skip
    last_failure_time: Optional[datetime] = field(default=None, metadata={"description": "The last time when logs failed to be delivered."})  # fmt: skip
    last_failure_message: Optional[str] = field(default=None, metadata={"description": "The message indicating that logs failed to be delivered."})  # fmt: skip
    log_destination_type: Optional[str] = field(default=None, metadata={"description": "The log destination type. An enum with possible values of s3 and cloudwatch."})  # fmt: skip
    log_exports: Optional[List[str]] = field(factory=list, metadata={"description": "The collection of exported log types. Possible values are connectionlog, useractivitylog, and userlog."})  # fmt: skip


@define(eq=False, slots=False)
class AwsRedshiftCluster(AwsResource):
    kind: ClassVar[str] = "aws_redshift_cluster"
    kind_display: ClassVar[str] = "AWS Redshift Cluster"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:redshift:{region}:{account}:cluster/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "Redshift Cluster is a fully managed, petabyte-scale data warehouse service provided by AWS."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-clusters", "Clusters")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_vpc", "aws_ec2_security_group", "aws_iam_role", "aws_ec2_subnet"],
            "delete": ["aws_kms_key", "aws_vpc", "aws_ec2_security_group", "aws_iam_role", "aws_ec2_subnet"],
        },
        "successors": {
            "default": ["aws_kms_key"],
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ClusterIdentifier"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("ClusterIdentifier"),
        "ctime": S("ClusterCreateTime"),
        "mtime": K(None),
        "atime": K(None),
        "redshift_node_type": S("NodeType"),
        "redshift_cluster_status": S("ClusterStatus"),
        "redshift_cluster_availability_status": S("ClusterAvailabilityStatus"),
        "redshift_modify_status": S("ModifyStatus"),
        "redshift_master_username": S("MasterUsername"),
        "redshift_db_name": S("DBName"),
        "redshift_endpoint": S("Endpoint") >> Bend(AwsRedshiftEndpoint.mapping),
        "redshift_automated_snapshot_retention_period": S("AutomatedSnapshotRetentionPeriod"),
        "redshift_manual_snapshot_retention_period": S("ManualSnapshotRetentionPeriod"),
        "redshift_cluster_security_groups": S("ClusterSecurityGroups", default=[])
        >> ForallBend(AwsRedshiftClusterSecurityGroupMembership.mapping),
        "redshift_vpc_security_groups": S("VpcSecurityGroups", default=[])
        >> ForallBend(AwsRedshiftVpcSecurityGroupMembership.mapping),
        "redshift_cluster_parameter_groups": S("ClusterParameterGroups", default=[])
        >> ForallBend(AwsRedshiftClusterParameterGroupStatus.mapping),
        "redshift_cluster_subnet_group_name": S("ClusterSubnetGroupName"),
        "redshift_vpc_id": S("VpcId"),
        "redshift_availability_zone": S("AvailabilityZone"),
        "redshift_preferred_maintenance_window": S("PreferredMaintenanceWindow"),
        "redshift_pending_modified_values": S("PendingModifiedValues")
        >> Bend(AwsRedshiftPendingModifiedValues.mapping),
        "redshift_cluster_version": S("ClusterVersion"),
        "redshift_allow_version_upgrade": S("AllowVersionUpgrade"),
        "redshift_number_of_nodes": S("NumberOfNodes"),
        "redshift_publicly_accessible": S("PubliclyAccessible"),
        "redshift_encrypted": S("Encrypted"),
        "redshift_restore_status": S("RestoreStatus") >> Bend(AwsRedshiftRestoreStatus.mapping),
        "redshift_data_transfer_progress": S("DataTransferProgress") >> Bend(AwsRedshiftDataTransferProgress.mapping),
        "redshift_hsm_status": S("HsmStatus") >> Bend(AwsRedshiftHsmStatus.mapping),
        "redshift_cluster_snapshot_copy_status": S("ClusterSnapshotCopyStatus")
        >> Bend(AwsRedshiftClusterSnapshotCopyStatus.mapping),
        "redshift_cluster_public_key": S("ClusterPublicKey"),
        "redshift_cluster_nodes": S("ClusterNodes", default=[]) >> ForallBend(AwsRedshiftClusterNode.mapping),
        "redshift_elastic_ip_status": S("ElasticIpStatus") >> Bend(AwsRedshiftElasticIpStatus.mapping),
        "redshift_cluster_revision_number": S("ClusterRevisionNumber"),
        "redshift_kms_key_id": S("KmsKeyId"),
        "redshift_enhanced_vpc_routing": S("EnhancedVpcRouting"),
        "redshift_iam_roles": S("IamRoles", default=[]) >> ForallBend(AwsRedshiftClusterIamRole.mapping),
        "redshift_pending_actions": S("PendingActions", default=[]),
        "redshift_maintenance_track_name": S("MaintenanceTrackName"),
        "redshift_elastic_resize_number_of_node_options": S("ElasticResizeNumberOfNodeOptions"),
        "redshift_deferred_maintenance_windows": S("DeferredMaintenanceWindows", default=[])
        >> ForallBend(AwsRedshiftDeferredMaintenanceWindow.mapping),
        "redshift_snapshot_schedule_identifier": S("SnapshotScheduleIdentifier"),
        "redshift_snapshot_schedule_state": S("SnapshotScheduleState"),
        "redshift_expected_next_snapshot_schedule_time": S("ExpectedNextSnapshotScheduleTime"),
        "redshift_expected_next_snapshot_schedule_time_status": S("ExpectedNextSnapshotScheduleTimeStatus"),
        "redshift_next_maintenance_window_start_time": S("NextMaintenanceWindowStartTime"),
        "redshift_resize_info": S("ResizeInfo") >> Bend(AwsRedshiftResizeInfo.mapping),
        "redshift_availability_zone_relocation_status": S("AvailabilityZoneRelocationStatus"),
        "redshift_cluster_namespace_arn": S("ClusterNamespaceArn"),
        "redshift_total_storage_capacity_in_mega_bytes": S("TotalStorageCapacityInMegaBytes"),
        "redshift_aqua_configuration": S("AquaConfiguration") >> Bend(AwsRedshiftAquaConfiguration.mapping),
        "redshift_default_iam_role_arn": S("DefaultIamRoleArn"),
        "redshift_reserved_node_exchange_status": S("ReservedNodeExchangeStatus")
        >> Bend(AwsRedshiftReservedNodeExchangeStatus.mapping),
    }
    redshift_node_type: Optional[str] = field(default=None)
    redshift_cluster_status: Optional[str] = field(default=None)
    redshift_cluster_availability_status: Optional[str] = field(default=None)
    redshift_modify_status: Optional[str] = field(default=None)
    redshift_master_username: Optional[str] = field(default=None)
    redshift_db_name: Optional[str] = field(default=None)
    redshift_endpoint: Optional[AwsRedshiftEndpoint] = field(default=None)
    redshift_automated_snapshot_retention_period: Optional[int] = field(default=None)
    redshift_manual_snapshot_retention_period: Optional[int] = field(default=None)
    redshift_cluster_security_groups: List[AwsRedshiftClusterSecurityGroupMembership] = field(factory=list)
    redshift_vpc_security_groups: List[AwsRedshiftVpcSecurityGroupMembership] = field(factory=list)
    redshift_cluster_parameter_groups: List[AwsRedshiftClusterParameterGroupStatus] = field(factory=list)
    redshift_cluster_subnet_group_name: Optional[str] = field(default=None)
    redshift_vpc_id: Optional[str] = field(default=None)
    redshift_availability_zone: Optional[str] = field(default=None)
    redshift_preferred_maintenance_window: Optional[str] = field(default=None)
    redshift_pending_modified_values: Optional[AwsRedshiftPendingModifiedValues] = field(default=None)
    redshift_cluster_version: Optional[str] = field(default=None)
    redshift_allow_version_upgrade: Optional[bool] = field(default=None)
    redshift_number_of_nodes: Optional[int] = field(default=None)
    redshift_publicly_accessible: Optional[bool] = field(default=None)
    redshift_encrypted: Optional[bool] = field(default=None)
    redshift_restore_status: Optional[AwsRedshiftRestoreStatus] = field(default=None)
    redshift_data_transfer_progress: Optional[AwsRedshiftDataTransferProgress] = field(default=None)
    redshift_hsm_status: Optional[AwsRedshiftHsmStatus] = field(default=None)
    redshift_cluster_snapshot_copy_status: Optional[AwsRedshiftClusterSnapshotCopyStatus] = field(default=None)
    redshift_cluster_public_key: Optional[str] = field(default=None)
    redshift_cluster_nodes: List[AwsRedshiftClusterNode] = field(factory=list)
    redshift_elastic_ip_status: Optional[AwsRedshiftElasticIpStatus] = field(default=None)
    redshift_cluster_revision_number: Optional[str] = field(default=None)
    redshift_kms_key_id: Optional[str] = field(default=None)
    redshift_enhanced_vpc_routing: Optional[bool] = field(default=None)
    redshift_iam_roles: List[AwsRedshiftClusterIamRole] = field(factory=list)
    redshift_pending_actions: List[str] = field(factory=list)
    redshift_maintenance_track_name: Optional[str] = field(default=None)
    redshift_elastic_resize_number_of_node_options: Optional[str] = field(default=None)
    redshift_deferred_maintenance_windows: List[AwsRedshiftDeferredMaintenanceWindow] = field(factory=list)
    redshift_snapshot_schedule_identifier: Optional[str] = field(default=None)
    redshift_snapshot_schedule_state: Optional[str] = field(default=None)
    redshift_expected_next_snapshot_schedule_time: Optional[datetime] = field(default=None)
    redshift_expected_next_snapshot_schedule_time_status: Optional[str] = field(default=None)
    redshift_next_maintenance_window_start_time: Optional[datetime] = field(default=None)
    redshift_resize_info: Optional[AwsRedshiftResizeInfo] = field(default=None)
    redshift_availability_zone_relocation_status: Optional[str] = field(default=None)
    redshift_cluster_namespace_arn: Optional[str] = field(default=None)
    redshift_total_storage_capacity_in_mega_bytes: Optional[int] = field(default=None)
    redshift_aqua_configuration: Optional[AwsRedshiftAquaConfiguration] = field(default=None)
    redshift_default_iam_role_arn: Optional[str] = field(default=None)
    redshift_reserved_node_exchange_status: Optional[AwsRedshiftReservedNodeExchangeStatus] = field(default=None)
    redshift_logging_status: Optional[AwsRedshiftLoggingStatus] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-logging-status")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def fetch_logging_status(rc: AwsRedshiftCluster) -> None:
            with builder.suppress("redshift.describe-logging-status"):
                if raw := builder.client.get(
                    aws_service=service_name,
                    action="describe-logging-status",
                    ClusterIdentifier=rc.id,
                ):
                    rc.redshift_logging_status = parse_json(
                        raw, AwsRedshiftLoggingStatus, builder, AwsRedshiftLoggingStatus.mapping
                    )

        for js in json:
            if cluster := cls.from_api(js, builder):
                cluster.set_arn(builder=builder, resource=f"cluster:{cluster.id}")
                builder.add_node(cluster, js)
                builder.submit_work(service_name, fetch_logging_status, cluster)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        redshifts = {
            redshift.id: redshift
            for redshift in builder.nodes(clazz=AwsRedshiftCluster)
            if redshift.region().id == builder.region.id
        }
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at

        for redshift_id in redshifts:
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="CPUUtilization",
                        namespace="AWS/Redshift",
                        period=delta,
                        ref_id=redshift_id,
                        stat=stat,
                        unit="Percent",
                        ClusterIdentifier=redshift_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="DatabaseConnections",
                        namespace="AWS/Redshift",
                        period=delta,
                        ref_id=redshift_id,
                        stat=stat,
                        unit="Count",
                        ClusterIdentifier=redshift_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/Redshift",
                        period=delta,
                        ref_id=redshift_id,
                        stat=stat,
                        unit="Bytes/Second",
                        ClusterIdentifier=redshift_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for name in ["NetworkReceiveThroughput", "NetworkTransmitThroughput"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/Redshift",
                        period=delta,
                        ref_id=redshift_id,
                        stat=stat,
                        unit="Count/Second",
                        ClusterIdentifier=redshift_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for name in ["ReadIOPS", "WriteIOPS"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/Redshift",
                        period=delta,
                        ref_id=redshift_id,
                        stat="Average",
                        unit="Seconds",
                        ClusterIdentifier=redshift_id,
                    )
                    for name in ["ReadLatency", "WriteLatency"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/Redshift",
                        period=delta,
                        ref_id=redshift_id,
                        stat="Average",
                        unit="Bytes",
                        ClusterIdentifier=redshift_id,
                    )
                    for name in ["ReadThroughput", "WriteThroughput"]
                ]
            )

        metric_normalizers = {
            "CPUUtilization": MetricNormalization(
                metric_name=MetricName.CpuUtilization,
                unit=MetricUnit.Percent,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "DatabaseConnections": MetricNormalization(
                metric_name=MetricName.DatabaseConnections,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "NetworkReceiveThroughput": MetricNormalization(
                metric_name=MetricName.NetworkReceiveThroughput,
                unit=MetricUnit.BytesPerSecond,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "NetworkTransmitThroughput": MetricNormalization(
                metric_name=MetricName.NetworkTransmitThroughput,
                unit=MetricUnit.BytesPerSecond,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ReadIOPS": MetricNormalization(
                metric_name=MetricName.DiskRead,
                unit=MetricUnit.IOPS,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "WriteIOPS": MetricNormalization(
                metric_name=MetricName.DiskWrite,
                unit=MetricUnit.IOPS,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ReadLatency": MetricNormalization(
                metric_name=MetricName.ReadLatency,
                unit=MetricUnit.Seconds,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "WriteLatency": MetricNormalization(
                metric_name=MetricName.WriteLatency,
                unit=MetricUnit.Seconds,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ReadThroughput": MetricNormalization(
                metric_name=MetricName.ReadThroughput,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "WriteThroughput": MetricNormalization(
                metric_name=MetricName.WriteThroughput,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(redshifts, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.redshift_vpc_id:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=self.redshift_vpc_id
            )

        for vsg in self.redshift_vpc_security_groups:
            if vsg.vpc_security_group_id:
                builder.dependant_node(
                    self,
                    reverse=True,
                    delete_same_as_default=True,
                    clazz=AwsEc2SecurityGroup,
                    id=vsg.vpc_security_group_id,
                )

        for role in self.redshift_iam_roles:
            if role.iam_role_arn:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role.iam_role_arn
                )

        if self.redshift_cluster_subnet_group_name:
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=AwsEc2Subnet,
                name=self.redshift_cluster_subnet_group_name,
            )

        if self.redshift_kms_key_id:
            builder.dependant_node(self, clazz=AwsKmsKey, id=self.redshift_kms_key_id)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="create-tags",
            result_name=None,
            ResourceName=self.arn,
            Tags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-tags",
            result_name=None,
            ResourceName=self.arn,
            TagKeys=[key],
        )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-cluster",
            result_name=None,
            ClusterIdentifier=self.id,
            SkipFinalClusterSnapshot=True,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "create-tags"),
            AwsApiSpec(service_name, "delete-tags"),
            AwsApiSpec(service_name, "delete-cluster"),
        ]


resources: List[Type[AwsResource]] = [AwsRedshiftCluster]
