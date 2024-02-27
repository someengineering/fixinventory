from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.resource.ec2 import AwsEc2Instance, AwsEc2LaunchTemplate
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import BaseAutoScalingGroup, ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend
from fixlib.types import Json
from fix_plugin_aws.aws_client import AwsClient

service_name = "autoscaling"


@define(eq=False, slots=False)
class AwsAutoScalingLaunchTemplateSpecification:
    kind: ClassVar[str] = "aws_autoscaling_launch_template_specification"
    kind_display: ClassVar[str] = "AWS Auto Scaling Launch Template Specification"
    kind_description: ClassVar[str] = (
        "An Auto Scaling Launch Template Specification is a configuration template"
        " for launching instances in an Auto Scaling group in Amazon Web Services. It"
        " allows users to define the instance specifications, such as the AMI,"
        " instance type, security groups, and more."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "launch_template_id": S("LaunchTemplateId"),
        "launch_template_name": S("LaunchTemplateName"),
        "version": S("Version"),
    }
    launch_template_id: Optional[str] = field(default=None)
    launch_template_name: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingMinMax:
    kind: ClassVar[str] = "aws_autoscaling_min_max"
    kind_display: ClassVar[str] = "AWS Auto Scaling Min Max"
    kind_description: ClassVar[str] = (
        "AWS Auto Scaling Min Max is a feature of Amazon Web Services that allows"
        " users to set minimum and maximum limits for the number of instances in an"
        " auto scaling group. This helps to ensure that the group scales within"
        " desired bounds based on resource needs."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[int] = field(default=None)
    max: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingInstanceRequirements:
    kind: ClassVar[str] = "aws_autoscaling_instance_requirements"
    kind_display: ClassVar[str] = "AWS Auto Scaling Instance Requirements"
    kind_description: ClassVar[str] = (
        "Auto Scaling Instance Requirements refer to the specific requirements that"
        " need to be fulfilled by instances in an Auto Scaling group, such as"
        " specifying the minimum and maximum number of instances, instance types, and"
        " availability zones."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "v_cpu_count": S("VCpuCount") >> Bend(AwsAutoScalingMinMax.mapping),
        "memory_mi_b": S("MemoryMiB") >> Bend(AwsAutoScalingMinMax.mapping),
        "cpu_manufacturers": S("CpuManufacturers", default=[]),
        "memory_gi_b_per_v_cpu": S("MemoryGiBPerVCpu") >> Bend(AwsAutoScalingMinMax.mapping),
        "excluded_instance_types": S("ExcludedInstanceTypes", default=[]),
        "instance_generations": S("InstanceGenerations", default=[]),
        "spot_max_price_percentage_over_lowest_price": S("SpotMaxPricePercentageOverLowestPrice"),
        "on_demand_max_price_percentage_over_lowest_price": S("OnDemandMaxPricePercentageOverLowestPrice"),
        "bare_metal": S("BareMetal"),
        "burstable_performance": S("BurstablePerformance"),
        "require_hibernate_support": S("RequireHibernateSupport"),
        "network_interface_count": S("NetworkInterfaceCount") >> Bend(AwsAutoScalingMinMax.mapping),
        "local_storage": S("LocalStorage"),
        "local_storage_types": S("LocalStorageTypes", default=[]),
        "total_local_storage_gb": S("TotalLocalStorageGB") >> Bend(AwsAutoScalingMinMax.mapping),
        "baseline_ebs_bandwidth_mbps": S("BaselineEbsBandwidthMbps") >> Bend(AwsAutoScalingMinMax.mapping),
        "accelerator_types": S("AcceleratorTypes", default=[]),
        "accelerator_count": S("AcceleratorCount") >> Bend(AwsAutoScalingMinMax.mapping),
        "accelerator_manufacturers": S("AcceleratorManufacturers", default=[]),
        "accelerator_names": S("AcceleratorNames", default=[]),
        "accelerator_total_memory_mi_b": S("AcceleratorTotalMemoryMiB") >> Bend(AwsAutoScalingMinMax.mapping),
    }
    v_cpu_count: Optional[AwsAutoScalingMinMax] = field(default=None)
    memory_mi_b: Optional[AwsAutoScalingMinMax] = field(default=None)
    cpu_manufacturers: List[str] = field(factory=list)
    memory_gi_b_per_v_cpu: Optional[AwsAutoScalingMinMax] = field(default=None)
    excluded_instance_types: List[str] = field(factory=list)
    instance_generations: List[str] = field(factory=list)
    spot_max_price_percentage_over_lowest_price: Optional[int] = field(default=None)
    on_demand_max_price_percentage_over_lowest_price: Optional[int] = field(default=None)
    bare_metal: Optional[str] = field(default=None)
    burstable_performance: Optional[str] = field(default=None)
    require_hibernate_support: Optional[bool] = field(default=None)
    network_interface_count: Optional[AwsAutoScalingMinMax] = field(default=None)
    local_storage: Optional[str] = field(default=None)
    local_storage_types: List[str] = field(factory=list)
    total_local_storage_gb: Optional[AwsAutoScalingMinMax] = field(default=None)
    baseline_ebs_bandwidth_mbps: Optional[AwsAutoScalingMinMax] = field(default=None)
    accelerator_types: List[str] = field(factory=list)
    accelerator_count: Optional[AwsAutoScalingMinMax] = field(default=None)
    accelerator_manufacturers: List[str] = field(factory=list)
    accelerator_names: List[str] = field(factory=list)
    accelerator_total_memory_mi_b: Optional[AwsAutoScalingMinMax] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingLaunchTemplateOverrides:
    kind: ClassVar[str] = "aws_autoscaling_launch_template_overrides"
    kind_display: ClassVar[str] = "AWS Autoscaling Launch Template Overrides"
    kind_description: ClassVar[str] = (
        "Launch Template Overrides are used in AWS Autoscaling to customize the"
        " configuration of instances launched by an autoscaling group."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_type": S("InstanceType"),
        "weighted_capacity": S("WeightedCapacity"),
        "launch_template_specification": S("LaunchTemplateSpecification")
        >> Bend(AwsAutoScalingLaunchTemplateSpecification.mapping),
        "instance_requirements": S("InstanceRequirements") >> Bend(AwsAutoScalingInstanceRequirements.mapping),
    }
    instance_type: Optional[str] = field(default=None)
    weighted_capacity: Optional[str] = field(default=None)
    launch_template_specification: Optional[AwsAutoScalingLaunchTemplateSpecification] = field(default=None)
    instance_requirements: Optional[AwsAutoScalingInstanceRequirements] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingLaunchTemplate:
    kind: ClassVar[str] = "aws_autoscaling_launch_template"
    kind_display: ClassVar[str] = "AWS Autoscaling Launch Template"
    kind_description: ClassVar[str] = (
        "An Autoscaling Launch Template is a reusable configuration that defines the"
        " launch parameters and instance settings for instances created by Autoscaling"
        " groups in AWS."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "launch_template_specification": S("LaunchTemplateSpecification")
        >> Bend(AwsAutoScalingLaunchTemplateSpecification.mapping),
        "overrides": S("Overrides", default=[]) >> ForallBend(AwsAutoScalingLaunchTemplateOverrides.mapping),
    }
    launch_template_specification: Optional[AwsAutoScalingLaunchTemplateSpecification] = field(default=None)
    overrides: List[AwsAutoScalingLaunchTemplateOverrides] = field(factory=list)


@define(eq=False, slots=False)
class AwsAutoScalingInstancesDistribution:
    kind: ClassVar[str] = "aws_autoscaling_instances_distribution"
    kind_display: ClassVar[str] = "AWS Autoscaling Instances Distribution"
    kind_description: ClassVar[str] = (
        "Autoscaling Instances Distribution in AWS allows for automatic scaling of"
        " EC2 instances based on predefined conditions, ensuring optimized resource"
        " allocation and workload management."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "on_demand_allocation_strategy": S("OnDemandAllocationStrategy"),
        "on_demand_base_capacity": S("OnDemandBaseCapacity"),
        "on_demand_percentage_above_base_capacity": S("OnDemandPercentageAboveBaseCapacity"),
        "spot_allocation_strategy": S("SpotAllocationStrategy"),
        "spot_instance_pools": S("SpotInstancePools"),
        "spot_max_price": S("SpotMaxPrice"),
    }
    on_demand_allocation_strategy: Optional[str] = field(default=None)
    on_demand_base_capacity: Optional[int] = field(default=None)
    on_demand_percentage_above_base_capacity: Optional[int] = field(default=None)
    spot_allocation_strategy: Optional[str] = field(default=None)
    spot_instance_pools: Optional[int] = field(default=None)
    spot_max_price: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingMixedInstancesPolicy:
    kind: ClassVar[str] = "aws_autoscaling_mixed_instances_policy"
    kind_display: ClassVar[str] = "AWS Autoscaling Mixed Instances Policy"
    kind_description: ClassVar[str] = (
        "AWS Autoscaling Mixed Instances Policy allows users to define a policy for"
        " autoscaling groups that specifies a mixture of instance types and purchase"
        " options."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "launch_template": S("LaunchTemplate") >> Bend(AwsAutoScalingLaunchTemplate.mapping),
        "instances_distribution": S("InstancesDistribution") >> Bend(AwsAutoScalingInstancesDistribution.mapping),
    }
    launch_template: Optional[AwsAutoScalingLaunchTemplate] = field(default=None)
    instances_distribution: Optional[AwsAutoScalingInstancesDistribution] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingInstance:
    kind: ClassVar[str] = "aws_autoscaling_instance"
    kind_display: ClassVar[str] = "AWS Auto Scaling Instance"
    kind_description: ClassVar[str] = (
        "Auto Scaling Instances are automatically provisioned and terminated"
        " instances managed by the AWS Auto Scaling service, which helps maintain"
        " application availability and optimize resource usage based on user-defined"
        " scaling policies."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_id": S("InstanceId"),
        "instance_type": S("InstanceType"),
        "availability_zone": S("AvailabilityZone"),
        "lifecycle_state": S("LifecycleState"),
        "health_status": S("HealthStatus"),
        "launch_configuration_name": S("LaunchConfigurationName"),
        "launch_template": S("LaunchTemplate") >> Bend(AwsAutoScalingLaunchTemplateSpecification.mapping),
        "protected_from_scale_in": S("ProtectedFromScaleIn"),
        "weighted_capacity": S("WeightedCapacity"),
    }
    instance_id: Optional[str] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    availability_zone: Optional[str] = field(default=None)
    lifecycle_state: Optional[str] = field(default=None)
    health_status: Optional[str] = field(default=None)
    launch_configuration_name: Optional[str] = field(default=None)
    launch_template: Optional[AwsAutoScalingLaunchTemplateSpecification] = field(default=None)
    protected_from_scale_in: Optional[bool] = field(default=None)
    weighted_capacity: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingSuspendedProcess:
    kind: ClassVar[str] = "aws_autoscaling_suspended_process"
    kind_display: ClassVar[str] = "AWS Autoscaling Suspended Process"
    kind_description: ClassVar[str] = (
        "Autoscaling Suspended Process is a feature in Amazon EC2 Auto Scaling that"
        " allows you to suspend and resume specific scaling processes for your Auto"
        " Scaling group. It allows you to temporarily stop scaling activities for a"
        " specific process, such as launching new instances or terminating instances,"
        " while keeping your existing resources running."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "process_name": S("ProcessName"),
        "suspension_reason": S("SuspensionReason"),
    }
    process_name: Optional[str] = field(default=None)
    suspension_reason: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingEnabledMetric:
    kind: ClassVar[str] = "aws_autoscaling_enabled_metric"
    kind_display: ClassVar[str] = "AWS Auto Scaling Enabled Metric"
    kind_description: ClassVar[str] = (
        "Auto Scaling Enabled Metric is a feature in AWS Auto Scaling that scales"
        " resources based on a specified metric, such as CPU utilization or request"
        " count."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"metric": S("Metric"), "granularity": S("Granularity")}
    metric: Optional[str] = field(default=None)
    granularity: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingWarmPoolConfiguration:
    kind: ClassVar[str] = "aws_autoscaling_warm_pool_configuration"
    kind_display: ClassVar[str] = "AWS Auto Scaling Warm Pool Configuration"
    kind_description: ClassVar[str] = (
        "AWS Auto Scaling Warm Pool Configuration is a feature that allows you to"
        " provision and maintain a pool of pre-warmed instances for faster scaling."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_group_prepared_capacity": S("MaxGroupPreparedCapacity"),
        "min_size": S("MinSize"),
        "pool_state": S("PoolState"),
        "status": S("Status"),
        "instance_reuse_policy": S("InstanceReusePolicy", "ReuseOnScaleIn"),
    }
    max_group_prepared_capacity: Optional[int] = field(default=None)
    min_size: Optional[int] = field(default=None)
    pool_state: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    instance_reuse_policy: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsAutoScalingGroup(AwsResource, BaseAutoScalingGroup):
    kind: ClassVar[str] = "aws_autoscaling_group"
    kind_display: ClassVar[str] = "AWS Autoscaling Group"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/awsautoscaling/home?region={region}#dashboard/{name}", "arn_tpl": "arn:{partition}:autoscaling:{region}:{account}:autoscalinggroup/{name}"}  # fmt: skip

    kind_description: ClassVar[str] = (
        "An AWS Autoscaling Group is a collection of Amazon EC2 instances that are"
        " treated as a logical grouping for the purpose of automatic scaling and"
        " management."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-auto-scaling-groups", "AutoScalingGroups")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_ec2_instance", "aws_ec2_launch_template"]},
        "predecessors": {"delete": ["aws_ec2_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AutoScalingGroupName"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("AutoScalingGroupName"),
        "ctime": S("CreatedTime"),
        "arn": S("AutoScalingGroupARN"),
        "autoscaling_launch_configuration_name": S("LaunchConfigurationName"),
        "autoscaling_launch_template": S("LaunchTemplate") >> Bend(AwsAutoScalingLaunchTemplateSpecification.mapping),
        "autoscaling_mixed_instances_policy": S("MixedInstancesPolicy")
        >> Bend(AwsAutoScalingMixedInstancesPolicy.mapping),
        "min_size": S("MinSize"),
        "max_size": S("MaxSize"),
        "autoscaling_desired_capacity": S("DesiredCapacity"),
        "autoscaling_predicted_capacity": S("PredictedCapacity"),
        "autoscaling_default_cooldown": S("DefaultCooldown"),
        "autoscaling_availability_zones": S("AvailabilityZones", default=[]),
        "autoscaling_load_balancer_names": S("LoadBalancerNames", default=[]),
        "autoscaling_target_group_ar_ns": S("TargetGroupARNs", default=[]),
        "autoscaling_health_check_type": S("HealthCheckType"),
        "autoscaling_health_check_grace_period": S("HealthCheckGracePeriod"),
        "autoscaling_instances": S("Instances", default=[]) >> ForallBend(AwsAutoScalingInstance.mapping),
        "autoscaling_suspended_processes": S("SuspendedProcesses", default=[])
        >> ForallBend(AwsAutoScalingSuspendedProcess.mapping),
        "autoscaling_placement_group": S("PlacementGroup"),
        "autoscaling_vpc_zone_identifier": S("VPCZoneIdentifier"),
        "autoscaling_enabled_metrics": S("EnabledMetrics", default=[])
        >> ForallBend(AwsAutoScalingEnabledMetric.mapping),
        "autoscaling_status": S("Status"),
        "autoscaling_termination_policies": S("TerminationPolicies", default=[]),
        "autoscaling_new_instances_protected_from_scale_in": S("NewInstancesProtectedFromScaleIn"),
        "autoscaling_service_linked_role_arn": S("ServiceLinkedRoleARN"),
        "autoscaling_max_instance_lifetime": S("MaxInstanceLifetime"),
        "autoscaling_capacity_rebalance": S("CapacityRebalance"),
        "autoscaling_warm_pool_configuration": S("WarmPoolConfiguration")
        >> Bend(AwsAutoScalingWarmPoolConfiguration.mapping),
        "autoscaling_warm_pool_size": S("WarmPoolSize"),
        "autoscaling_context": S("Context"),
        "autoscaling_desired_capacity_type": S("DesiredCapacityType"),
        "autoscaling_default_instance_warmup": S("DefaultInstanceWarmup"),
    }
    autoscaling_launch_configuration_name: Optional[str] = field(default=None)
    autoscaling_launch_template: Optional[AwsAutoScalingLaunchTemplateSpecification] = field(default=None)
    autoscaling_mixed_instances_policy: Optional[AwsAutoScalingMixedInstancesPolicy] = field(default=None)
    autoscaling_predicted_capacity: Optional[int] = field(default=None)
    autoscaling_default_cooldown: Optional[int] = field(default=None)
    autoscaling_availability_zones: List[str] = field(factory=list)
    autoscaling_load_balancer_names: List[str] = field(factory=list)
    autoscaling_target_group_ar_ns: List[str] = field(factory=list)
    autoscaling_health_check_type: Optional[str] = field(default=None)
    autoscaling_health_check_grace_period: Optional[int] = field(default=None)
    autoscaling_instances: List[AwsAutoScalingInstance] = field(factory=list)
    autoscaling_suspended_processes: List[AwsAutoScalingSuspendedProcess] = field(factory=list)
    autoscaling_placement_group: Optional[str] = field(default=None)
    autoscaling_vpc_zone_identifier: Optional[str] = field(default=None)
    autoscaling_enabled_metrics: List[AwsAutoScalingEnabledMetric] = field(factory=list)
    autoscaling_status: Optional[str] = field(default=None)
    autoscaling_termination_policies: List[str] = field(factory=list)
    autoscaling_new_instances_protected_from_scale_in: Optional[bool] = field(default=None)
    autoscaling_service_linked_role_arn: Optional[str] = field(default=None)
    autoscaling_max_instance_lifetime: Optional[int] = field(default=None)
    autoscaling_capacity_rebalance: Optional[bool] = field(default=None)
    autoscaling_warm_pool_configuration: Optional[AwsAutoScalingWarmPoolConfiguration] = field(default=None)
    autoscaling_warm_pool_size: Optional[int] = field(default=None)
    autoscaling_context: Optional[str] = field(default=None)
    autoscaling_desired_capacity_type: Optional[str] = field(default=None)
    autoscaling_default_instance_warmup: Optional[int] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for instance in self.autoscaling_instances:
            builder.dependant_node(self, clazz=AwsEc2Instance, id=instance.instance_id)
        if (tpl := self.autoscaling_launch_template) and (tid := tpl.launch_template_id):
            builder.add_edge(self, clazz=AwsEc2LaunchTemplate, id=tid)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name,
            action="create-or-update-tags",
            result_name=None,
            Tags=[
                {
                    "ResourceId": self.name,
                    "ResourceType": "auto-scaling-group",
                    "Key": key,
                    "Value": value,
                    "PropagateAtLaunch": False,
                }
            ],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=service_name,
            action="delete-tags",
            result_name=None,
            Tags=[
                {
                    "ResourceId": self.name,
                    "ResourceType": "auto-scaling-group",
                    "Key": key,
                }
            ],
        )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-auto-scaling-group",
            result_name=None,
            AutoScalingGroupName=self.name,
            ForceDelete=True,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "create-or-update-tags"),
            AwsApiSpec(service_name, "delete-tags"),
            AwsApiSpec(service_name, "delete-auto-scaling-group"),
        ]


resources: List[Type[AwsResource]] = [AwsAutoScalingGroup]
