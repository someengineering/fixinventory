import base64
from functools import partial
import logging
from contextlib import suppress
from datetime import datetime, timedelta
from typing import ClassVar, Dict, Optional, List, Type, Any
import copy

from attrs import define, field
from fix_plugin_aws.aws_client import AwsClient

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec, get_client
from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchQuery,
    AwsCloudwatchMetricData,
    bytes_to_megabits_per_second,
    bytes_to_megabytes_per_second,
    calculate_min_max_avg,
    operations_to_iops,
    update_resource_metrics,
)
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.s3 import AwsS3Bucket
from fix_plugin_aws.resource.iam import AwsIamInstanceProfile
from fix_plugin_aws.utils import ToDict, TagsValue, MetricNormalization
from fixlib.baseresources import (
    BaseInstance,
    EdgeType,
    BaseVolume,
    BaseInstanceType,
    MetricName,
    MetricUnit,
    VolumeStatus,
    InstanceStatus,
    BaseIPAddress,
    BaseNetworkInterface,
    BaseNetwork,
    BaseSubnet,
    BaseSecurityGroup,
    BaseGateway,
    BaseSnapshot,
    BasePeeringConnection,
    BaseEndpoint,
    BaseRoutingTable,
    ModelReference,
)
from fixlib.config import current_config
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend, bend, MapEnum, F, K, StripNones
from fixlib.types import Json


# region InstanceType
from fixlib.utils import utc

log = logging.getLogger("fix.plugins.aws")
service_name = "ec2"


# noinspection PyUnresolvedReferences
class EC2Taggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="create-tags",
                    result_name=None,
                    Resources=[self.id],
                    Tags=[{"Key": key, "Value": value}],
                )
                return True
            return False
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="delete-tags",
                    result_name=None,
                    Resources=[self.id],
                    Tags=[{"Key": key}],
                )
                return True
            return False
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "create-tags"), AwsApiSpec(service_name, "delete-tags")]


@define(eq=False, slots=False)
class AwsEc2ProcessorInfo:
    kind: ClassVar[str] = "aws_ec2_processor_info"
    kind_display: ClassVar[str] = "AWS EC2 Processor Info"
    kind_description: ClassVar[str] = (
        "EC2 Processor Info provides detailed information about the processors used"
        " in Amazon EC2 instances, such as the model, clock speed, and number of"
        " cores."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "supported_architectures": S("SupportedArchitectures", default=[]),
        "sustained_clock_speed_in_ghz": S("SustainedClockSpeedInGhz"),
    }
    supported_architectures: List[str] = field(factory=list)
    sustained_clock_speed_in_ghz: Optional[float] = field(default=None)
    physical_processor: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2VCpuInfo:
    kind: ClassVar[str] = "aws_ec2_v_cpu_info"
    kind_display: ClassVar[str] = "AWS EC2 vCPU Info"
    kind_description: ClassVar[str] = (
        "EC2 vCPU Info provides detailed information about the virtual CPU capabilities of Amazon EC2 instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_v_cpus": S("DefaultVCpus"),
        "default_cores": S("DefaultCores"),
        "default_threads_per_core": S("DefaultThreadsPerCore"),
        "valid_cores": S("ValidCores", default=[]),
        "valid_threads_per_core": S("ValidThreadsPerCore", default=[]),
    }
    default_v_cpus: Optional[int] = field(default=None)
    default_cores: Optional[int] = field(default=None)
    default_threads_per_core: Optional[int] = field(default=None)
    valid_cores: List[int] = field(factory=list)
    valid_threads_per_core: List[int] = field(factory=list)


@define(eq=False, slots=False)
class AwsEc2DiskInfo:
    kind: ClassVar[str] = "aws_ec2_disk_info"
    kind_display: ClassVar[str] = "AWS EC2 Disk Info"
    kind_description: ClassVar[str] = (
        "AWS EC2 Disk Info refers to the details about the storage disk(s) attached to an Amazon EC2 instance,"
        " including volume type, size, IOPS, throughput, and encryption status."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"size_in_gb": S("SizeInGB"), "count": S("Count"), "type": S("Type")}
    size_in_gb: Optional[int] = field(default=None)
    count: Optional[int] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InstanceStorageInfo:
    kind: ClassVar[str] = "aws_ec2_instance_storage_info"
    kind_display: ClassVar[str] = "AWS EC2 Instance Storage Info"
    kind_description: ClassVar[str] = (
        "EC2 Instance Storage Info provides information about the storage"
        " configuration and details of an EC2 instance in Amazon Web Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "total_size_in_gb": S("TotalSizeInGB"),
        "disks": S("Disks", default=[]) >> ForallBend(AwsEc2DiskInfo.mapping),
        "nvme_support": S("NvmeSupport"),
        "encryption_support": S("EncryptionSupport"),
    }
    total_size_in_gb: Optional[int] = field(default=None)
    disks: List[AwsEc2DiskInfo] = field(factory=list)
    nvme_support: Optional[str] = field(default=None)
    encryption_support: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2EbsOptimizedInfo:
    kind: ClassVar[str] = "aws_ec2_ebs_optimized_info"
    kind_display: ClassVar[str] = "AWS EC2 EBS Optimized Info"
    kind_description: ClassVar[str] = (
        "EBS optimization is an Amazon EC2 feature that enables EC2 instances to"
        " fully utilize the IOPS provisioned on an EBS volume."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "baseline_bandwidth_in_mbps": S("BaselineBandwidthInMbps"),
        "baseline_throughput_in_mbps": S("BaselineThroughputInMBps"),
        "baseline_iops": S("BaselineIops"),
        "maximum_bandwidth_in_mbps": S("MaximumBandwidthInMbps"),
        "maximum_throughput_in_mbps": S("MaximumThroughputInMBps"),
        "maximum_iops": S("MaximumIops"),
    }
    baseline_bandwidth_in_mbps: Optional[int] = field(default=None)
    baseline_throughput_in_mbps: Optional[float] = field(default=None)
    baseline_iops: Optional[int] = field(default=None)
    maximum_bandwidth_in_mbps: Optional[int] = field(default=None)
    maximum_throughput_in_mbps: Optional[float] = field(default=None)
    maximum_iops: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2EbsInfo:
    kind: ClassVar[str] = "aws_ec2_ebs_info"
    kind_display: ClassVar[str] = "AWS EC2 EBS Info"
    kind_description: ClassVar[str] = (
        "EBS (Elastic Block Store) is a block storage service provided by AWS. It"
        " provides persistent storage volumes that can be attached to EC2 instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ebs_optimized_support": S("EbsOptimizedSupport"),
        "encryption_support": S("EncryptionSupport"),
        "ebs_optimized_info": S("EbsOptimizedInfo") >> Bend(AwsEc2EbsOptimizedInfo.mapping),
        "nvme_support": S("NvmeSupport"),
    }
    ebs_optimized_support: Optional[str] = field(default=None)
    encryption_support: Optional[str] = field(default=None)
    ebs_optimized_info: Optional[AwsEc2EbsOptimizedInfo] = field(default=None)
    nvme_support: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2NetworkCardInfo:
    kind: ClassVar[str] = "aws_ec2_network_card_info"
    kind_display: ClassVar[str] = "AWS EC2 Network Card Info"
    kind_description: ClassVar[str] = (
        "AWS EC2 Network Card Info refers to the information related to the network"
        " cards associated with EC2 instances in Amazon Web Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_card_index": S("NetworkCardIndex"),
        "network_performance": S("NetworkPerformance"),
        "maximum_network_interfaces": S("MaximumNetworkInterfaces"),
    }
    network_card_index: Optional[int] = field(default=None)
    network_performance: Optional[str] = field(default=None)
    maximum_network_interfaces: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2NetworkInfo:
    kind: ClassVar[str] = "aws_ec2_network_info"
    kind_display: ClassVar[str] = "AWS EC2 Network Info"
    kind_description: ClassVar[str] = (
        "AWS EC2 Network Info provides details on the networking capabilities of an EC2 instance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_performance": S("NetworkPerformance"),
        "maximum_network_interfaces": S("MaximumNetworkInterfaces"),
        "maximum_network_cards": S("MaximumNetworkCards"),
        "default_network_card_index": S("DefaultNetworkCardIndex"),
        "network_cards": S("NetworkCards", default=[]) >> ForallBend(AwsEc2NetworkCardInfo.mapping),
        "ipv4_addresses_per_interface": S("Ipv4AddressesPerInterface"),
        "ipv6_addresses_per_interface": S("Ipv6AddressesPerInterface"),
        "ipv6_supported": S("Ipv6Supported"),
        "ena_support": S("EnaSupport"),
        "efa_supported": S("EfaSupported"),
        "efa_info": S("EfaInfo", "MaximumEfaInterfaces"),
        "encryption_in_transit_supported": S("EncryptionInTransitSupported"),
    }
    network_performance: Optional[str] = field(default=None)
    maximum_network_interfaces: Optional[int] = field(default=None)
    maximum_network_cards: Optional[int] = field(default=None)
    default_network_card_index: Optional[int] = field(default=None)
    network_cards: List[AwsEc2NetworkCardInfo] = field(factory=list)
    ipv4_addresses_per_interface: Optional[int] = field(default=None)
    ipv6_addresses_per_interface: Optional[int] = field(default=None)
    ipv6_supported: Optional[bool] = field(default=None)
    ena_support: Optional[str] = field(default=None)
    efa_supported: Optional[bool] = field(default=None)
    efa_info: Optional[int] = field(default=None)
    encryption_in_transit_supported: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2GpuDeviceInfo:
    kind: ClassVar[str] = "aws_ec2_gpu_device_info"
    kind_display: ClassVar[str] = "AWS EC2 GPU Device Info"
    kind_description: ClassVar[str] = (
        "AWS EC2 GPU Device Info includes specifications such as model, quantity, memory size, and performance"
        " of the GPU devices available on certain Amazon EC2 instances that are designed for graphic-intensive"
        " tasks or machine learning workloads."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "manufacturer": S("Manufacturer"),
        "count": S("Count"),
        "memory_info": S("MemoryInfo", "SizeInMiB"),
    }
    name: Optional[str] = field(default=None)
    manufacturer: Optional[str] = field(default=None)
    count: Optional[int] = field(default=None)
    memory_info: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2GpuInfo:
    kind: ClassVar[str] = "aws_ec2_gpu_info"
    kind_display: ClassVar[str] = "AWS EC2 GPU Info"
    kind_description: ClassVar[str] = (
        "EC2 GPU Info provides detailed information about the Graphics Processing"
        " Units (GPUs) available in Amazon EC2 instances. This includes information"
        " about the GPU type, memory, and performance capabilities."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "gpus": S("Gpus", default=[]) >> ForallBend(AwsEc2GpuDeviceInfo.mapping),
        "total_gpu_memory_in_mi_b": S("TotalGpuMemoryInMiB"),
    }
    gpus: List[AwsEc2GpuDeviceInfo] = field(factory=list)
    total_gpu_memory_in_mi_b: Optional[int] = field(default=None)
    gpu_model: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2FpgaDeviceInfo:
    kind: ClassVar[str] = "aws_ec2_fpga_device_info"
    kind_display: ClassVar[str] = "AWS EC2 FPGA Device Info"
    kind_description: ClassVar[str] = (
        "Provides information about FPGA devices available in EC2 instances. FPGA"
        " devices in EC2 instances provide customizable and programmable hardware"
        " acceleration for various workloads."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "manufacturer": S("Manufacturer"),
        "count": S("Count"),
        "memory_info": S("MemoryInfo", "SizeInMiB"),
    }
    name: Optional[str] = field(default=None)
    manufacturer: Optional[str] = field(default=None)
    count: Optional[int] = field(default=None)
    memory_info: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2FpgaInfo:
    kind: ClassVar[str] = "aws_ec2_fpga_info"
    kind_display: ClassVar[str] = "AWS EC2 FPGA Info"
    kind_description: ClassVar[str] = (
        "FPGAs (Field-Programmable Gate Arrays) in AWS EC2 provide hardware"
        " acceleration capabilities for your applications, enabling you to optimize"
        " performance and efficiency for specific workloads."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "fpgas": S("Fpgas", default=[]) >> ForallBend(AwsEc2FpgaDeviceInfo.mapping),
        "total_fpga_memory_in_mi_b": S("TotalFpgaMemoryInMiB"),
    }
    fpgas: List[AwsEc2FpgaDeviceInfo] = field(factory=list)
    total_fpga_memory_in_mi_b: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2PlacementGroupInfo:
    kind: ClassVar[str] = "aws_ec2_placement_group_info"
    kind_display: ClassVar[str] = "AWS EC2 Placement Group Info"
    kind_description: ClassVar[str] = (
        "EC2 Placement Groups are logical groupings of instances within a single"
        " Availability Zone that enables applications to take advantage of low-latency"
        " network connections between instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"supported_strategies": S("SupportedStrategies", default=[])}
    supported_strategies: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEc2InferenceDeviceInfo:
    kind: ClassVar[str] = "aws_ec2_inference_device_info"
    kind_display: ClassVar[str] = "AWS EC2 Inference Device Info"
    kind_description: ClassVar[str] = (
        "EC2 Inference Device Info provides information about the inference devices"
        " available for EC2 instances. Inference devices are specialized hardware"
        " accelerators that can be used to optimize the performance of machine"
        " learning or deep learning workloads on EC2 instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"count": S("Count"), "name": S("Name"), "manufacturer": S("Manufacturer")}
    count: Optional[int] = field(default=None)
    name: Optional[str] = field(default=None)
    manufacturer: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InferenceAcceleratorInfo:
    kind: ClassVar[str] = "aws_ec2_inference_accelerator_info"
    kind_display: ClassVar[str] = "AWS EC2 Inference Accelerator Info"
    kind_description: ClassVar[str] = (
        "EC2 Inference Accelerator Info provides information about acceleration"
        " options available for Amazon EC2 instances, allowing users to enhance"
        " performance of their machine learning inference workloads."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerators": S("Accelerators", default=[]) >> ForallBend(AwsEc2InferenceDeviceInfo.mapping)
    }
    accelerators: List[AwsEc2InferenceDeviceInfo] = field(factory=list)


@define(eq=False, slots=False)
class AwsEc2InstanceType(AwsResource, BaseInstanceType):
    kind: ClassVar[str] = "aws_ec2_instance_type"
    kind_display: ClassVar[str] = "AWS EC2 Instance Type"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:ec2:{region}:{account}:instance/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS EC2 Instance Type refers to the classification of an EC2 instance based on the resources and"
        " capabilities it offers, such as CPU, memory, storage, and networking capacity, tailored for different"
        " workload requirements and applications."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-instance-types", "InstanceTypes")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_ec2_instance"],
            "delete": [],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("InstanceType"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("InstanceType"),
        "instance_type": S("InstanceType"),
        "instance_cores": S("VCpuInfo", "DefaultVCpus"),
        "instance_memory": S("MemoryInfo", "SizeInMiB") >> F(lambda x: int(x) / 1024),
        "current_generation": S("CurrentGeneration"),
        "free_tier_eligible": S("FreeTierEligible"),
        "supported_usage_classes": S("SupportedUsageClasses", default=[]),
        "supported_root_device_types": S("SupportedRootDeviceTypes", default=[]),
        "supported_virtualization_types": S("SupportedVirtualizationTypes", default=[]),
        "bare_metal": S("BareMetal"),
        "hypervisor": S("Hypervisor"),
        "instance_type_processor_info": S("ProcessorInfo") >> Bend(AwsEc2ProcessorInfo.mapping),
        "instance_type_v_cpu_info": S("VCpuInfo") >> Bend(AwsEc2VCpuInfo.mapping),
        "memory_info": S("MemoryInfo", "SizeInMiB"),
        "instance_storage_supported": S("InstanceStorageSupported"),
        "instance_type_instance_storage_info": S("InstanceStorageInfo") >> Bend(AwsEc2InstanceStorageInfo.mapping),
        "instance_type_ebs_info": S("EbsInfo") >> Bend(AwsEc2EbsInfo.mapping),
        "instance_type_network_info": S("NetworkInfo") >> Bend(AwsEc2NetworkInfo.mapping),
        "instance_type_gpu_info": S("GpuInfo") >> Bend(AwsEc2GpuInfo.mapping),
        "instance_type_fpga_info": S("FpgaInfo") >> Bend(AwsEc2FpgaInfo.mapping),
        "instance_type_placement_group_info": S("PlacementGroupInfo") >> Bend(AwsEc2PlacementGroupInfo.mapping),
        "instance_type_inference_accelerator_info": S("InferenceAcceleratorInfo")
        >> Bend(AwsEc2InferenceAcceleratorInfo.mapping),
        "hibernation_supported": S("HibernationSupported"),
        "burstable_performance_supported": S("BurstablePerformanceSupported"),
        "dedicated_hosts_supported": S("DedicatedHostsSupported"),
        "auto_recovery_supported": S("AutoRecoverySupported"),
        "supported_boot_modes": S("SupportedBootModes", default=[]),
    }
    pretty_name: Optional[str] = field(default=None)
    ecu: Optional[float] = field(default=None)
    current_generation: Optional[bool] = field(default=None)
    free_tier_eligible: Optional[bool] = field(default=None)
    supported_usage_classes: List[str] = field(factory=list)
    supported_root_device_types: List[str] = field(factory=list)
    supported_virtualization_types: List[str] = field(factory=list)
    bare_metal: Optional[bool] = field(default=None)
    hypervisor: Optional[str] = field(default=None)
    instance_type_processor_info: Optional[AwsEc2ProcessorInfo] = field(default=None)
    instance_type_v_cpu_info: Optional[AwsEc2VCpuInfo] = field(default=None)
    memory_info: Optional[int] = field(default=None)
    instance_storage_supported: Optional[bool] = field(default=None)
    instance_type_instance_storage_info: Optional[AwsEc2InstanceStorageInfo] = field(default=None)
    instance_type_ebs_info: Optional[AwsEc2EbsInfo] = field(default=None)
    instance_type_network_info: Optional[AwsEc2NetworkInfo] = field(default=None)
    instance_type_gpu_info: Optional[AwsEc2GpuInfo] = field(default=None)
    instance_type_fpga_info: Optional[AwsEc2FpgaInfo] = field(default=None)
    instance_type_placement_group_info: Optional[AwsEc2PlacementGroupInfo] = field(default=None)
    instance_type_inference_accelerator_info: Optional[AwsEc2InferenceAcceleratorInfo] = field(default=None)
    hibernation_supported: Optional[bool] = field(default=None)
    burstable_performance_supported: Optional[bool] = field(default=None)
    dedicated_hosts_supported: Optional[bool] = field(default=None)
    auto_recovery_supported: Optional[bool] = field(default=None)
    supported_boot_modes: List[str] = field(factory=list)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            if it := AwsEc2InstanceType.from_api(js, builder):
                # only store this information in the builder, not directly in the graph
                # reason: pricing is region-specific - this is enriched in the builder on demand
                # Only "used" instance type will be stored in the graph
                # note: not all instance types are returned in any region.
                # we collect instance types in all regions and make the data unique in the builder
                builder.global_instance_types[it.safe_name] = it


# endregion

# region Volume


@define(eq=False, slots=False)
class AwsEc2VolumeAttachment:
    kind: ClassVar[str] = "aws_ec2_volume_attachment"
    kind_display: ClassVar[str] = "AWS EC2 Volume Attachment"
    kind_description: ClassVar[str] = (
        "AWS EC2 Volume Attachment is a resource that represents the attachment of an"
        " Amazon Elastic Block Store (EBS) volume to an EC2 instance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "attach_time": S("AttachTime"),
        "device": S("Device"),
        "instance_id": S("InstanceId"),
        "state": S("State"),
        "volume_id": S("VolumeId"),
        "delete_on_termination": S("DeleteOnTermination"),
    }
    attach_time: Optional[datetime] = field(default=None)
    device: Optional[str] = field(default=None)
    instance_id: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    volume_id: Optional[str] = field(default=None)
    delete_on_termination: Optional[bool] = field(default=None)


VolumeStatusMapping = {
    "creating": VolumeStatus.BUSY,
    "available": VolumeStatus.AVAILABLE,
    "in-use": VolumeStatus.IN_USE,
    "deleting": VolumeStatus.DELETED,
    "deleted": VolumeStatus.DELETED,
    "error": VolumeStatus.ERROR,
}


@define(eq=False, slots=False)
class AwsEc2Volume(EC2Taggable, AwsResource, BaseVolume):
    kind: ClassVar[str] = "aws_ec2_volume"
    kind_display: ClassVar[str] = "AWS EC2 Volume"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#VolumeDetails:volumeId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:volume/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "EC2 Volumes are block-level storage devices that can be attached to EC2"
        " instances in Amazon's cloud, providing additional storage for applications"
        " and data."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-volumes", "Volumes")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_ec2_volume_type", "aws_ec2_instance"], "delete": ["aws_kms_key"]},
        "successors": {"default": ["aws_kms_key"], "delete": ["aws_ec2_instance"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("VolumeId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreateTime"),
        "volume_size": S("Size"),
        "volume_type": S("VolumeType"),
        "volume_status": S("State") >> MapEnum(VolumeStatusMapping, default=VolumeStatus.UNKNOWN),
        "volume_iops": S("Iops"),
        "volume_throughput": S("Throughput"),
        "volume_encrypted": S("Encrypted"),
        "volume_attachments": S("Attachments", default=[]) >> ForallBend(AwsEc2VolumeAttachment.mapping),
        "availability_zone": S("AvailabilityZone"),
        "volume_kms_key_id": S("KmsKeyId"),
        "volume_outpost_arn": S("OutpostArn"),
        "volume_snapshot_id": S("SnapshotId"),
        "volume_fast_restored": S("FastRestored"),
        "volume_multi_attach_enabled": S("MultiAttachEnabled"),
    }
    volume_attachments: List[AwsEc2VolumeAttachment] = field(factory=list)
    availability_zone: Optional[str] = field(default=None)
    volume_encrypted: Optional[bool] = field(default=None)
    volume_kms_key_id: Optional[str] = field(default=None)
    volume_outpost_arn: Optional[str] = field(default=None)
    volume_snapshot_id: Optional[str] = field(default=None)
    volume_iops: Optional[int] = field(default=None)
    volume_fast_restored: Optional[bool] = field(default=None)
    volume_multi_attach_enabled: Optional[bool] = field(default=None)
    volume_throughput: Optional[int] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        volumes: List[AwsEc2Volume] = []

        def update_atime_mtime() -> None:
            delta = builder.config.atime_mtime_granularity()
            queries = []
            now = utc()
            start = now - builder.config.atime_mtime_period()
            lookup: Dict[str, AwsEc2Volume] = {}
            for volume in volumes:
                # Used volumes: use now as atime and mtime
                if volume.volume_status == VolumeStatus.IN_USE:
                    volume.atime = now
                    volume.mtime = now
                elif volume.volume_status == VolumeStatus.AVAILABLE:
                    vid = volume.id
                    lookup[vid] = volume
                    queries.append(AwsCloudwatchQuery.create("VolumeReadOps", "AWS/EBS", delta, vid, VolumeId=vid))
                    queries.append(AwsCloudwatchQuery.create("VolumeWriteOps", "AWS/EBS", delta, vid, VolumeId=vid))

            for query, metric in AwsCloudwatchMetricData.query_for(builder, queries, start, now).items():
                if non_zero := metric.first_non_zero():
                    at, value = non_zero
                    if vol := lookup.get(query.ref_id):
                        if metric.label == "VolumeReadOps":
                            vol.atime = at
                        elif metric.label == "VolumeWriteOps":
                            vol.mtime = at
            # fall back to either ctime or start time whatever is more recent for all volumes cloudwatch did not return
            for v in lookup.values():
                t = max(v.ctime or start, start)
                if v.atime is None:
                    v.atime = t
                if v.mtime is None:
                    v.mtime = t

        for js in json:
            if volume := AwsEc2Volume.from_api(js, builder):
                instance = builder.add_node(volume, js)
                volumes.append(instance)
                if vt := builder.volume_type(instance.volume_type):
                    builder.add_edge(vt, EdgeType.default, node=instance)
        update_atime_mtime()

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        volumes = {
            volume.id: volume
            for volume in builder.nodes(clazz=AwsEc2Volume)
            if volume.region().id == builder.region.id and volume
        }
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at
        five_minutes_or_less = min(timedelta(minutes=5), delta)

        for volume_id in volumes:
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric_name,
                        namespace="AWS/EBS",
                        period=five_minutes_or_less,
                        ref_id=volume_id,
                        stat="Sum",
                        unit="Bytes",
                        VolumeId=volume_id,
                    )
                    for metric_name in ["VolumeWriteBytes", "VolumeReadBytes"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric_name,
                        namespace="AWS/EBS",
                        period=five_minutes_or_less,
                        ref_id=volume_id,
                        stat="Sum",
                        unit="Count",
                        VolumeId=volume_id,
                    )
                    for metric_name in ["VolumeWriteOps", "VolumeReadOps"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric_name,
                        namespace="AWS/EBS",
                        period=delta,
                        ref_id=volume_id,
                        stat="Sum",
                        unit="Seconds",
                        VolumeId=volume_id,
                    )
                    for metric_name in ["VolumeTotalWriteTime", "VolumeIdleTime"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="VolumeQueueLength",
                        namespace="AWS/EBS",
                        period=delta,
                        ref_id=volume_id,
                        stat=stat,
                        unit="Count",
                        VolumeId=volume_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )

        metric_normalizers = {
            "VolumeWriteBytes": MetricNormalization(
                metric_name=MetricName.VolumeWrite,
                unit=MetricUnit.MegabytesPerSecond,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(bytes_to_megabytes_per_second, period=five_minutes_or_less),
            ),
            "VolumeReadBytes": MetricNormalization(
                metric_name=MetricName.VolumeRead,
                unit=MetricUnit.MegabytesPerSecond,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(bytes_to_megabytes_per_second, period=five_minutes_or_less),
            ),
            "VolumeWriteOps": MetricNormalization(
                metric_name=MetricName.VolumeWrite,
                unit=MetricUnit.IOPS,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(operations_to_iops, period=five_minutes_or_less),
            ),
            "VolumeReadOps": MetricNormalization(
                metric_name=MetricName.VolumeRead,
                unit=MetricUnit.IOPS,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(operations_to_iops, period=five_minutes_or_less),
            ),
            "VolumeTotalWriteTime": MetricNormalization(
                metric_name=MetricName.VolumeTotalWriteTime, unit=MetricUnit.Seconds
            ),
            "VolumeIdleTime": MetricNormalization(metric_name=MetricName.VolumeIdleTime, unit=MetricUnit.Seconds),
            "VolumeQueueLength": MetricNormalization(metric_name=MetricName.VolumeQueueLength, unit=MetricUnit.Count),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(volumes, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for attachment in self.volume_attachments:
            builder.dependant_node(self, reverse=True, clazz=AwsEc2Instance, id=attachment.instance_id)
        if self.volume_kms_key_id:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                id=AwsKmsKey.normalise_id(self.volume_kms_key_id),
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-volume",
            result_name=None,
            VolumeId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-volume")]


# endregion

# region Snapshot


@define(eq=False, slots=False)
class AwsEc2Snapshot(EC2Taggable, AwsResource, BaseSnapshot):
    kind: ClassVar[str] = "aws_ec2_snapshot"
    kind_display: ClassVar[str] = "AWS EC2 Snapshot"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#SnapshotDetails:snapshotId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:snapshot/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "EC2 Snapshots are backups of Amazon Elastic Block Store (EBS)"
        " volumes, allowing users to capture and store point-in-time copies of their"
        " data."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "describe-snapshots", "Snapshots", dict(OwnerIds=["self"])
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_ec2_volume"], "delete": ["aws_kms_key"]},
        "successors": {"default": ["aws_kms_key"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("SnapshotId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": (S("Tags", default=[]) >> TagsValue("Name")).or_else(S("SnapshotId")),
        "ctime": S("StartTime"),
        "description": S("Description"),
        "encrypted": S("Encrypted"),
        "owner_alias": S("OwnerAlias"),
        "owner_id": S("OwnerId"),
        "volume_id": S("VolumeId"),
        "volume_size": S("VolumeSize"),
        "snapshot_data_encryption_key_id": S("DataEncryptionKeyId"),
        "snapshot_kms_key_id": S("KmsKeyId"),
        "snapshot_outpost_arn": S("OutpostArn"),
        "snapshot_progress": S("Progress"),
        "snapshot_state_message": S("StateMessage"),
        "snapshot_status": S("State"),
        "snapshot_storage_tier": S("StorageTier"),
        "snapshot_restore_expiry_time": S("RestoreExpiryTime"),
    }
    snapshot_data_encryption_key_id: Optional[str] = field(default=None)
    snapshot_kms_key_id: Optional[str] = field(default=None)
    snapshot_progress: Optional[str] = field(default=None)
    snapshot_state_message: Optional[str] = field(default=None)
    snapshot_outpost_arn: Optional[str] = field(default=None)
    snapshot_storage_tier: Optional[str] = field(default=None)
    snapshot_restore_expiry_time: Optional[datetime] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if volume_id := source.get("VolumeId"):
            builder.add_edge(self, EdgeType.default, reverse=True, clazz=AwsEc2Volume, id=volume_id)
        if self.snapshot_kms_key_id:
            builder.dependant_node(
                self,
                clazz=AwsKmsKey,
                id=AwsKmsKey.normalise_id(self.snapshot_kms_key_id),
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-snapshot", result_name=None, SnapshotId=self.id)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-snapshot")]


# endregion

# region KeyPair


@define(eq=False, slots=False)
class AwsEc2KeyPair(EC2Taggable, AwsResource):
    kind: ClassVar[str] = "aws_ec2_keypair"
    kind_display: ClassVar[str] = "AWS EC2 Keypair"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#KeyPairs:search={name}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:keypair/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = "EC2 Keypairs are SSH key pairs used to securely connect to EC2 instances in Amazon's cloud."  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-key-pairs", "KeyPairs")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [],
            "delete": ["aws_ec2_instance"],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("KeyPairId"),
        "name": S("KeyName"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "key_fingerprint": S("KeyFingerprint"),
        "key_type": S("KeyType"),
        "public_key": S("PublicKey"),
        "ctime": S("CreateTime"),
    }
    key_fingerprint: Optional[str] = field(default=None)
    key_type: Optional[str] = field(default=None)
    public_key: Optional[str] = field(default=None)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-key-pair",
            result_name=None,
            KeyPairId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-key-pair")]


# endregion

# region Instance


@define(eq=False, slots=False)
class AwsEc2Placement:
    kind: ClassVar[str] = "aws_ec2_placement"
    kind_display: ClassVar[str] = "AWS EC2 Placement"
    kind_description: ClassVar[str] = (
        "AWS EC2 Placement specifies the placement settings for an EC2 instance, including the Availability Zone,"
        " placement group, and tenancy options, which determine how instances are distributed within the AWS"
        " infrastructure for performance and isolation."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "availability_zone": S("AvailabilityZone"),
        "affinity": S("Affinity"),
        "group_name": S("GroupName"),
        "partition_number": S("PartitionNumber"),
        "host_id": S("HostId"),
        "tenancy": S("Tenancy"),
        "spread_domain": S("SpreadDomain"),
        "host_resource_group_arn": S("HostResourceGroupArn"),
    }
    availability_zone: Optional[str] = field(default=None)
    affinity: Optional[str] = field(default=None)
    group_name: Optional[str] = field(default=None)
    partition_number: Optional[int] = field(default=None)
    host_id: Optional[str] = field(default=None)
    tenancy: Optional[str] = field(default=None)
    spread_domain: Optional[str] = field(default=None)
    host_resource_group_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2ProductCode:
    kind: ClassVar[str] = "aws_ec2_product_code"
    kind_display: ClassVar[str] = "AWS EC2 Product Code"
    kind_description: ClassVar[str] = (
        "An EC2 Product Code is a unique identifier assigned to an Amazon Machine"
        " Image (AMI) to facilitate tracking and licensing of software packages"
        " included in the image."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "product_code_id": S("ProductCodeId"),
        "product_code_type": S("ProductCodeType"),
    }
    product_code_id: Optional[str] = field(default=None)
    product_code_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InstanceState:
    kind: ClassVar[str] = "aws_ec2_instance_state"
    kind_display: ClassVar[str] = "AWS EC2 Instance State"
    kind_description: ClassVar[str] = (
        "AWS EC2 Instance State represents the current state of an EC2 instance in"
        " Amazon's cloud, such as running, stopped, terminated, or pending."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "name": S("Name")}
    code: Optional[int] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2EbsInstanceBlockDevice:
    kind: ClassVar[str] = "aws_ec2_ebs_instance_block_device"
    kind_display: ClassVar[str] = "AWS EC2 EBS Instance Block Device"
    kind_description: ClassVar[str] = (
        "EC2 EBS Instance Block Device is a storage volume attached to an Amazon EC2"
        " instance for persistent data storage."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "attach_time": S("AttachTime"),
        "delete_on_termination": S("DeleteOnTermination"),
        "status": S("Status"),
        "volume_id": S("VolumeId"),
    }
    attach_time: Optional[datetime] = field(default=None)
    delete_on_termination: Optional[bool] = field(default=None)
    status: Optional[str] = field(default=None)
    volume_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InstanceBlockDeviceMapping:
    kind: ClassVar[str] = "aws_ec2_instance_block_device_mapping"
    kind_display: ClassVar[str] = "AWS EC2 Instance Block Device Mapping"
    kind_description: ClassVar[str] = (
        "Block device mapping is a feature in Amazon EC2 that allows users to specify"
        " the block devices to attach to an EC2 instance at launch time."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_name": S("DeviceName"),
        "ebs": S("Ebs") >> Bend(AwsEc2EbsInstanceBlockDevice.mapping),
    }
    device_name: Optional[str] = field(default=None)
    ebs: Optional[AwsEc2EbsInstanceBlockDevice] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2IamInstanceProfile:
    kind: ClassVar[str] = "aws_ec2_iam_instance_profile"
    kind_display: ClassVar[str] = "AWS EC2 IAM Instance Profile"
    kind_description: ClassVar[str] = (
        "IAM Instance Profiles are used to associate IAM roles with EC2 instances,"
        " allowing applications running on the instances to securely access other AWS"
        " services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "id": S("Id")}
    arn: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2ElasticGpuAssociation:
    kind: ClassVar[str] = "aws_ec2_elastic_gpu_association"
    kind_display: ClassVar[str] = "AWS EC2 Elastic GPU Association"
    kind_description: ClassVar[str] = (
        "Elastic GPU Association is a feature in AWS EC2 that allows attaching an"
        " Elastic GPU to an EC2 instance, providing additional GPU resources for"
        " graphics-intensive applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "elastic_gpu_id": S("ElasticGpuId"),
        "elastic_gpu_association_id": S("ElasticGpuAssociationId"),
        "elastic_gpu_association_state": S("ElasticGpuAssociationState"),
        "elastic_gpu_association_time": S("ElasticGpuAssociationTime"),
    }
    elastic_gpu_id: Optional[str] = field(default=None)
    elastic_gpu_association_id: Optional[str] = field(default=None)
    elastic_gpu_association_state: Optional[str] = field(default=None)
    elastic_gpu_association_time: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2ElasticInferenceAcceleratorAssociation:
    kind: ClassVar[str] = "aws_ec2_elastic_inference_accelerator_association"
    kind_display: ClassVar[str] = "AWS EC2 Elastic Inference Accelerator Association"
    kind_description: ClassVar[str] = (
        "AWS EC2 Elastic Inference Accelerator Association refers to the connection between an EC2 instance and"
        " an Elastic Inference (EI) Accelerator, which provides additional, scalable inference computing"
        " resources to run deep learning models with improved performance-cost ratio."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "elastic_inference_accelerator_arn": S("ElasticInferenceAcceleratorArn"),
        "elastic_inference_accelerator_association_id": S("ElasticInferenceAcceleratorAssociationId"),
        "elastic_inference_accelerator_association_state": S("ElasticInferenceAcceleratorAssociationState"),
        "elastic_inference_accelerator_association_time": S("ElasticInferenceAcceleratorAssociationTime"),
    }
    elastic_inference_accelerator_arn: Optional[str] = field(default=None)
    elastic_inference_accelerator_association_id: Optional[str] = field(default=None)
    elastic_inference_accelerator_association_state: Optional[str] = field(default=None)
    elastic_inference_accelerator_association_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InstanceNetworkInterfaceAssociation:
    kind: ClassVar[str] = "aws_ec2_instance_network_interface_association"
    kind_display: ClassVar[str] = "AWS EC2 Instance Network Interface Association"
    kind_description: ClassVar[str] = (
        "A network interface association for an EC2 instance in Amazon's cloud, which"
        " helps manage the connection between the instance and its associated network"
        " interface."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "carrier_ip": S("CarrierIp"),
        "customer_owned_ip": S("CustomerOwnedIp"),
        "owner_id": S("IpOwnerId"),
        "public_dns_name": S("PublicDnsName"),
        "public_ip": S("PublicIp"),
    }
    carrier_ip: Optional[str] = field(default=None)
    customer_owned_ip: Optional[str] = field(default=None)
    owner_id: Optional[str] = field(default=None)
    public_dns_name: Optional[str] = field(default=None)
    public_ip: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InstanceNetworkInterfaceAttachment:
    kind: ClassVar[str] = "aws_ec2_instance_network_interface_attachment"
    kind_display: ClassVar[str] = "AWS EC2 Instance Network Interface Attachment"
    kind_description: ClassVar[str] = (
        "An attachment of a network interface to an EC2 instance in the Amazon Web Services cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "attach_time": S("AttachTime"),
        "attachment_id": S("AttachmentId"),
        "delete_on_termination": S("DeleteOnTermination"),
        "device_index": S("DeviceIndex"),
        "status": S("Status"),
        "network_card_index": S("NetworkCardIndex"),
    }
    attach_time: Optional[datetime] = field(default=None)
    attachment_id: Optional[str] = field(default=None)
    delete_on_termination: Optional[bool] = field(default=None)
    device_index: Optional[int] = field(default=None)
    status: Optional[str] = field(default=None)
    network_card_index: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2GroupIdentifier:
    kind: ClassVar[str] = "aws_ec2_group_identifier"
    kind_display: ClassVar[str] = "AWS EC2 Group Identifier"
    kind_description: ClassVar[str] = (
        "An EC2 Group Identifier is a unique identifier for a group of EC2 instances"
        " that are associated with a security group in Amazon's cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"group_name": S("GroupName"), "group_id": S("GroupId")}
    group_name: Optional[str] = field(default=None)
    group_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InstancePrivateIpAddress:
    kind: ClassVar[str] = "aws_ec2_instance_private_ip_address"
    kind_display: ClassVar[str] = "AWS EC2 Instance Private IP Address"
    kind_description: ClassVar[str] = (
        "The private IP address is the internal IP address assigned to the EC2"
        " instance within the Amazon VPC (Virtual Private Cloud) network."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "association": S("Association") >> Bend(AwsEc2InstanceNetworkInterfaceAssociation.mapping),
        "primary": S("Primary"),
        "private_dns_name": S("PrivateDnsName"),
        "private_ip_address": S("PrivateIpAddress"),
    }
    association: Optional[AwsEc2InstanceNetworkInterfaceAssociation] = field(default=None)
    primary: Optional[bool] = field(default=None)
    private_dns_name: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InstanceNetworkInterface:
    kind: ClassVar[str] = "aws_ec2_instance_network_interface"
    kind_display: ClassVar[str] = "AWS EC2 Instance Network Interface"
    kind_description: ClassVar[str] = (
        "A network interface is a virtual network card that allows an EC2 instance to"
        " connect to networks and communicate with other resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "association": S("Association") >> Bend(AwsEc2InstanceNetworkInterfaceAssociation.mapping),
        "attachment": S("Attachment") >> Bend(AwsEc2InstanceNetworkInterfaceAttachment.mapping),
        "description": S("Description"),
        "groups": S("Groups", default=[]) >> ForallBend(AwsEc2GroupIdentifier.mapping),
        "ipv6_addresses": S("Ipv6Addresses", default=[]) >> ForallBend(S("Ipv6Address")),
        "mac_address": S("MacAddress"),
        "network_interface_id": S("NetworkInterfaceId"),
        # "owner_id": S("OwnerId"),
        "private_dns_name": S("PrivateDnsName"),
        "private_ip_address": S("PrivateIpAddress"),
        "private_ip_addresses": S("PrivateIpAddresses", default=[])
        >> ForallBend(AwsEc2InstancePrivateIpAddress.mapping),
        "source_dest_check": S("SourceDestCheck"),
        "status": S("Status"),
        # "subnet_id": S("SubnetId"),
        # "vpc_id": S("VpcId"),
        "interface_type": S("InterfaceType"),
        "ipv4_prefixes": S("Ipv4Prefixes", default=[]) >> ForallBend(S("Ipv4Prefix")),
        "ipv6_prefixes": S("Ipv6Prefixes", default=[]) >> ForallBend(S("Ipv6Prefix")),
    }
    association: Optional[AwsEc2InstanceNetworkInterfaceAssociation] = field(default=None)
    attachment: Optional[AwsEc2InstanceNetworkInterfaceAttachment] = field(default=None)
    description: Optional[str] = field(default=None)
    groups: List[AwsEc2GroupIdentifier] = field(factory=list)
    ipv6_addresses: List[str] = field(factory=list)
    mac_address: Optional[str] = field(default=None)
    network_interface_id: Optional[str] = field(default=None)
    private_dns_name: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)
    private_ip_addresses: List[AwsEc2InstancePrivateIpAddress] = field(factory=list)
    source_dest_check: Optional[bool] = field(default=None)
    status: Optional[str] = field(default=None)
    interface_type: Optional[str] = field(default=None)
    ipv4_prefixes: List[str] = field(factory=list)
    ipv6_prefixes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEc2StateReason:
    kind: ClassVar[str] = "aws_ec2_state_reason"
    kind_display: ClassVar[str] = "AWS EC2 State Reason"
    kind_description: ClassVar[str] = (
        "EC2 State Reason provides information about the reason a certain EC2"
        " instance is in its current state, such as running, stopped, or terminated."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "message": S("Message")}
    code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2CpuOptions:
    kind: ClassVar[str] = "aws_ec2_cpu_options"
    kind_display: ClassVar[str] = "AWS EC2 CPU Options"
    kind_description: ClassVar[str] = (
        "EC2 CPU Options allow users to customize the number of vCPUs (virtual CPUs)"
        " and the processor generation of their EC2 instances in Amazon's cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"core_count": S("CoreCount"), "threads_per_core": S("ThreadsPerCore")}
    core_count: Optional[int] = field(default=None)
    threads_per_core: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2CapacityReservationTargetResponse:
    kind: ClassVar[str] = "aws_ec2_capacity_reservation_target_response"
    kind_display: ClassVar[str] = "AWS EC2 Capacity Reservation Target Response"
    kind_description: ClassVar[str] = (
        "Capacity Reservation Target Response is used in AWS to specify the Amazon Resource Name (ARN)"
        " of the Capacity Reservation target in AWS EC2. This is used when you launch an instance or"
        " when you allocate an elastic IP address."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_reservation_id": S("CapacityReservationId"),
        "capacity_reservation_resource_group_arn": S("CapacityReservationResourceGroupArn"),
    }
    capacity_reservation_id: Optional[str] = field(default=None)
    capacity_reservation_resource_group_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2CapacityReservationSpecificationResponse:
    kind: ClassVar[str] = "aws_ec2_capacity_reservation_specification_response"
    kind_display: ClassVar[str] = "AWS EC2 Capacity Reservation Specification Response"
    kind_description: ClassVar[str] = (
        "The Capacity Reservation Specification Response is a response object that"
        " provides information about the capacity reservations for an EC2 instance in"
        " Amazon's cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_reservation_preference": S("CapacityReservationPreference"),
        "capacity_reservation_target": S("CapacityReservationTarget")
        >> Bend(AwsEc2CapacityReservationTargetResponse.mapping),
    }
    capacity_reservation_preference: Optional[str] = field(default=None)
    capacity_reservation_target: Optional[AwsEc2CapacityReservationTargetResponse] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InstanceMetadataOptionsResponse:
    kind: ClassVar[str] = "aws_ec2_instance_metadata_options_response"
    kind_display: ClassVar[str] = "AWS EC2 Instance Metadata Options Response"
    kind_description: ClassVar[str] = (
        "The AWS EC2 Instance Metadata Options Response is a configuration response"
        " from Amazon EC2 that provides information about the metadata service options"
        " enabled for an EC2 instance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "state": S("State"),
        "http_tokens": S("HttpTokens"),
        "http_put_response_hop_limit": S("HttpPutResponseHopLimit"),
        "http_endpoint": S("HttpEndpoint"),
        "http_protocol_ipv6": S("HttpProtocolIpv6"),
        "instance_metadata_tags": S("InstanceMetadataTags"),
    }
    state: Optional[str] = field(default=None)
    http_tokens: Optional[str] = field(default=None)
    http_put_response_hop_limit: Optional[int] = field(default=None)
    http_endpoint: Optional[str] = field(default=None)
    http_protocol_ipv6: Optional[str] = field(default=None)
    instance_metadata_tags: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2PrivateDnsNameOptionsResponse:
    kind: ClassVar[str] = "aws_ec2_private_dns_name_options_response"
    kind_display: ClassVar[str] = "AWS EC2 Private DNS Name Options Response"
    kind_description: ClassVar[str] = (
        "Private DNS Name Options Response is a response object in the AWS EC2"
        " service that provides options for configuring the private DNS name of a"
        " resource in a virtual private cloud (VPC)."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname_type": S("HostnameType"),
        "enable_resource_name_dns_a_record": S("EnableResourceNameDnsARecord"),
        "enable_resource_name_dns_aaaa_record": S("EnableResourceNameDnsAAAARecord"),
    }
    hostname_type: Optional[str] = field(default=None)
    enable_resource_name_dns_a_record: Optional[bool] = field(default=None)
    enable_resource_name_dns_aaaa_record: Optional[bool] = field(default=None)


InstanceStatusMapping = {
    "pending": InstanceStatus.BUSY,
    "running": InstanceStatus.RUNNING,
    "shutting-down": InstanceStatus.STOPPED,
    "terminated": InstanceStatus.TERMINATED,
    "stopping": InstanceStatus.STOPPED,
    "stopped": InstanceStatus.STOPPED,
}


@define(eq=False, slots=False)
class AwsEc2Instance(EC2Taggable, AwsResource, BaseInstance):
    kind: ClassVar[str] = "aws_ec2_instance"
    kind_display: ClassVar[str] = "AWS EC2 Instance"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#InstanceDetails:instanceId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:instance/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "EC2 Instances are virtual servers in Amazon's cloud, allowing users to run"
        " applications on the Amazon Web Services infrastructure."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-instances", "Reservations")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_vpc", "aws_subnet", "aws_ec2_image", "aws_iam_instance_profile"],
            "delete": ["aws_ec2_keypair", "aws_vpc", "aws_subnet"],
        },
        "successors": {"default": ["aws_ec2_keypair"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        # base properties
        "id": S("InstanceId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("LaunchTime"),
        "instance_status": S("State", "Name") >> MapEnum(InstanceStatusMapping, default=InstanceStatus.UNKNOWN),
        "instance_cores": S("CpuOptions", "CoreCount"),
        "instance_ami_launch_index": S("AmiLaunchIndex"),
        "instance_image_id": S("ImageId"),
        "instance_type": S("InstanceType"),
        "instance_kernel_id": S("KernelId"),
        "instance_key_name": S("KeyName"),
        "instance_launch_time": S("LaunchTime"),
        "instance_monitoring": S("Monitoring", "State"),
        "instance_placement": S("Placement") >> Bend(AwsEc2Placement.mapping),
        "instance_platform": S("Platform"),
        "instance_private_dns_name": S("PrivateDnsName"),
        "instance_private_ip_address": S("PrivateIpAddress"),
        "instance_product_codes": S("ProductCodes", default=[]) >> ForallBend(AwsEc2ProductCode.mapping),
        "instance_public_dns_name": S("PublicDnsName"),
        "instance_public_ip_address": S("PublicIpAddress"),
        "instance_ramdisk_id": S("RamdiskId"),
        "instance_state": S("State") >> Bend(AwsEc2InstanceState.mapping),
        "instance_state_transition_reason": S("StateTransitionReason"),
        "instance_subnet_id": S("SubnetId"),
        "instance_architecture": S("Architecture"),
        "instance_block_device_mappings": S("BlockDeviceMappings", default=[])
        >> ForallBend(AwsEc2InstanceBlockDeviceMapping.mapping),
        "instance_client_token": S("ClientToken"),
        "instance_ebs_optimized": S("EbsOptimized"),
        "instance_ena_support": S("EnaSupport"),
        "instance_hypervisor": S("Hypervisor"),
        "instance_iam_instance_profile": S("IamInstanceProfile") >> Bend(AwsEc2IamInstanceProfile.mapping),
        "instance_lifecycle": S("InstanceLifecycle"),
        "instance_elastic_gpu_associations": S("ElasticGpuAssociations", default=[])
        >> ForallBend(AwsEc2ElasticGpuAssociation.mapping),
        "instance_elastic_inference_accelerator_associations": S("ElasticInferenceAcceleratorAssociations", default=[])
        >> ForallBend(AwsEc2ElasticInferenceAcceleratorAssociation.mapping),
        "instance_network_interfaces": S("NetworkInterfaces", default=[])
        >> ForallBend(AwsEc2InstanceNetworkInterface.mapping),
        "instance_outpost_arn": S("OutpostArn"),
        "instance_root_device_name": S("RootDeviceName"),
        "instance_root_device_type": S("RootDeviceType"),
        "instance_security_groups": S("SecurityGroups", default=[]) >> ForallBend(AwsEc2GroupIdentifier.mapping),
        "instance_source_dest_check": S("SourceDestCheck"),
        "instance_spot_instance_request_id": S("SpotInstanceRequestId"),
        "instance_sriov_net_support": S("SriovNetSupport"),
        "instance_state_reason": S("StateReason") >> Bend(AwsEc2StateReason.mapping),
        "instance_virtualization_type": S("VirtualizationType"),
        "instance_cpu_options": S("CpuOptions") >> Bend(AwsEc2CpuOptions.mapping),
        "instance_capacity_reservation_id": S("CapacityReservationId"),
        "instance_capacity_reservation_specification": S("CapacityReservationSpecification")
        >> Bend(AwsEc2CapacityReservationSpecificationResponse.mapping),
        "instance_hibernation_options": S("HibernationOptions", "Configured"),
        "instance_licenses": S("Licenses", default=[]) >> ForallBend(S("LicenseConfigurationArn")),
        "instance_metadata_options": S("MetadataOptions") >> Bend(AwsEc2InstanceMetadataOptionsResponse.mapping),
        "instance_enclave_options": S("EnclaveOptions", "Enabled"),
        "instance_boot_mode": S("BootMode"),
        "instance_platform_details": S("PlatformDetails"),
        "instance_usage_operation": S("UsageOperation"),
        "instance_usage_operation_update_time": S("UsageOperationUpdateTime"),
        "instance_private_dns_name_options": S("PrivateDnsNameOptions")
        >> Bend(AwsEc2PrivateDnsNameOptionsResponse.mapping),
        "instance_ipv6_address": S("Ipv6Address"),
        "instance_tpm_support": S("TpmSupport"),
        "instance_maintenance_options": S("MaintenanceOptions", "AutoRecovery"),
    }
    instance_ami_launch_index: Optional[int] = field(default=None)
    instance_image_id: Optional[str] = field(default=None)
    instance_kernel_id: Optional[str] = field(default=None)
    instance_key_name: Optional[str] = field(default=None)
    instance_launch_time: Optional[datetime] = field(default=None)
    instance_monitoring: Optional[str] = field(default=None)
    instance_placement: Optional[AwsEc2Placement] = field(default=None)
    instance_platform: Optional[str] = field(default=None)
    instance_private_dns_name: Optional[str] = field(default=None)
    instance_private_ip_address: Optional[str] = field(default=None)
    instance_product_codes: List[AwsEc2ProductCode] = field(factory=list)
    instance_public_dns_name: Optional[str] = field(default=None)
    instance_public_ip_address: Optional[str] = field(default=None)
    instance_ramdisk_id: Optional[str] = field(default=None)
    instance_state: Optional[AwsEc2InstanceState] = field(default=None)
    instance_state_transition_reason: Optional[str] = field(default=None)
    instance_subnet_id: Optional[str] = field(default=None)
    instance_architecture: Optional[str] = field(default=None)
    instance_block_device_mappings: List[AwsEc2InstanceBlockDeviceMapping] = field(factory=list)
    instance_client_token: Optional[str] = field(default=None)
    instance_ebs_optimized: Optional[bool] = field(default=None)
    instance_ena_support: Optional[bool] = field(default=None)
    instance_hypervisor: Optional[str] = field(default=None)
    instance_iam_instance_profile: Optional[AwsEc2IamInstanceProfile] = field(default=None)
    instance_lifecycle: Optional[str] = field(default=None)
    instance_elastic_gpu_associations: List[AwsEc2ElasticGpuAssociation] = field(factory=list)
    instance_elastic_inference_accelerator_associations: List[AwsEc2ElasticInferenceAcceleratorAssociation] = field(
        factory=list
    )
    instance_network_interfaces: List[AwsEc2InstanceNetworkInterface] = field(factory=list)
    instance_outpost_arn: Optional[str] = field(default=None)
    instance_root_device_name: Optional[str] = field(default=None)
    instance_root_device_type: Optional[str] = field(default=None)
    instance_security_groups: List[AwsEc2GroupIdentifier] = field(factory=list)
    instance_source_dest_check: Optional[bool] = field(default=None)
    instance_spot_instance_request_id: Optional[str] = field(default=None)
    instance_sriov_net_support: Optional[str] = field(default=None)
    instance_state_reason: Optional[AwsEc2StateReason] = field(default=None)
    instance_virtualization_type: Optional[str] = field(default=None)
    instance_cpu_options: Optional[AwsEc2CpuOptions] = field(default=None)
    instance_capacity_reservation_id: Optional[str] = field(default=None)
    instance_capacity_reservation_specification: Optional[AwsEc2CapacityReservationSpecificationResponse] = field(
        default=None
    )
    instance_hibernation_options: Optional[bool] = field(default=None)
    instance_licenses: List[str] = field(factory=list)
    instance_metadata_options: Optional[AwsEc2InstanceMetadataOptionsResponse] = field(default=None)
    instance_enclave_options: Optional[bool] = field(default=None)
    instance_boot_mode: Optional[str] = field(default=None)
    instance_platform_details: Optional[str] = field(default=None)
    instance_usage_operation: Optional[str] = field(default=None)
    instance_usage_operation_update_time: Optional[datetime] = field(default=None)
    instance_private_dns_name_options: Optional[AwsEc2PrivateDnsNameOptionsResponse] = field(default=None)
    instance_ipv6_address: Optional[str] = field(default=None)
    instance_tpm_support: Optional[str] = field(default=None)
    instance_maintenance_options: Optional[str] = field(default=None)
    instance_user_data: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def fetch_user_data(instance: AwsEc2Instance) -> None:
            if (
                result := builder.client.get(
                    service_name,
                    "describe-instance-attribute",
                    "UserData",
                    InstanceId=instance.id,
                    Attribute="userData",
                )
            ) and (data := result.get("Value")):
                with suppress(Exception):  # ignore userdata with wrong encoding
                    instance.instance_user_data = base64.b64decode(data).decode("utf-8")

        for reservation in json:
            for instance_in in reservation["Instances"]:
                mapped = bend(cls.mapping, instance_in)
                instance = AwsEc2Instance.from_json(mapped)
                builder.submit_work(service_name, fetch_user_data, instance)
                builder.add_node(instance, instance_in)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        instances = {
            instance.id: instance
            for instance in builder.nodes(clazz=AwsEc2Instance)
            if instance.region().id == builder.region.id and instance.instance_status == InstanceStatus.RUNNING
        }
        queries = []
        delta_since_last_scan = builder.metrics_delta
        # for metrics which are expressed as sum, we want the period to be
        # 5 minutes or less if the last scan was less than 5 minutes ago
        period = min(timedelta(minutes=5), delta_since_last_scan)

        start = builder.metrics_start
        now = builder.created_at
        for instance_id in instances:
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name="CPUUtilization",
                        namespace="AWS/EC2",
                        period=delta_since_last_scan,
                        ref_id=instance_id,
                        stat=stat,
                        unit="Percent",
                        InstanceId=instance_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/EC2",
                        period=period,
                        ref_id=instance_id,
                        stat="Sum",
                        unit="Bytes",
                        InstanceId=instance_id,
                    )
                    for name in ["NetworkIn", "NetworkOut"]
                ]
            )

            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/EC2",
                        period=period,
                        ref_id=instance_id,
                        stat="Sum",
                        unit="Count",
                        InstanceId=instance_id,
                    )
                    for name in ["NetworkPacketsIn", "NetworkPacketsOut"]
                ]
            )

            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/EC2",
                        period=period,
                        ref_id=instance_id,
                        stat="Sum",
                        unit="Count",
                        InstanceId=instance_id,
                    )
                    for name in ["DiskReadOps", "DiskWriteOps"]
                ]
            )

            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=name,
                        namespace="AWS/EC2",
                        period=period,
                        ref_id=instance_id,
                        stat="Sum",
                        unit="Bytes",
                        InstanceId=instance_id,
                    )
                    for name in ["DiskReadBytes", "DiskWriteBytes"]
                ]
            )

        metric_normalizers = {
            "CPUUtilization": MetricNormalization(
                metric_name=MetricName.CpuUtilization,
                unit=MetricUnit.Percent,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "NetworkIn": MetricNormalization(
                metric_name=MetricName.NetworkIn,
                unit=MetricUnit.MegabitsPerSecond,
                compute_stats=calculate_min_max_avg,
                # normalize to Mbps
                normalize_value=partial(bytes_to_megabits_per_second, period=period),
            ),
            "NetworkOut": MetricNormalization(
                metric_name=MetricName.NetworkOut,
                unit=MetricUnit.MegabitsPerSecond,
                compute_stats=calculate_min_max_avg,
                # normalize to Mbps
                normalize_value=partial(bytes_to_megabits_per_second, period=period),
            ),
            "NetworkPacketsIn": MetricNormalization(
                metric_name=MetricName.NetworkIn,
                unit=MetricUnit.PacketsPerSecond,
                compute_stats=calculate_min_max_avg,
                # normalize to packets per second
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "NetworkPacketsOut": MetricNormalization(
                metric_name=MetricName.NetworkOut,
                unit=MetricUnit.PacketsPerSecond,
                compute_stats=calculate_min_max_avg,
                # normalize to packets per second
                normalize_value=lambda x: round(x / period.total_seconds(), 4),
            ),
            "DiskReadOps": MetricNormalization(
                metric_name=MetricName.DiskRead,
                unit=MetricUnit.IOPS,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(operations_to_iops, period=period),
            ),
            "DiskWriteOps": MetricNormalization(
                metric_name=MetricName.DiskWrite,
                unit=MetricUnit.IOPS,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(operations_to_iops, period=period),
            ),
            "DiskReadBytes": MetricNormalization(
                metric_name=MetricName.DiskRead,
                unit=MetricUnit.MegabytesPerSecond,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(bytes_to_megabytes_per_second, period=period),
            ),
            "DiskWriteBytes": MetricNormalization(
                metric_name=MetricName.DiskWrite,
                unit=MetricUnit.MegabytesPerSecond,
                compute_stats=calculate_min_max_avg,
                normalize_value=partial(bytes_to_megabytes_per_second, period=period),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(instances, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        # connect instance type and copy values
        # noinspection PyTypeChecker
        if instance_type := builder.instance_type(self.region(), self.instance_type):  # type: ignore
            self.instance_cores = instance_type.instance_cores
            self.instance_memory = instance_type.instance_memory
            builder.add_edge(instance_type, EdgeType.default, node=self)

        if self.instance_key_name:
            builder.dependant_node(self, clazz=AwsEc2KeyPair, name=self.instance_key_name)
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, name=vpc_id)
        if subnet_id := source.get("SubnetId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, name=subnet_id)
        if image_id := source.get("ImageId"):
            builder.add_edge(self, reverse=True, clazz=AwsEc2Image, id=image_id)
        if lt_id := self.tags.get("aws:ec2launchtemplate:id"):
            builder.add_edge(self, reverse=True, clazz=AwsEc2LaunchTemplate, id=lt_id)
        if iam_profile := self.instance_iam_instance_profile:
            builder.add_edge(self, reverse=True, clazz=AwsIamInstanceProfile, arn=iam_profile.arn)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        if self.instance_status == InstanceStatus.TERMINATED:
            self.log("Instance is already terminated")
            return True
        client.call(
            aws_service=self.api_spec.service,
            action="terminate-instances",
            result_name=None,
            InstanceIds=[self.id],
            DryRun=False,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "terminate-instances"),
            AwsApiSpec(service_name, "describe-instance-attribute"),
        ]


# endregion

# region ReservedInstances


@define(eq=False, slots=False)
class AwsEc2RecurringCharge:
    kind: ClassVar[str] = "aws_ec2_recurring_charge"
    kind_display: ClassVar[str] = "AWS EC2 Recurring Charge"
    kind_description: ClassVar[str] = (
        "AWS EC2 Recurring Charge is a cost structure applied to certain EC2 instances, where users pay a fixed"
        " price at regular intervals for the use of the instance, typically offering savings over on-demand pricing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"amount": S("Amount"), "frequency": S("Frequency")}
    amount: Optional[float] = field(default=None)
    frequency: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2ReservedInstances(EC2Taggable, AwsResource):
    kind: ClassVar[str] = "aws_ec2_reserved_instances"
    kind_display: ClassVar[str] = "AWS EC2 Reserved Instances"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#ReservedInstances:instanceId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:reserved-instances/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "Reserved Instances are a purchasing option to save money on EC2 instance"
        " usage. Users can reserve instances for a one- or three-year term, allowing"
        " them to pay a lower hourly rate compared to on-demand instances."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-reserved-instances", "ReservedInstances")
    reference_kinds: ClassVar[ModelReference] = {"predecessors": {"default": ["aws_ec2_instance_type"]}}
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ReservedInstancesId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "availability_zone": S("AvailabilityZone"),
        "reservation_duration": S("Duration"),
        "reservation_end": S("End"),
        "reservation_fixed_price": S("FixedPrice"),
        "reservation_instance_count": S("InstanceCount"),
        "reservation_instance_type": S("InstanceType"),
        "reservation_product_description": S("ProductDescription"),
        "reservation_reserved_instances_id": S("ReservedInstancesId"),
        "reservation_start": S("Start"),
        "reservation_state": S("State"),
        "reservation_usage_price": S("UsagePrice"),
        "reservation_currency_code": S("CurrencyCode"),
        "reservation_instance_tenancy": S("InstanceTenancy"),
        "reservation_offering_class": S("OfferingClass"),
        "reservation_offering_type": S("OfferingType"),
        "reservation_recurring_charges": S("RecurringCharges", default=[]) >> ForallBend(AwsEc2RecurringCharge.mapping),
        "reservation_scope": S("Scope"),
    }
    availability_zone: Optional[str] = field(default=None)
    reservation_duration: Optional[int] = field(default=None)
    reservation_end: Optional[datetime] = field(default=None)
    reservation_fixed_price: Optional[float] = field(default=None)
    reservation_instance_count: Optional[int] = field(default=None)
    reservation_instance_type: Optional[str] = field(default=None)
    reservation_product_description: Optional[str] = field(default=None)
    reservation_reserved_instances_id: Optional[str] = field(default=None)
    reservation_start: Optional[datetime] = field(default=None)
    reservation_state: Optional[str] = field(default=None)
    reservation_usage_price: Optional[float] = field(default=None)
    reservation_currency_code: Optional[str] = field(default=None)
    reservation_instance_tenancy: Optional[str] = field(default=None)
    reservation_offering_class: Optional[str] = field(default=None)
    reservation_offering_type: Optional[str] = field(default=None)
    reservation_recurring_charges: List[AwsEc2RecurringCharge] = field(factory=list)
    reservation_scope: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        builder.add_edge(
            self, EdgeType.default, reverse=True, clazz=AwsEc2InstanceType, name=self.reservation_instance_type
        )


# endregion

# region Network ACLs


@define(eq=False, slots=False)
class AwsEc2NetworkAclAssociation:
    kind: ClassVar[str] = "aws_ec2_network_acl_association"
    kind_display: ClassVar[str] = "AWS EC2 Network ACL Association"
    kind_description: ClassVar[str] = (
        "Network ACL Associations are used to associate a network ACL with a subnet"
        " in an Amazon VPC, allowing the network ACL to control inbound and outbound"
        " traffic to and from the subnet."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "network_acl_association_id": S("NetworkAclAssociationId"),
        "network_acl_id": S("NetworkAclId"),
        "subnet_id": S("SubnetId"),
    }
    network_acl_association_id: Optional[str] = field(default=None)
    network_acl_id: Optional[str] = field(default=None)
    subnet_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2IcmpTypeCode:
    kind: ClassVar[str] = "aws_ec2_icmp_type_code"
    kind_display: ClassVar[str] = "AWS EC2 ICMP Type Code"
    kind_description: ClassVar[str] = (
        "ICMP Type Code is a parameter used in AWS EC2 to specify the type and code"
        " of Internet Control Message Protocol (ICMP) messages."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "type": S("Type")}
    code: Optional[int] = field(default=None)
    type: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2PortRange:
    kind: ClassVar[str] = "aws_ec2_port_range"
    kind_display: ClassVar[str] = "AWS EC2 Port Range"
    kind_description: ClassVar[str] = (
        "A range of port numbers that can be used to control inbound and outbound traffic for an AWS EC2 instance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"from_range": S("From"), "to_range": S("To")}
    from_range: Optional[int] = field(default=None)
    to_range: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2NetworkAclEntry:
    kind: ClassVar[str] = "aws_ec2_network_acl_entry"
    kind_display: ClassVar[str] = "AWS EC2 Network ACL Entry"
    kind_description: ClassVar[str] = (
        "EC2 Network ACL Entry is an access control entry for a network ACL in Amazon"
        " EC2, which controls inbound and outbound traffic flow for subnets."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cidr_block": S("CidrBlock"),
        "egress": S("Egress"),
        "icmp_type_code": S("IcmpTypeCode") >> Bend(AwsEc2IcmpTypeCode.mapping),
        "ipv6_cidr_block": S("Ipv6CidrBlock"),
        "port_range": S("PortRange") >> Bend(AwsEc2PortRange.mapping),
        "protocol": S("Protocol"),
        "rule_action": S("RuleAction"),
        "rule_number": S("RuleNumber"),
    }
    cidr_block: Optional[str] = field(default=None)
    egress: Optional[bool] = field(default=None)
    icmp_type_code: Optional[AwsEc2IcmpTypeCode] = field(default=None)
    ipv6_cidr_block: Optional[str] = field(default=None)
    port_range: Optional[AwsEc2PortRange] = field(default=None)
    protocol: Optional[str] = field(default=None)
    rule_action: Optional[str] = field(default=None)
    rule_number: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2NetworkAcl(EC2Taggable, AwsResource):
    kind: ClassVar[str] = "aws_ec2_network_acl"
    kind_display: ClassVar[str] = "AWS EC2 Network ACL"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/vpc/home?region={region}#NetworkAclDetails:networkAclId={NetworkAclId}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:network-acl/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "EC2 Network ACLs are virtual stateless firewalls that control inbound and"
        " outbound traffic for EC2 instances in Amazon's cloud."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-network-acls", "NetworkAcls")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_vpc"], "delete": ["aws_vpc", "aws_ec2_subnet"]},
        "successors": {"default": ["aws_ec2_subnet"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("NetworkAclId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "acl_associations": S("Associations", default=[]) >> ForallBend(AwsEc2NetworkAclAssociation.mapping),
        "acl_entries": S("Entries", default=[]) >> ForallBend(AwsEc2NetworkAclEntry.mapping),
        "is_default": S("IsDefault"),
        # "vpc_id": S("VpcId"),
        "owner_id": S("OwnerId"),
    }
    acl_associations: List[AwsEc2NetworkAclAssociation] = field(factory=list)
    acl_entries: List[AwsEc2NetworkAclEntry] = field(factory=list)
    is_default: Optional[bool] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, name=vpc_id)
        for association in self.acl_associations:
            builder.dependant_node(self, reverse=True, clazz=AwsEc2Subnet, name=association.subnet_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-network-acl", result_name=None, NetworkAclId=self.id
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-network-acl")]


# endregion

# region Elastic IPs


@define(eq=False, slots=False)
class AwsEc2ElasticIp(EC2Taggable, AwsResource, BaseIPAddress):
    kind: ClassVar[str] = "aws_ec2_elastic_ip"
    kind_display: ClassVar[str] = "AWS EC2 Elastic IP"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#ElasticIpDetails:AllocationId={AllocationId}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:elastic-ip/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "Elastic IP addresses are static, IPv4 addresses designed for dynamic cloud"
        " computing. They allow you to mask the failure or replacement of an instance"
        " by rapidly remapping the address to another instance in your account."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-addresses", "Addresses")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_ec2_instance", "aws_ec2_network_interface"]},
        "successors": {"delete": ["aws_ec2_instance", "aws_ec2_network_interface"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("PublicIp"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("InstanceId").or_else(S("Tags", default=[]) >> TagsValue("Name")).or_else(S("NetworkInterfaceId")),
        "ip_address": S("PublicIp") or S("PrivateIpAddress"),
        "ip_address_family": K("ipv4"),
        "private_ip_address": S("PrivateIpAddress"),
        "public_ip": S("PublicIp"),
        "ip_allocation_id": S("AllocationId"),
        "ip_association_id": S("AssociationId"),
        "ip_domain": S("Domain"),
        "ip_network_interface_id": S("NetworkInterfaceId"),
        # "owner_id": S("NetworkInterfaceOwnerId"),
        "ip_public_ipv4_pool": S("PublicIpv4Pool"),
        "ip_network_border_group": S("NetworkBorderGroup"),
        "ip_customer_owned_ip": S("CustomerOwnedIp"),
        "ip_customer_owned_ipv4_pool": S("CustomerOwnedIpv4Pool"),
        "ip_carrier_ip": S("CarrierIp"),
    }
    public_ip: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)
    ip_allocation_id: Optional[str] = field(default=None)
    ip_association_id: Optional[str] = field(default=None)
    ip_domain: Optional[str] = field(default=None)
    ip_network_interface_id: Optional[str] = field(default=None)
    ip_public_ipv4_pool: Optional[str] = field(default=None)
    ip_network_border_group: Optional[str] = field(default=None)
    ip_customer_owned_ip: Optional[str] = field(default=None)
    ip_customer_owned_ipv4_pool: Optional[str] = field(default=None)
    ip_carrier_ip: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if instance_id := source.get("InstanceId"):
            builder.dependant_node(self, reverse=True, clazz=AwsEc2Instance, id=instance_id)
        if interface_id := source.get("NetworkInterfaceId"):
            builder.dependant_node(self, reverse=True, clazz=AwsEc2NetworkInterface, id=interface_id)

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        if self.ip_association_id:
            client.call(
                aws_service=self.api_spec.service,
                action="disassociate-address",
                result_name=None,
                AssociationId=self.ip_association_id,
            )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="release-address",
            result_name=None,
            AllocationId=self.ip_allocation_id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "disassociate-address"),
            AwsApiSpec(service_name, "release-address"),
        ]


# endregion

# region Network Interfaces


@define(eq=False, slots=False)
class AwsEc2NetworkInterfaceAssociation:
    kind: ClassVar[str] = "aws_ec2_network_interface_association"
    kind_display: ClassVar[str] = "AWS EC2 Network Interface Association"
    kind_description: ClassVar[str] = (
        "The association between a network interface and an EC2 instance, allowing"
        " the instance to access the network."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "allocation_id": S("AllocationId"),
        "association_id": S("AssociationId"),
        # "owner_id": S("IpOwnerId"),
        "public_dns_name": S("PublicDnsName"),
        "public_ip": S("PublicIp"),
        "customer_owned_ip": S("CustomerOwnedIp"),
        "carrier_ip": S("CarrierIp"),
    }
    allocation_id: Optional[str] = field(default=None)
    association_id: Optional[str] = field(default=None)
    public_dns_name: Optional[str] = field(default=None)
    public_ip: Optional[str] = field(default=None)
    customer_owned_ip: Optional[str] = field(default=None)
    carrier_ip: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2NetworkInterfaceAttachment:
    kind: ClassVar[str] = "aws_ec2_network_interface_attachment"
    kind_display: ClassVar[str] = "AWS EC2 Network Interface Attachment"
    kind_description: ClassVar[str] = (
        "An attachment of a network interface to an EC2 instance, allowing the"
        " instance to communicate over the network."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "attach_time": S("AttachTime"),
        "attachment_id": S("AttachmentId"),
        "delete_on_termination": S("DeleteOnTermination"),
        "device_index": S("DeviceIndex"),
        "network_card_index": S("NetworkCardIndex"),
        "instance_id": S("InstanceId"),
        # "owner_id": S("InstanceOwnerId"),
        "status": S("Status"),
    }
    attach_time: Optional[datetime] = field(default=None)
    attachment_id: Optional[str] = field(default=None)
    delete_on_termination: Optional[bool] = field(default=None)
    device_index: Optional[int] = field(default=None)
    network_card_index: Optional[int] = field(default=None)
    instance_id: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2NetworkInterfacePrivateIpAddress:
    kind: ClassVar[str] = "aws_ec2_network_interface_private_ip_address"
    kind_display: ClassVar[str] = "AWS EC2 Network Interface Private IP Address"
    kind_description: ClassVar[str] = (
        "The private IP address assigned to a network interface of an Amazon EC2"
        " instance. This IP address is used for communication within the Amazon VPC"
        " (Virtual Private Cloud) network."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "association": S("Association") >> Bend(AwsEc2NetworkInterfaceAssociation.mapping),
        "primary": S("Primary"),
        "private_dns_name": S("PrivateDnsName"),
        "private_ip_address": S("PrivateIpAddress"),
    }
    association: Optional[AwsEc2NetworkInterfaceAssociation] = field(default=None)
    primary: Optional[bool] = field(default=None)
    private_dns_name: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2Tag:
    kind: ClassVar[str] = "aws_ec2_tag"
    kind_display: ClassVar[str] = "AWS EC2 Tag"
    kind_description: ClassVar[str] = (
        "EC2 tags are key-value pairs that can be assigned to EC2 instances, images,"
        " volumes, and other resources for easier management and organization."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"key": S("Key"), "value": S("Value")}
    key: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2NetworkInterface(EC2Taggable, AwsResource, BaseNetworkInterface):
    kind: ClassVar[str] = "aws_ec2_network_interface"
    kind_display: ClassVar[str] = "AWS EC2 Network Interface"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/v2/home?region={region}#NetworkInterface:networkInterfaceId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:network-interface/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An EC2 Network Interface is a virtual network interface that can be attached"
        " to EC2 instances in the AWS cloud, allowing for communication between"
        " instances and with external networks."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-network-interfaces", "NetworkInterfaces")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_vpc", "aws_ec2_subnet", "aws_ec2_instance", "aws_ec2_security_group"],
            "delete": ["aws_vpc", "aws_ec2_instance"],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("NetworkInterfaceId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "network_interface_type": S("InterfaceType"),
        "network_interface_status": S("Status"),
        "private_ips": S("PrivateIpAddresses", default=[]) >> ForallBend(S("PrivateIpAddress")),
        "public_ips": S("PrivateIpAddresses", default=[]) >> ForallBend(S("Association", "PublicIp")) >> StripNones(),
        "mac": S("MacAddress"),
        "v6_ips": S("Ipv6Addresses", default=[]) >> ForallBend(S("Ipv6Address")),
        "description": S("Description"),
        "nic_association": S("Association") >> Bend(AwsEc2NetworkInterfaceAssociation.mapping),
        "nic_attachment": S("Attachment") >> Bend(AwsEc2NetworkInterfaceAttachment.mapping),
        "nic_availability_zone": S("AvailabilityZone"),
        "nic_groups": S("Groups", default=[]) >> ForallBend(AwsEc2GroupIdentifier.mapping),
        "nic_outpost_arn": S("OutpostArn"),
        # "owner_id": S("OwnerId"),
        "nic_private_dns_name": S("PrivateDnsName"),
        "nic_private_ip_address": S("PrivateIpAddress"),
        "nic_private_ip_addresses": S("PrivateIpAddresses", default=[])
        >> ForallBend(AwsEc2NetworkInterfacePrivateIpAddress.mapping),
        "nic_ipv4_prefixes": S("Ipv4Prefixes", default=[]) >> ForallBend(S("Ipv4Prefix")),
        "nic_ipv6_prefixes": S("Ipv6Prefixes", default=[]) >> ForallBend(S("Ipv6Prefix")),
        "nic_requester_id": S("RequesterId"),
        "nic_requester_managed": S("RequesterManaged"),
        "nic_source_dest_check": S("SourceDestCheck"),
        "nic_subnet_id": S("SubnetId"),
        "nic_tag_set": S("TagSet", default=[]) >> ForallBend(AwsEc2Tag.mapping),
        "nic_deny_all_igw_traffic": S("DenyAllIgwTraffic"),
        "nic_ipv6_native": S("Ipv6Native"),
        "nic_ipv6_address": S("Ipv6Address"),
    }
    nic_association: Optional[AwsEc2NetworkInterfaceAssociation] = field(default=None)
    nic_attachment: Optional[AwsEc2NetworkInterfaceAttachment] = field(default=None, metadata=dict(ignore_history=True))
    nic_availability_zone: Optional[str] = field(default=None)
    nic_groups: List[AwsEc2GroupIdentifier] = field(factory=list)
    nic_outpost_arn: Optional[str] = field(default=None)
    nic_private_dns_name: Optional[str] = field(default=None)
    nic_private_ip_address: Optional[str] = field(default=None)
    nic_private_ip_addresses: List[AwsEc2NetworkInterfacePrivateIpAddress] = field(factory=list)
    nic_ipv4_prefixes: List[str] = field(factory=list)
    nic_ipv6_prefixes: List[str] = field(factory=list)
    nic_requester_id: Optional[str] = field(default=None)
    nic_requester_managed: Optional[bool] = field(default=None)
    nic_source_dest_check: Optional[bool] = field(default=None)
    nic_subnet_id: Optional[str] = field(default=None)
    nic_tag_set: List[AwsEc2Tag] = field(factory=list)
    nic_deny_all_igw_traffic: Optional[bool] = field(default=None)
    nic_ipv6_native: Optional[bool] = field(default=None)
    nic_ipv6_address: Optional[str] = field(default=None)

    def pre_cleanup(self, graph: Optional[Any] = None) -> bool:
        client = get_client(current_config(), self)
        if (attachment := self.nic_attachment) and (aid := attachment.attachment_id):
            try:
                client.call(
                    aws_service=self.api_spec.service,
                    action="detach-network-interface",
                    AttachmentId=aid,
                    Force=True,
                )
            except Exception as e:
                log.warning(f"Failed to detach network interface {self.id}: {e}")
                return False
        return True

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
        if subnet_id := source.get("SubnetId"):
            builder.add_edge(self, reverse=True, clazz=AwsEc2Subnet, id=subnet_id)
        if self.nic_attachment and (iid := self.nic_attachment.instance_id):
            builder.dependant_node(self, reverse=True, clazz=AwsEc2Instance, id=iid)
        for group in self.nic_groups:
            if gid := group.group_id:
                builder.add_edge(self, EdgeType.default, reverse=True, clazz=AwsEc2SecurityGroup, id=gid)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-network-interface",
            result_name=None,
            NetworkInterfaceId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-network-interface")]


# endregion

# region VPCs


@define(eq=False, slots=False)
class AwsEc2VpcCidrBlockState:
    kind: ClassVar[str] = "aws_vpc_cidr_block_state"
    kind_display: ClassVar[str] = "AWS VPC CIDR Block State"
    kind_description: ClassVar[str] = (
        "The state of a CIDR block in an Amazon Virtual Private Cloud (VPC) which"
        " provides networking functionality for Amazon Elastic Compute Cloud (EC2)"
        " instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"state": S("State"), "status_message": S("StatusMessage")}
    state: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2VpcIpv6CidrBlockAssociation:
    kind: ClassVar[str] = "aws_vpc_ipv6_cidr_block_association"
    kind_display: ClassVar[str] = "AWS VPC IPv6 CIDR Block Association"
    kind_description: ClassVar[str] = (
        "AWS VPC IPv6 CIDR Block Association represents the association between an"
        " Amazon Virtual Private Cloud (VPC) and an IPv6 CIDR block, enabling"
        " communication over IPv6 in the VPC."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "association_id": S("AssociationId"),
        "ipv6_cidr_block": S("Ipv6CidrBlock"),
        "ipv6_cidr_block_state": S("Ipv6CidrBlockState") >> Bend(AwsEc2VpcCidrBlockState.mapping),
        "network_border_group": S("NetworkBorderGroup"),
        "ipv6_pool": S("Ipv6Pool"),
    }
    association_id: Optional[str] = field(default=None)
    ipv6_cidr_block: Optional[str] = field(default=None)
    ipv6_cidr_block_state: Optional[AwsEc2VpcCidrBlockState] = field(default=None)
    network_border_group: Optional[str] = field(default=None)
    ipv6_pool: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2VpcCidrBlockAssociation:
    kind: ClassVar[str] = "aws_vpc_cidr_block_association"
    kind_display: ClassVar[str] = "AWS VPC CIDR Block Association"
    kind_description: ClassVar[str] = (
        "CIDR Block Association is used to associate a specific range of IP addresses"
        " (CIDR block) with a Virtual Private Cloud (VPC) in the AWS cloud. It allows"
        " the VPC to have a defined IP range for its resources and enables secure"
        " communication within the VPC."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "association_id": S("AssociationId"),
        "cidr_block": S("CidrBlock"),
        "cidr_block_state": S("CidrBlockState") >> Bend(AwsEc2VpcCidrBlockState.mapping),
    }
    association_id: Optional[str] = field(default=None)
    cidr_block: Optional[str] = field(default=None)
    cidr_block_state: Optional[AwsEc2VpcCidrBlockState] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2Vpc(EC2Taggable, AwsResource, BaseNetwork):
    kind: ClassVar[str] = "aws_vpc"
    kind_display: ClassVar[str] = "AWS VPC"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/vpcconsole/home?region={region}#VpcDetails:VpcId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:vpc/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS VPC stands for Amazon Virtual Private Cloud. It is a virtual network"
        " dedicated to your AWS account, allowing you to launch AWS resources in a"
        " defined virtual network environment."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-vpcs", "Vpcs")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("VpcId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name").or_else(S("VpcId")),
        "vpc_cidr_block": S("CidrBlock"),
        "vpc_dhcp_options_id": S("DhcpOptionsId"),
        "vpc_state": S("State"),
        # "owner_id": S("OwnerId"),
        "vpc_instance_tenancy": S("InstanceTenancy"),
        "vpc_ipv6_cidr_block_association_set": S("Ipv6CidrBlockAssociationSet", default=[])
        >> ForallBend(AwsEc2VpcIpv6CidrBlockAssociation.mapping),
        "vpc_cidr_block_association_set": S("CidrBlockAssociationSet", default=[])
        >> ForallBend(AwsEc2VpcCidrBlockAssociation.mapping),
        "vpc_is_default": S("IsDefault"),
    }
    vpc_cidr_block: Optional[str] = field(default=None)
    vpc_dhcp_options_id: Optional[str] = field(default=None)
    vpc_state: Optional[str] = field(default=None)
    vpc_instance_tenancy: Optional[str] = field(default=None)
    vpc_ipv6_cidr_block_association_set: List[AwsEc2VpcIpv6CidrBlockAssociation] = field(factory=list)
    vpc_cidr_block_association_set: List[AwsEc2VpcCidrBlockAssociation] = field(factory=list)
    vpc_is_default: Optional[bool] = field(default=None)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        if self.vpc_is_default:
            log_msg = f"Not removing the default VPC {self.id} - aborting delete request"
            self.log(log_msg)
            return False
        client.call(aws_service=self.api_spec.service, action="delete-vpc", result_name=None, VpcId=self.id)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-vpc")]


# endregion


# region VPC Peering Connections
@define(eq=False, slots=False)
class AwsEc2VpcPeeringConnectionOptionsDescription:
    kind: ClassVar[str] = "aws_vpc_peering_connection_options_description"
    kind_display: ClassVar[str] = "AWS VPC Peering Connection Options Description"
    kind_description: ClassVar[str] = (
        "VPC Peering Connection Options Description provides the different options"
        " and configurations for establishing a peering connection between two Amazon"
        " Virtual Private Clouds (VPCs). This allows communication between the VPCs"
        " using private IP addresses."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "allow_dns_resolution_from_remote_vpc": S("AllowDnsResolutionFromRemoteVpc"),
        "allow_egress_from_local_classic_link_to_remote_vpc": S("AllowEgressFromLocalClassicLinkToRemoteVpc"),
        "allow_egress_from_local_vpc_to_remote_classic_link": S("AllowEgressFromLocalVpcToRemoteClassicLink"),
    }
    allow_dns_resolution_from_remote_vpc: Optional[bool] = field(default=None)
    allow_egress_from_local_classic_link_to_remote_vpc: Optional[bool] = field(default=None)
    allow_egress_from_local_vpc_to_remote_classic_link: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2VpcPeeringConnectionVpcInfo:
    kind: ClassVar[str] = "aws_vpc_peering_connection_vpc_info"
    kind_display: ClassVar[str] = "AWS VPC Peering Connection VPC Info"
    kind_description: ClassVar[str] = (
        "VPC Peering Connection VPC Info provides information about the virtual"
        " private cloud (VPC) involved in a VPC peering connection in Amazon Web"
        " Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cidr_block": S("CidrBlock"),
        "ipv6_cidr_block_set": S("Ipv6CidrBlockSet", default=[]) >> ForallBend(S("Ipv6CidrBlock")),
        "cidr_block_set": S("CidrBlockSet", default=[]) >> ForallBend(S("CidrBlock")),
        "owner_id": S("OwnerId"),
        "peering_options": S("PeeringOptions") >> Bend(AwsEc2VpcPeeringConnectionOptionsDescription.mapping),
        "vpc_id": S("VpcId"),
        "region": S("Region"),
    }
    cidr_block: Optional[str] = field(default=None)
    ipv6_cidr_block_set: List[str] = field(factory=list)
    cidr_block_set: List[str] = field(factory=list)
    owner_id: Optional[str] = field(default=None)
    peering_options: Optional[AwsEc2VpcPeeringConnectionOptionsDescription] = field(default=None)
    vpc_id: Optional[str] = field(default=None)
    region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2VpcPeeringConnectionStateReason:
    kind: ClassVar[str] = "aws_vpc_peering_connection_state_reason"
    kind_display: ClassVar[str] = "AWS VPC Peering Connection State Reason"
    kind_description: ClassVar[str] = (
        "This resource represents the reason for the current state of a VPC peering"
        " connection in Amazon Web Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "message": S("Message")}
    code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2VpcPeeringConnection(EC2Taggable, AwsResource, BasePeeringConnection):
    kind: ClassVar[str] = "aws_vpc_peering_connection"
    kind_display: ClassVar[str] = "AWS VPC Peering Connection"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/vpcconsole/home?region={region}#PeeringConnectionDetails:vpcPeeringConnectionId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:vpc-peering-connection/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "VPC Peering Connection is a networking connection between two Amazon Virtual"
        " Private Clouds (VPCs) that enables you to route traffic between them using"
        " private IP addresses."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "describe-vpc-peering-connections", "VpcPeeringConnections"
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_vpc"], "delete": ["aws_vpc"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("VpcPeeringConnectionId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": (S("Tags", default=[]) >> TagsValue("Name")).or_else(S("VpcPeeringConnectionId")),
        "connection_accepter_vpc_info": S("AccepterVpcInfo") >> Bend(AwsEc2VpcPeeringConnectionVpcInfo.mapping),
        "connection_expiration_time": S("ExpirationTime"),
        "connection_requester_vpc_info": S("RequesterVpcInfo") >> Bend(AwsEc2VpcPeeringConnectionVpcInfo.mapping),
        "peering_connection_status": S("Status") >> Bend(AwsEc2VpcPeeringConnectionStateReason.mapping),
    }
    connection_accepter_vpc_info: Optional[AwsEc2VpcPeeringConnectionVpcInfo] = field(default=None)
    connection_expiration_time: Optional[datetime] = field(default=None)
    connection_requester_vpc_info: Optional[AwsEc2VpcPeeringConnectionVpcInfo] = field(default=None)
    peering_connection_status: Optional[AwsEc2VpcPeeringConnectionStateReason] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.connection_requester_vpc_info and (vpc_id := self.connection_requester_vpc_info.vpc_id):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
        if self.connection_accepter_vpc_info and (vpc_id := self.connection_accepter_vpc_info.vpc_id):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-vpc-peering-connection",
            result_name=None,
            VpcPeeringConnectionId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "delete-vpc-peering-connection"),
        ]


# endregion

# region VPC Endpoints


@define(eq=False, slots=False)
class AwsEc2DnsEntry:
    kind: ClassVar[str] = "aws_ec2_dns_entry"
    kind_display: ClassVar[str] = "AWS EC2 DNS Entry"
    kind_description: ClassVar[str] = (
        "An EC2 DNS Entry is a domain name assigned to an Amazon EC2 instance,"
        " allowing users to access the instance's applications using a human-readable"
        " name instead of its IP address."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"dns_name": S("DnsName"), "hosted_zone_id": S("HostedZoneId")}
    dns_name: Optional[str] = field(default=None)
    hosted_zone_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2LastError:
    kind: ClassVar[str] = "aws_ec2_last_error"
    kind_display: ClassVar[str] = "AWS EC2 Last Error"
    kind_description: ClassVar[str] = (
        "The AWS EC2 Last Error is a description of the last error occurred in"
        " relation to an EC2 instance. It helps in troubleshooting and identifying"
        " issues with the EC2 instances in Amazon's cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"message": S("Message"), "code": S("Code")}
    message: Optional[str] = field(default=None)
    code: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2VpcEndpoint(EC2Taggable, AwsResource, BaseEndpoint):
    kind: ClassVar[str] = "aws_vpc_endpoint"
    kind_display: ClassVar[str] = "AWS VPC Endpoint"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/vpcconsole/home?region={region}#Endpoints:vpcEndpointId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:vpc-endpoint/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "VPC Endpoints enable secure and private communication between your VPC and"
        " supported AWS services without using public IPs or requiring traffic to"
        " traverse the internet."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-vpc-endpoints", "VpcEndpoints")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_vpc", "aws_ec2_route_table", "aws_ec2_subnet", "aws_ec2_security_group"],
            "delete": [
                "aws_ec2_network_interface",
                "aws_vpc",
                "aws_ec2_route_table",
                "aws_ec2_subnet",
                "aws_ec2_security_group",
            ],
        },
        "successors": {
            "default": ["aws_ec2_network_interface"],
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("VpcEndpointId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "vpc_endpoint_type": S("VpcEndpointType"),
        "endpoint_service_name": S("ServiceName"),
        "endpoint_state": S("State"),
        "endpoint_policy_document": S("PolicyDocument"),
        "endpoint_ip_address_type": S("IpAddressType"),
        "endpoint_dns_options": S("DnsOptions", "DnsRecordIpType"),
        "endpoint_private_dns_enabled": S("PrivateDnsEnabled"),
        "endpoint_requester_managed": S("RequesterManaged"),
        "endpoint_dns_entries": S("DnsEntries", default=[]) >> ForallBend(AwsEc2DnsEntry.mapping),
        "endpoint_creation_timestamp": S("CreationTimestamp"),
        "endpoint_owner_id": S("OwnerId"),
        "endpoint_last_error": S("LastError") >> Bend(AwsEc2LastError.mapping),
    }
    vpc_endpoint_type: Optional[str] = field(default=None)
    endpoint_service_name: Optional[str] = field(default=None)
    endpoint_state: Optional[str] = field(default=None)
    endpoint_policy_document: Optional[str] = field(default=None)
    endpoint_ip_address_type: Optional[str] = field(default=None)
    endpoint_dns_options: Optional[str] = field(default=None)
    endpoint_private_dns_enabled: Optional[bool] = field(default=None)
    endpoint_requester_managed: Optional[bool] = field(default=None)
    endpoint_dns_entries: List[AwsEc2DnsEntry] = field(factory=list)
    endpoint_creation_timestamp: Optional[datetime] = field(default=None)
    endpoint_owner_id: Optional[str] = field(default=None)
    endpoint_last_error: Optional[AwsEc2LastError] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)

        for rt in source.get("RouteTableIds", []):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2RouteTable, id=rt)

        for sn in source.get("SubnetIds", []):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=sn)

        for nic in source.get("NetworkInterfaceIds", []):
            builder.dependant_node(self, clazz=AwsEc2NetworkInterface, id=nic)

        for group in source.get("Groups", []):
            if group_id := group.get("GroupId"):
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=group_id
                )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-vpc-endpoints", result_name=None, VpcEndpointIds=[self.id]
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-vpc-endpoints")]


# endregion


# region Subnets
@define(eq=False, slots=False)
class AwsEc2SubnetCidrBlockState:
    kind: ClassVar[str] = "aws_ec2_subnet_cidr_block_state"
    kind_display: ClassVar[str] = "AWS EC2 Subnet CIDR Block State"
    kind_description: ClassVar[str] = (
        "The AWS EC2 Subnet CIDR Block State is an indication of the status of a CIDR block within a subnet,"
        " such as whether it's active, pending, or in some error state, along with a message that may provide"
        " additional details about that status."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"state": S("State"), "status_message": S("StatusMessage")}
    state: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2SubnetIpv6CidrBlockAssociation:
    kind: ClassVar[str] = "aws_ec2_subnet_ipv6_cidr_block_association"
    kind_display: ClassVar[str] = "AWS EC2 Subnet IPv6 CIDR Block Association"
    kind_description: ClassVar[str] = (
        "IPv6 CIDR Block Association is used to associate an IPv6 CIDR block with a"
        " subnet in Amazon EC2, enabling the subnet to use IPv6 addresses."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "association_id": S("AssociationId"),
        "ipv6_cidr_block": S("Ipv6CidrBlock"),
        "ipv6_cidr_block_state": S("Ipv6CidrBlockState") >> Bend(AwsEc2SubnetCidrBlockState.mapping),
    }
    association_id: Optional[str] = field(default=None)
    ipv6_cidr_block: Optional[str] = field(default=None)
    ipv6_cidr_block_state: Optional[AwsEc2SubnetCidrBlockState] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2PrivateDnsNameOptionsOnLaunch:
    kind: ClassVar[str] = "aws_ec2_private_dns_name_options_on_launch"
    kind_display: ClassVar[str] = "AWS EC2 Private DNS Name Options on Launch"
    kind_description: ClassVar[str] = (
        "The option to enable or disable assigning a private DNS name to an Amazon EC2 instance on launch."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname_type": S("HostnameType"),
        "enable_resource_name_dns_a_record": S("EnableResourceNameDnsARecord"),
        "enable_resource_name_dns_aaaa_record": S("EnableResourceNameDnsAAAARecord"),
    }
    hostname_type: Optional[str] = field(default=None)
    enable_resource_name_dns_a_record: Optional[bool] = field(default=None)
    enable_resource_name_dns_aaaa_record: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2Subnet(EC2Taggable, AwsResource, BaseSubnet):
    kind: ClassVar[str] = "aws_ec2_subnet"
    kind_display: ClassVar[str] = "AWS EC2 Subnet"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/vpcconsole/home?region={region}#SubnetDetails:subnetId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:subnet/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An AWS EC2 Subnet is a logical subdivision of a VPC (Virtual Private Cloud)"
        " in Amazon's cloud, allowing users to group resources and control network"
        " access within a specific network segment."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-subnets", "Subnets")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_vpc"], "delete": ["aws_vpc"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("SubnetId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": (S("Tags", default=[]) >> TagsValue("Name")).or_else(S("SubnetId")),
        "ctime": K(None),
        "mtime": K(None),
        "atime": K(None),
        "subnet_availability_zone": S("AvailabilityZone"),
        "subnet_availability_zone_id": S("AvailabilityZoneId"),
        "subnet_available_ip_address_count": S("AvailableIpAddressCount"),
        "subnet_cidr_block": S("CidrBlock"),
        "subnet_default_for_az": S("DefaultForAz"),
        "subnet_enable_lni_at_device_index": S("EnableLniAtDeviceIndex"),
        "subnet_map_public_ip_on_launch": S("MapPublicIpOnLaunch"),
        "subnet_map_customer_owned_ip_on_launch": S("MapCustomerOwnedIpOnLaunch"),
        "subnet_customer_owned_ipv4_pool": S("CustomerOwnedIpv4Pool"),
        "subnet_state": S("State"),
        # "subnet_vpc_id": S("VpcId"),
        # "owner_id": S("OwnerId"),
        "subnet_assign_ipv6_address_on_creation": S("AssignIpv6AddressOnCreation"),
        "subnet_ipv6_cidr_block_association_set": S("Ipv6CidrBlockAssociationSet", default=[])
        >> ForallBend(AwsEc2SubnetIpv6CidrBlockAssociation.mapping),
        "arn": S("SubnetArn"),
        "subnet_outpost_arn": S("OutpostArn"),
        "subnet_enable_dns64": S("EnableDns64"),
        "subnet_ipv6_native": S("Ipv6Native"),
        "subnet_private_dns_name_options_on_launch": S("PrivateDnsNameOptionsOnLaunch")
        >> Bend(AwsEc2PrivateDnsNameOptionsOnLaunch.mapping),
    }
    subnet_availability_zone: Optional[str] = field(default=None)
    subnet_availability_zone_id: Optional[str] = field(default=None)
    subnet_available_ip_address_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    subnet_cidr_block: Optional[str] = field(default=None)
    subnet_default_for_az: Optional[bool] = field(default=None)
    subnet_enable_lni_at_device_index: Optional[int] = field(default=None)
    subnet_map_public_ip_on_launch: Optional[bool] = field(default=None)
    subnet_map_customer_owned_ip_on_launch: Optional[bool] = field(default=None)
    subnet_customer_owned_ipv4_pool: Optional[str] = field(default=None)
    subnet_state: Optional[str] = field(default=None)
    subnet_assign_ipv6_address_on_creation: Optional[bool] = field(default=None)
    subnet_ipv6_cidr_block_association_set: List[AwsEc2SubnetIpv6CidrBlockAssociation] = field(factory=list)
    subnet_outpost_arn: Optional[str] = field(default=None)
    subnet_enable_dns64: Optional[bool] = field(default=None)
    subnet_ipv6_native: Optional[bool] = field(default=None)
    subnet_private_dns_name_options_on_launch: Optional[AwsEc2PrivateDnsNameOptionsOnLaunch] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-subnet", result_name=None, SubnetId=self.id)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-subnet")]


# endregion


# region Security Groups
@define(eq=False, slots=False)
class AwsEc2IpRange:
    kind: ClassVar[str] = "aws_ec2_ip_range"
    kind_display: ClassVar[str] = "AWS EC2 IP Range"
    kind_description: ClassVar[str] = (
        "An IP range in the Amazon EC2 service that is used to define a range of IP"
        " addresses available for EC2 instances. It allows users to control inbound"
        " and outbound traffic to their virtual servers within the specified IP range."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"cidr_ip": S("CidrIp"), "description": S("Description")}
    cidr_ip: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2Ipv6Range:
    kind: ClassVar[str] = "aws_ec2_ipv6_range"
    kind_display: ClassVar[str] = "AWS EC2 IPv6 Range"
    kind_description: ClassVar[str] = (
        "AWS EC2 IPv6 Range is a range of IPv6 addresses that can be assigned to EC2"
        " instances in the Amazon Web Services cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"cidr_ipv6": S("CidrIpv6"), "description": S("Description")}
    cidr_ipv6: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2PrefixListId:
    kind: ClassVar[str] = "aws_ec2_prefix_list_id"
    kind_display: ClassVar[str] = "AWS EC2 Prefix List ID"
    kind_description: ClassVar[str] = (
        "A prefix list is a set of CIDR blocks that can be used as a firewall rule in"
        " AWS VPC to allow or deny traffic."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"description": S("Description"), "prefix_list_id": S("PrefixListId")}
    description: Optional[str] = field(default=None)
    prefix_list_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2UserIdGroupPair:
    kind: ClassVar[str] = "aws_ec2_user_id_group_pair"
    kind_display: ClassVar[str] = "AWS EC2 User ID Group Pair"
    kind_description: ClassVar[str] = (
        "The AWS EC2 User ID Group Pair is a networking configuration setting within EC2 that defines"
        " a relationship between a user's account and a security group. It typically includes information"
        " about the security group and its permissions, and is used for setting up network access controls"
        " in VPC peering connections."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "description": S("Description"),
        "group_id": S("GroupId"),
        "group_name": S("GroupName"),
        "peering_status": S("PeeringStatus"),
        "user_id": S("UserId"),
        "vpc_id": S("VpcId"),
        "vpc_peering_connection_id": S("VpcPeeringConnectionId"),
    }
    description: Optional[str] = field(default=None)
    group_id: Optional[str] = field(default=None)
    group_name: Optional[str] = field(default=None)
    peering_status: Optional[str] = field(default=None)
    user_id: Optional[str] = field(default=None)
    vpc_id: Optional[str] = field(default=None)
    vpc_peering_connection_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2IpPermission:
    kind: ClassVar[str] = "aws_ec2_ip_permission"
    kind_display: ClassVar[str] = "AWS EC2 IP Permission"
    kind_description: ClassVar[str] = (
        "IP Permission in AWS EC2 allows you to control inbound and outbound traffic"
        " to an EC2 instance based on IP addresses."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "from_port": S("FromPort"),
        "ip_protocol": S("IpProtocol"),
        "ip_ranges": S("IpRanges", default=[]) >> ForallBend(AwsEc2IpRange.mapping),
        "ipv6_ranges": S("Ipv6Ranges", default=[]) >> ForallBend(AwsEc2Ipv6Range.mapping),
        "prefix_list_ids": S("PrefixListIds", default=[]) >> ForallBend(AwsEc2PrefixListId.mapping),
        "to_port": S("ToPort"),
        "user_id_group_pairs": S("UserIdGroupPairs", default=[]) >> ForallBend(AwsEc2UserIdGroupPair.mapping),
    }
    from_port: Optional[int] = field(default=None)
    ip_protocol: Optional[str] = field(default=None)
    ip_ranges: List[AwsEc2IpRange] = field(factory=list)
    ipv6_ranges: List[AwsEc2Ipv6Range] = field(factory=list)
    prefix_list_ids: List[AwsEc2PrefixListId] = field(factory=list)
    to_port: Optional[int] = field(default=None)
    user_id_group_pairs: List[AwsEc2UserIdGroupPair] = field(factory=list)


@define(eq=False, slots=False)
class AwsEc2SecurityGroup(EC2Taggable, AwsResource, BaseSecurityGroup):
    kind: ClassVar[str] = "aws_ec2_security_group"
    kind_display: ClassVar[str] = "AWS EC2 Security Group"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/v2/home?region={region}#SecurityGroup:groupId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:security-group/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An EC2 Security Group acts as a virtual firewall that controls inbound and"
        " outbound traffic for EC2 instances within a VPC."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-security-groups", "SecurityGroups")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_vpc"], "delete": ["aws_vpc"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("GroupId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("GroupName"),
        "description": S("Description"),
        "group_ip_permissions": S("IpPermissions", default=[]) >> ForallBend(AwsEc2IpPermission.mapping),
        # "owner_id": S("OwnerId"),
        "group_ip_permissions_egress": S("IpPermissionsEgress", default=[]) >> ForallBend(AwsEc2IpPermission.mapping),
    }
    description: Optional[str] = field(default=None)
    group_ip_permissions: List[AwsEc2IpPermission] = field(factory=list)
    group_ip_permissions_egress: List[AwsEc2IpPermission] = field(factory=list)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        remove_ingress = []
        remove_egress = []

        security_groups = client.list(
            aws_service=self.api_spec.service,
            action="describe-security-groups",
            result_name="SecurityGroups",
            GroupIds=[self.id],
            expected_errors=["InvalidGroup.NotFound"],
        )

        security_group: Json = next(iter(security_groups), {})

        for permission in security_group.get("IpPermissions", []):
            if "UserIdGroupPairs" in permission and len(permission["UserIdGroupPairs"]) > 0:
                p = copy.deepcopy(permission)
                remove_ingress.append(p)

        for permission in security_group.get("IpPermissionsEgress", []):
            if "UserIdGroupPairs" in permission and len(permission["UserIdGroupPairs"]) > 0:
                p = copy.deepcopy(permission)
                remove_egress.append(p)

        if len(remove_ingress) > 0:
            client.call(
                aws_service=self.api_spec.service,
                action="revoke-security-group-ingress",
                result_name=None,
                IpPermissions=remove_ingress,
                GroupId=self.id,
            )

        if len(remove_egress) > 0:
            client.call(
                aws_service=self.api_spec.service,
                action="revoke-security-group-egress",
                result_name=None,
                IpPermissions=remove_egress,
                GroupId=self.id,
            )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-security-group",
            result_name=None,
            GroupId=self.id,
            expected_errors=["InvalidGroup.NotFound"],
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "revoke-security-group-ingress"),
            AwsApiSpec(service_name, "revoke-security-group-egress"),
            AwsApiSpec(service_name, "delete-security-group"),
        ]


# endregion


# region Nat Gateways
@define(eq=False, slots=False)
class AwsEc2NatGatewayAddress:
    kind: ClassVar[str] = "aws_ec2_nat_gateway_address"
    kind_display: ClassVar[str] = "AWS EC2 NAT Gateway Address"
    kind_description: ClassVar[str] = (
        "The NAT Gateway Address is a public IP address assigned to an AWS EC2 NAT"
        " Gateway, which allows instances within a private subnet to communicate with"
        " the internet."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "allocation_id": S("AllocationId"),
        "network_interface_id": S("NetworkInterfaceId"),
        "private_ip": S("PrivateIp"),
        "public_ip": S("PublicIp"),
    }
    allocation_id: Optional[str] = field(default=None)
    network_interface_id: Optional[str] = field(default=None)
    private_ip: Optional[str] = field(default=None)
    public_ip: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2ProvisionedBandwidth:
    kind: ClassVar[str] = "aws_ec2_provisioned_bandwidth"
    kind_display: ClassVar[str] = "AWS EC2 Provisioned Bandwidth"
    kind_description: ClassVar[str] = (
        "AWS EC2 Provisioned Bandwidth refers to the amount of bandwidth that an AWS EC2 instance"
        " is guaranteed to have based on its instance type. This provisioned capacity is dedicated"
        " to the instance for network resources, ensuring consistent performance for network-intensive applications."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "provision_time": S("ProvisionTime"),
        "provisioned": S("Provisioned"),
        "request_time": S("RequestTime"),
        "requested": S("Requested"),
        "status": S("Status"),
    }
    provision_time: Optional[datetime] = field(default=None)
    provisioned: Optional[str] = field(default=None)
    request_time: Optional[datetime] = field(default=None)
    requested: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2NatGateway(EC2Taggable, AwsResource, BaseGateway):
    kind: ClassVar[str] = "aws_ec2_nat_gateway"
    kind_display: ClassVar[str] = "AWS EC2 NAT Gateway"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/vpcconsole/home?region={region}#NatGatewayDetails:natGatewayId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:nat-gateway/{id}"}  # fmt: skip

    kind_description: ClassVar[str] = (
        "A NAT Gateway is a fully managed network address translation (NAT) service"
        " provided by Amazon Web Services (AWS) that allows instances within a private"
        " subnet to connect outbound to the Internet while also preventing inbound"
        " connections from the outside."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-nat-gateways", "NatGateways")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_ec2_network_interface", "aws_vpc", "aws_ec2_subnet"]},
        "successors": {"default": ["aws_vpc", "aws_ec2_subnet", "aws_ec2_network_interface"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("NatGatewayId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreateTime"),
        "nat_delete_time": S("DeleteTime"),
        "nat_failure_code": S("FailureCode"),
        "nat_failure_message": S("FailureMessage"),
        "nat_gateway_addresses": S("NatGatewayAddresses", default=[]) >> ForallBend(AwsEc2NatGatewayAddress.mapping),
        "nat_provisioned_bandwidth": S("ProvisionedBandwidth") >> Bend(AwsEc2ProvisionedBandwidth.mapping),
        "nat_state": S("State"),
        "nat_connectivity_type": S("ConnectivityType"),
    }
    nat_delete_time: Optional[datetime] = field(default=None)
    nat_failure_code: Optional[str] = field(default=None)
    nat_failure_message: Optional[str] = field(default=None)
    nat_gateway_addresses: List[AwsEc2NatGatewayAddress] = field(factory=list)
    nat_provisioned_bandwidth: Optional[AwsEc2ProvisionedBandwidth] = field(default=None)
    nat_state: Optional[str] = field(default=None)
    nat_connectivity_type: Optional[str] = field(default=None)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        nat_gateways = {
            nat_gateway.id: nat_gateway
            for nat_gateway in builder.nodes(clazz=AwsEc2NatGateway)
            if nat_gateway.region().id == builder.region.id
        }
        queries = []
        delta = builder.metrics_delta
        start = builder.metrics_start
        now = builder.created_at

        for nat_g_id in nat_gateways:
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric,
                        namespace="AWS/NATGateway",
                        period=delta,
                        ref_id=nat_g_id,
                        stat=stat,
                        unit="Count",
                        NatGatewayId=nat_g_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for metric in [
                        "ActiveConnectionCount",
                        "ConnectionAttemptCount",
                        "ConnectionEstablishedCount",
                        "ErrorPortAllocation",
                        "IdleTimeoutCount",
                        "PacketsDropCount",
                        "PacketsInFromDestination",
                        "PacketsInFromSource",
                        "PacketsOutToDestination",
                        "PacketsOutToSource",
                    ]
                ]
            )
            queries.extend(
                [
                    AwsCloudwatchQuery.create(
                        metric_name=metric,
                        namespace="AWS/NATGateway",
                        period=delta,
                        ref_id=nat_g_id,
                        stat=stat,
                        unit="Bytes",
                        NatGatewayId=nat_g_id,
                    )
                    for stat in ["Minimum", "Average", "Maximum"]
                    for metric in [
                        "BytesInFromDestination",
                        "BytesInFromSource",
                        "BytesOutToDestination",
                        "BytesOutToSource",
                    ]
                ]
            )

        metric_normalizers = {
            "ActiveConnectionCount": MetricNormalization(
                metric_name=MetricName.ActiveConnection,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ConnectionAttemptCount": MetricNormalization(
                metric_name=MetricName.ConnectionAttemptCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ConnectionEstablishedCount": MetricNormalization(
                metric_name=MetricName.ConnectionEstablishedCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "ErrorPortAllocation": MetricNormalization(
                metric_name=MetricName.ErrorPortAllocation,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "IdleTimeoutCount": MetricNormalization(
                metric_name=MetricName.IdleTimeoutCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "PacketsDropCount": MetricNormalization(
                metric_name=MetricName.PacketsDropCount,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "PacketsInFromDestination": MetricNormalization(
                metric_name=MetricName.PacketsInFromDestination,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "PacketsInFromSource": MetricNormalization(
                metric_name=MetricName.PacketsInFromSource,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "PacketsOutToDestination": MetricNormalization(
                metric_name=MetricName.PacketsOutToDestination,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "PacketsOutToSource": MetricNormalization(
                metric_name=MetricName.PacketsOutToSource,
                unit=MetricUnit.Count,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "BytesInFromDestination": MetricNormalization(
                metric_name=MetricName.BytesInFromDestination,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "BytesInFromSource": MetricNormalization(
                metric_name=MetricName.BytesInFromSource,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "BytesOutToDestination": MetricNormalization(
                metric_name=MetricName.BytesOutToDestination,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
            "BytesOutToSource": MetricNormalization(
                metric_name=MetricName.BytesOutToSource,
                unit=MetricUnit.Bytes,
                normalize_value=lambda x: round(x, ndigits=4),
            ),
        }

        cloudwatch_result = AwsCloudwatchMetricData.query_for(builder, queries, start, now)

        update_resource_metrics(nat_gateways, cloudwatch_result, metric_normalizers)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
        if subnet_id := source.get("SubnetId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet_id)
        for address in self.nat_gateway_addresses:
            if network_interface_id := address.network_interface_id:
                builder.dependant_node(self, clazz=AwsEc2NetworkInterface, id=network_interface_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-nat-gateway", result_name=None, NatGatewayId=self.id
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-nat-gateway")]


# endregion


# region Internet Gateways
@define(eq=False, slots=False)
class AwsEc2InternetGatewayAttachment:
    kind: ClassVar[str] = "aws_ec2_internet_gateway_attachment"
    kind_display: ClassVar[str] = "AWS EC2 Internet Gateway Attachment"
    kind_description: ClassVar[str] = (
        "EC2 Internet Gateway Attachment is a resource that represents the attachment"
        " of an Internet Gateway to a VPC in Amazon's cloud, enabling outbound"
        " internet access for instances in the VPC."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"state": S("State"), "vpc_id": S("VpcId")}
    state: Optional[str] = field(default=None)
    vpc_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2InternetGateway(EC2Taggable, AwsResource, BaseGateway):
    kind: ClassVar[str] = "aws_ec2_internet_gateway"
    kind_display: ClassVar[str] = "AWS EC2 Internet Gateway"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/vpc/home?region={region}#InternetGateway:internetGatewayId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:internet-gateway/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An Internet Gateway is a horizontally scalable, redundant, and highly"
        " available VPC component that allows communication between instances in your"
        " VPC and the internet."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-internet-gateways", "InternetGateways")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_vpc"], "delete": ["aws_vpc"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("InternetGatewayId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": (S("Tags", default=[]) >> TagsValue("Name")).or_else(S("InternetGatewayId")),
        "gateway_attachments": S("Attachments", default=[]) >> ForallBend(AwsEc2InternetGatewayAttachment.mapping),
        # "owner_id": S("OwnerId"),
    }
    gateway_attachments: List[AwsEc2InternetGatewayAttachment] = field(factory=list)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        for attachment in self.gateway_attachments:
            if vpc_id := attachment.vpc_id:
                builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        for predecessor in self.predecessors(graph=graph, edge_type=EdgeType.delete):
            if isinstance(predecessor, AwsEc2Vpc):
                log_msg = f"Detaching {predecessor.kind} {predecessor.dname}"
                self.log(log_msg)
                client.call(
                    aws_service=self.api_spec.service,
                    action="detach-internet-gateway",
                    result_name=None,
                    InternetGatewayId=self.id,
                    VpcId=predecessor.id,
                    expected_errors=["Gateway.NotAttached"],
                )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-internet-gateway",
            result_name=None,
            InternetGatewayId=self.id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "detach-internet-gateway"),
            AwsApiSpec(service_name, "delete-internet-gateway"),
        ]


# endregion


# region Route Tables
@define(eq=False, slots=False)
class AwsEc2RouteTableAssociationState:
    kind: ClassVar[str] = "aws_ec2_route_table_association_state"
    kind_display: ClassVar[str] = "AWS EC2 Route Table Association State"
    kind_description: ClassVar[str] = (
        "Route Table Association State represents the state of association between a"
        " subnet and a route table in Amazon EC2."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"state": S("State"), "status_message": S("StatusMessage")}
    state: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2RouteTableAssociation:
    kind: ClassVar[str] = "aws_ec2_route_table_association"
    kind_display: ClassVar[str] = "AWS EC2 Route Table Association"
    kind_description: ClassVar[str] = (
        "A Route Table Association is used to associate a route table with a subnet"
        " in Amazon EC2, allowing for traffic routing within the virtual private cloud"
        " (VPC)"
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "main": S("Main"),
        "route_table_association_id": S("RouteTableAssociationId"),
        "route_table_id": S("RouteTableId"),
        "subnet_id": S("SubnetId"),
        "gateway_id": S("GatewayId"),
        "association_state": S("AssociationState") >> Bend(AwsEc2RouteTableAssociationState.mapping),
    }
    main: Optional[bool] = field(default=None)
    route_table_association_id: Optional[str] = field(default=None)
    route_table_id: Optional[str] = field(default=None)
    subnet_id: Optional[str] = field(default=None)
    gateway_id: Optional[str] = field(default=None)
    association_state: Optional[AwsEc2RouteTableAssociationState] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2Route:
    kind: ClassVar[str] = "aws_ec2_route"
    kind_display: ClassVar[str] = "AWS EC2 Route"
    kind_description: ClassVar[str] = (
        "Routes in AWS EC2 are used to direct network traffic from one subnet to"
        " another, allowing communication between different instances and networks"
        " within the Amazon EC2 service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "destination_cidr_block": S("DestinationCidrBlock"),
        "destination_ipv6_cidr_block": S("DestinationIpv6CidrBlock"),
        "destination_prefix_list_id": S("DestinationPrefixListId"),
        "egress_only_internet_gateway_id": S("EgressOnlyInternetGatewayId"),
        "gateway_id": S("GatewayId"),
        "instance_id": S("InstanceId"),
        "instance_owner_id": S("InstanceOwnerId"),
        "nat_gateway_id": S("NatGatewayId"),
        "transit_gateway_id": S("TransitGatewayId"),
        "local_gateway_id": S("LocalGatewayId"),
        "carrier_gateway_id": S("CarrierGatewayId"),
        "network_interface_id": S("NetworkInterfaceId"),
        "origin": S("Origin"),
        "state": S("State"),
        "vpc_peering_connection_id": S("VpcPeeringConnectionId"),
        "core_network_arn": S("CoreNetworkArn"),
    }
    destination_cidr_block: Optional[str] = field(default=None)
    destination_ipv6_cidr_block: Optional[str] = field(default=None)
    destination_prefix_list_id: Optional[str] = field(default=None)
    egress_only_internet_gateway_id: Optional[str] = field(default=None)
    gateway_id: Optional[str] = field(default=None)
    instance_id: Optional[str] = field(default=None)
    instance_owner_id: Optional[str] = field(default=None)
    nat_gateway_id: Optional[str] = field(default=None)
    transit_gateway_id: Optional[str] = field(default=None)
    local_gateway_id: Optional[str] = field(default=None)
    carrier_gateway_id: Optional[str] = field(default=None)
    network_interface_id: Optional[str] = field(default=None)
    origin: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    vpc_peering_connection_id: Optional[str] = field(default=None)
    core_network_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2RouteTable(EC2Taggable, AwsResource, BaseRoutingTable):
    kind: ClassVar[str] = "aws_ec2_route_table"
    kind_display: ClassVar[str] = "AWS EC2 Route Table"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/vpcconsole/home?region={region}#RouteTableDetails:RouteTableId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:route-table/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "EC2 Route Tables are used to determine where network traffic is directed"
        " within a Virtual Private Cloud (VPC) in Amazon's cloud infrastructure."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-route-tables", "RouteTables")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_vpc"], "delete": ["aws_vpc"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("RouteTableId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": (S("Tags", default=[]) >> TagsValue("Name")).or_else(S("RouteTableId")),
        "route_table_associations": S("Associations", default=[]) >> ForallBend(AwsEc2RouteTableAssociation.mapping),
        "route_table_propagating_vgws": S("PropagatingVgws", default=[]) >> ForallBend(S("GatewayId")),
        "route_table_routes": S("Routes", default=[]) >> ForallBend(AwsEc2Route.mapping),
        # "route_table_vpc_id": S("VpcId"),
        "owner_id": S("OwnerId"),
    }
    route_table_associations: List[AwsEc2RouteTableAssociation] = field(factory=list)
    route_table_propagating_vgws: List[str] = field(factory=list)
    route_table_routes: List[AwsEc2Route] = field(factory=list)
    owner_id: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if vpc_id := source.get("VpcId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        for rta in self.route_table_associations:
            if rta.main:
                log_msg = f"Deleting route table association {rta.route_table_association_id}"
                self.log(log_msg)
                client.call(
                    aws_service=self.api_spec.service,
                    action="disassociate-route-table",
                    result_name=None,
                    AssociationId=rta.route_table_association_id,
                    expected_errors=["InvalidParameterValue", "InvalidAssociationID.NotFound"],
                )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-route-table",
            result_name=None,
            RouteTableId=self.id,
            expected_errors=["InvalidRouteTableID.NotFound"],
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [
            AwsApiSpec(service_name, "disassociate-route-table"),
            AwsApiSpec(service_name, "delete-route-table"),
        ]


@define(eq=False, slots=False)
class AwsEc2InstanceCapacity:
    kind: ClassVar[str] = "aws_ec2_instance_capacity"
    kind_display: ClassVar[str] = "AWS EC2 Instance Capacity"
    kind_description: ClassVar[str] = (
        "AWS EC2 Instance Capacity refers to the amount of computing power, expressed"
        " in terms of CPU, memory, and networking resources, that an EC2 instance can"
        " provide to run applications in the Amazon Web Services cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_capacity": S("AvailableCapacity"),
        "instance_type": S("InstanceType"),
        "total_capacity": S("TotalCapacity"),
    }
    available_capacity: Optional[int] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    total_capacity: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2AvailableCapacity:
    kind: ClassVar[str] = "aws_ec2_available_capacity"
    kind_display: ClassVar[str] = "AWS EC2 Available Capacity"
    kind_description: ClassVar[str] = (
        "The available capacity refers to the amount of resources (such as CPU,"
        " memory, and storage) that are currently available for new EC2 instances to"
        " be launched in the Amazon Web Services infrastructure."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "available_instance_capacity": S("AvailableInstanceCapacity", default=[])
        >> ForallBend(AwsEc2InstanceCapacity.mapping),
        "available_v_cpus": S("AvailableVCpus"),
    }
    available_instance_capacity: List[AwsEc2InstanceCapacity] = field(factory=list)
    available_v_cpus: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2HostProperties:
    kind: ClassVar[str] = "aws_ec2_host_properties"
    kind_display: ClassVar[str] = "AWS EC2 Host Properties"
    kind_description: ClassVar[str] = (
        "EC2 Host Properties provide detailed information and configuration options"
        " for the physical hosts within the Amazon EC2 infrastructure."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cores": S("Cores"),
        "instance_type": S("InstanceType"),
        "instance_family": S("InstanceFamily"),
        "sockets": S("Sockets"),
        "total_v_cpus": S("TotalVCpus"),
    }
    cores: Optional[int] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    instance_family: Optional[str] = field(default=None)
    sockets: Optional[int] = field(default=None)
    total_v_cpus: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2HostInstance:
    kind: ClassVar[str] = "aws_ec2_host_instance"
    kind_display: ClassVar[str] = "AWS EC2 Host Instance"
    kind_description: ClassVar[str] = (
        "EC2 Host Instances are physical servers in Amazon's cloud that are dedicated"
        " to hosting EC2 instances, providing you with more control over your"
        " infrastructure and allowing you to easily manage your own host-level"
        " resources."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_id": S("InstanceId"),
        "instance_type": S("InstanceType"),
        "owner_id": S("OwnerId"),
    }
    instance_id: Optional[str] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    owner_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEc2Host(EC2Taggable, AwsResource):
    kind: ClassVar[str] = "aws_ec2_host"
    kind_display: ClassVar[str] = "AWS EC2 Host"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#Host:hostId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:host/{id}"}  # fmt: skip

    kind_description: ClassVar[str] = (
        "EC2 Hosts are physical servers in Amazon's cloud that are used to run EC2 instances."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-hosts", "Hosts")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_ec2_instance"], "delete": ["aws_ec2_instance"]}
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("HostId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": (S("Tags", default=[]) >> TagsValue("Name")).or_else(S("HostId")),
        "ctime": S("AllocationTime"),
        "host_auto_placement": S("AutoPlacement"),
        "host_availability_zone": S("AvailabilityZone"),
        "host_available_capacity": S("AvailableCapacity") >> Bend(AwsEc2AvailableCapacity.mapping),
        "host_client_token": S("ClientToken"),
        "host_properties": S("HostProperties") >> Bend(AwsEc2HostProperties.mapping),
        "host_reservation_id": S("HostReservationId"),
        "host_instances": S("Instances", default=[]) >> ForallBend(AwsEc2HostInstance.mapping),
        "host_state": S("State"),
        "host_release_time": S("ReleaseTime"),
        "host_recovery": S("HostRecovery"),
        "host_allows_multiple_instance_types": S("AllowsMultipleInstanceTypes"),
        "host_owner_id": S("OwnerId"),
        "host_availability_zone_id": S("AvailabilityZoneId"),
        "host_member_of_service_linked_resource_group": S("MemberOfServiceLinkedResourceGroup"),
        "host_outpost_arn": S("OutpostArn"),
    }
    host_auto_placement: Optional[str] = field(default=None)
    host_availability_zone: Optional[str] = field(default=None)
    host_available_capacity: Optional[AwsEc2AvailableCapacity] = field(default=None)
    host_client_token: Optional[str] = field(default=None)
    host_properties: Optional[AwsEc2HostProperties] = field(default=None)
    host_reservation_id: Optional[str] = field(default=None)
    host_instances: List[AwsEc2HostInstance] = field(factory=list)
    host_state: Optional[str] = field(default=None)
    host_release_time: Optional[datetime] = field(default=None)
    host_recovery: Optional[str] = field(default=None)
    host_allows_multiple_instance_types: Optional[str] = field(default=None)
    host_owner_id: Optional[str] = field(default=None)
    host_availability_zone_id: Optional[str] = field(default=None)
    host_member_of_service_linked_resource_group: Optional[bool] = field(default=None)
    host_outpost_arn: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for instance in self.host_instances:
            builder.dependant_node(
                self,
                clazz=AwsEc2Instance,
                delete_same_as_default=True,
                id=instance.instance_id,
            )
        # TODO add edge to outpost (host_outpost_arn) when applicable

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="release-hosts",
            result_name=None,
            HostIds=[self.id],
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "release-hosts")]


@define(eq=False, slots=False)
class AwsEc2DestinationOption:
    kind: ClassVar[str] = "aws_ec2_destination_option"
    kind_display: ClassVar[str] = "AWS EC2 Destination Option"
    kind_description: ClassVar[str] = (
        "AWS EC2 Destination Options allow you to configure the storage format, Hive compatibility,"
        " and hourly partitioning of EC2 flow logs in Amazon S3, facilitating customized log management and analysis."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "file_format": S("FileFormat"),
        "hive_compatible_partitions": S("HiveCompatiblePartitions"),
        "per_hour_partition": S("PerHourPartition"),
    }
    file_format: Optional[str] = field(default=None)
    hive_compatible_partitions: Optional[bool] = field(default=None)
    per_hour_partition: Optional[bool] = field(default=None)


# endregion

# region Flow Log


@define(eq=False, slots=False)
class AwsEc2FlowLog(EC2Taggable, AwsResource):
    kind: ClassVar[str] = "aws_ec2_flow_log"
    kind_display: ClassVar[str] = "AWS EC2 Flow Log"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:ec2:{region}:{account}:flow-log/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "EC2 Flow Logs capture information about the IP traffic going to and from"
        " network interfaces in an Amazon EC2 instance, helping to troubleshoot"
        " network connectivity issues."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-flow-logs", "FlowLogs")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("FlowLogId"),
        "name": (S("Tags", default=[]) >> TagsValue("Name")).or_else(S("FlowLogId")),
        "tags": S("Tags", default=[]) >> ToDict(),
        "ctime": S("CreationTime"),
        "deliver_logs_error_message": S("DeliverLogsErrorMessage"),
        "deliver_logs_permission_arn": S("DeliverLogsPermissionArn"),
        "deliver_cross_account_role": S("DeliverCrossAccountRole"),
        "deliver_logs_status": S("DeliverLogsStatus"),
        "flow_log_status": S("FlowLogStatus"),
        "resource_id": S("ResourceId"),
        "traffic_type": S("TrafficType"),
        "log_destination_type": S("LogDestinationType"),
        "log_destination": S("LogDestination"),
        "log_format": S("LogFormat"),
        "log_group_name": S("LogGroupName"),
        "max_aggregation_interval": S("MaxAggregationInterval"),
        "destination_options": S("DestinationOptions") >> Bend(AwsEc2DestinationOption.mapping),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_s3_bucket"]},
        "predecessors": {"default": ["aws_vpc"]},
    }
    deliver_logs_error_message: Optional[str] = field(default=None)
    deliver_logs_permission_arn: Optional[str] = field(default=None)
    deliver_cross_account_role: Optional[str] = field(default=None)
    deliver_logs_status: Optional[str] = field(default=None)
    flow_log_status: Optional[str] = field(default=None)
    resource_id: Optional[str] = field(default=None)
    traffic_type: Optional[str] = field(default=None)
    log_destination_type: Optional[str] = field(default=None)
    log_destination: Optional[str] = field(default=None)
    log_format: Optional[str] = field(default=None)
    log_group_name: Optional[str] = field(default=None)
    max_aggregation_interval: Optional[int] = field(default=None)
    destination_options: Optional[AwsEc2DestinationOption] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if vpc_id := self.resource_id:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
        if self.log_destination_type == "s3" and (s3 := self.log_destination):
            builder.add_edge(self, clazz=AwsS3Bucket, arn=s3)
        # elif self.log_destination_type == "cloud-watch-logs" and (name := self.log_group_name):
        # TODO: add link to cloudwatch log group with given name

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(service_name, "delete-flow-logs", FlowLogIds=[self.id])
        return True


@define(eq=False, slots=False)
class AwsEc2EbsBlockDevice:
    kind: ClassVar[str] = "aws_ec2_ebs_block_device"
    mapping: ClassVar[Dict[str, Bender]] = {
        "delete_on_termination": S("DeleteOnTermination"),
        "iops": S("Iops"),
        "snapshot_id": S("SnapshotId"),
        "volume_size": S("VolumeSize"),
        "volume_type": S("VolumeType"),
        "kms_key_id": S("KmsKeyId"),
        "throughput": S("Throughput"),
        "outpost_arn": S("OutpostArn"),
        "encrypted": S("Encrypted"),
    }
    delete_on_termination: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the EBS volume is deleted on instance termination."})  # fmt: skip
    iops: Optional[int] = field(default=None, metadata={"description": "The number of I/O operations per second (IOPS)."})  # fmt: skip
    snapshot_id: Optional[str] = field(default=None, metadata={"description": "The ID of the snapshot."})  # fmt: skip
    volume_size: Optional[int] = field(default=None, metadata={"description": "The size of the volume, in GiBs."})  # fmt: skip
    volume_type: Optional[str] = field(default=None, metadata={"description": "The volume type. For more information, see Amazon EBS volume types in the Amazon EC2 User Guide."})  # fmt: skip
    kms_key_id: Optional[str] = field(default=None, metadata={"description": "Identifier (key ID, key alias, ID ARN, or alias ARN) for a customer managed CMK under which the EBS volume is encrypted."})  # fmt: skip
    throughput: Optional[int] = field(default=None, metadata={"description": "The throughput that the volume supports, in MiB/s. This parameter is valid only for gp3 volumes. Valid Range: Minimum value of 125. Maximum value of 1000."})  # fmt: skip
    outpost_arn: Optional[str] = field(default=None, metadata={"description": "The ARN of the Outpost on which the snapshot is stored. This parameter is not supported when using CreateImage."})  # fmt: skip
    encrypted: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the encryption state of an EBS volume is changed while being restored from a backing snapshot."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2BlockDeviceMapping:
    kind: ClassVar[str] = "aws_ec2_block_device_mapping"
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_name": S("DeviceName"),
        "virtual_name": S("VirtualName"),
        "ebs": S("Ebs") >> Bend(AwsEc2EbsBlockDevice.mapping),
        "no_device": S("NoDevice"),
    }
    device_name: Optional[str] = field(default=None, metadata={"description": "The device name (for example, /dev/sdh or xvdh)."})  # fmt: skip
    virtual_name: Optional[str] = field(default=None, metadata={"description": "The virtual device name (ephemeralN). Instance store volumes are numbered starting from 0."})  # fmt: skip
    ebs: Optional[AwsEc2EbsBlockDevice] = field(default=None, metadata={"description": "Parameters used to automatically set up EBS volumes when the instance is launched."})  # fmt: skip
    no_device: Optional[str] = field(default=None, metadata={"description": "To omit the device from the block device mapping, specify an empty string."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2Image(AwsResource):
    kind: ClassVar[str] = "aws_ec2_image"
    kind_display: ClassVar[str] = "AWS EC2 Image"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/home?region={region}#ImageDetails:imageId={id}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:image/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An Amazon Machine Image (AMI) is a supported and maintained image "
        "provided by AWS that provides the information required to launch an instance. "
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("ec2", "describe-images", "Images", {"Owners": ["self"]})
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ImageId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Name"),
        "ctime": S("CreationDate"),
        "architecture": S("Architecture"),
        "image_location": S("ImageLocation"),
        "image_type": S("ImageType"),
        "public": S("Public"),
        "kernel_id": S("KernelId"),
        "owner_id": S("OwnerId"),
        "platform": S("Platform"),
        "platform_details": S("PlatformDetails"),
        "usage_operation": S("UsageOperation"),
        "product_codes": S("ProductCodes", default=[]) >> ForallBend(AwsEc2ProductCode.mapping),
        "ramdisk_id": S("RamdiskId"),
        "state": S("State"),
        "block_device_mappings": S("BlockDeviceMappings", default=[]) >> ForallBend(AwsEc2BlockDeviceMapping.mapping),
        "description": S("Description"),
        "ena_support": S("EnaSupport"),
        "hypervisor": S("Hypervisor"),
        "image_owner_alias": S("ImageOwnerAlias"),
        "root_device_name": S("RootDeviceName"),
        "root_device_type": S("RootDeviceType"),
        "sriov_net_support": S("SriovNetSupport"),
        "state_reason": S("StateReason") >> Bend(AwsEc2StateReason.mapping),
        "virtualization_type": S("VirtualizationType"),
        "boot_mode": S("BootMode"),
        "tpm_support": S("TpmSupport"),
        "deprecation_time": S("DeprecationTime"),
        "imds_support": S("ImdsSupport"),
        "source_instance_id": S("SourceInstanceId"),
    }
    architecture: Optional[str] = field(default=None, metadata={"description": "The architecture of the image."})  # fmt: skip
    image_location: Optional[str] = field(default=None, metadata={"description": "The location of the AMI."})  # fmt: skip
    image_type: Optional[str] = field(default=None, metadata={"description": "The type of image."})  # fmt: skip
    public: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the image has public launch permissions."})  # fmt: skip
    kernel_id: Optional[str] = field(default=None, metadata={"description": "The kernel associated with the image, if any. Only applicable for machine images."})  # fmt: skip
    owner_id: Optional[str] = field(default=None, metadata={"description": "The ID of the Amazon Web Services account that owns the image."})  # fmt: skip
    platform: Optional[str] = field(default=None, metadata={"description": "This value is set to windows for Windows AMIs; otherwise, it is blank."})  # fmt: skip
    platform_details: Optional[str] = field(default=None, metadata={"description": "The platform details associated with the billing code of the AMI."})  # fmt: skip
    usage_operation: Optional[str] = field(default=None, metadata={"description": "The operation of the Amazon EC2 instance and the billing code that is associated with the AMI."})  # fmt: skip
    product_codes: Optional[List[AwsEc2ProductCode]] = field(factory=list, metadata={"description": "Any product codes associated with the AMI."})  # fmt: skip
    ramdisk_id: Optional[str] = field(default=None, metadata={"description": "The RAM disk associated with the image, if any."})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The current state of the AMI."})  # fmt: skip
    block_device_mappings: Optional[List[AwsEc2BlockDeviceMapping]] = field(factory=list, metadata={"description": "Any block device mapping entries."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of the AMI that was provided during image creation."})  # fmt: skip
    ena_support: Optional[bool] = field(default=None, metadata={"description": "Specifies whether enhanced networking with ENA is enabled."})  # fmt: skip
    hypervisor: Optional[str] = field(default=None, metadata={"description": "The hypervisor type of the image. Only xen is supported. ovm is not supported."})  # fmt: skip
    image_owner_alias: Optional[str] = field(default=None, metadata={"description": "The Amazon Web Services account alias (for example, amazon, self) or the Amazon Web Services account ID of the AMI owner."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the AMI that was provided during image creation."})  # fmt: skip
    root_device_name: Optional[str] = field(default=None, metadata={"description": "The device name of the root device volume (for example, /dev/sda1)."})  # fmt: skip
    root_device_type: Optional[str] = field(default=None, metadata={"description": "The type of root device used by the AMI. The AMI can use an Amazon EBS volume or an instance store volume."})  # fmt: skip
    sriov_net_support: Optional[str] = field(default=None, metadata={"description": "Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled."})  # fmt: skip
    state_reason: Optional[AwsEc2StateReason] = field(default=None, metadata={"description": "The reason for the state change."})  # fmt: skip
    virtualization_type: Optional[str] = field(default=None, metadata={"description": "The type of virtualization of the AMI."})  # fmt: skip
    boot_mode: Optional[str] = field(default=None, metadata={"description": "The boot mode of the image. For more information, see Boot modes in the Amazon EC2 User Guide."})  # fmt: skip
    tpm_support: Optional[str] = field(default=None, metadata={"description": "If the image is configured for NitroTPM support, the value is v2.0. For more information, see NitroTPM in the Amazon EC2 User Guide."})  # fmt: skip
    deprecation_time: Optional[str] = field(default=None, metadata={"description": "The date and time to deprecate the AMI, in UTC, in the following format: YYYY-MM-DDTHH:MM:SSZ."})  # fmt: skip
    imds_support: Optional[str] = field(default=None, metadata={"description": "If v2.0, it indicates that IMDSv2 is specified in the AMI."})  # fmt: skip
    source_instance_id: Optional[str] = field(default=None, metadata={"description": "The ID of the instance that the AMI was created from if the AMI was created using CreateImage."})  # fmt: skip

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="deregister-image",
            result_name=None,
            ImageId=self.id,
        )
        return True

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        if self.block_device_mappings is None:
            return
        for bdm in self.block_device_mappings:
            if bdm.ebs and bdm.ebs.snapshot_id:
                builder.add_edge(self, EdgeType.default, reverse=False, clazz=AwsEc2Snapshot, id=bdm.ebs.snapshot_id)


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateIamInstanceProfileSpecification:
    kind: ClassVar[str] = "aws_ec2_launch_template_iam_instance_profile_specification"
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "name": S("Name")}
    arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the instance profile."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the instance profile."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateEbsBlockDevice:
    kind: ClassVar[str] = "aws_ec2_launch_template_ebs_block_device"
    mapping: ClassVar[Dict[str, Bender]] = {
        "encrypted": S("Encrypted"),
        "delete_on_termination": S("DeleteOnTermination"),
        "iops": S("Iops"),
        "kms_key_id": S("KmsKeyId"),
        "snapshot_id": S("SnapshotId"),
        "volume_size": S("VolumeSize"),
        "volume_type": S("VolumeType"),
        "throughput": S("Throughput"),
    }
    encrypted: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the EBS volume is encrypted."})  # fmt: skip
    delete_on_termination: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the EBS volume is deleted on instance termination."})  # fmt: skip
    iops: Optional[int] = field(default=None, metadata={"description": "The number of I/O operations per second (IOPS) that the volume supports."})  # fmt: skip
    kms_key_id: Optional[str] = field(default=None, metadata={"description": "The ARN of the Key Management Service (KMS) CMK used for encryption."})  # fmt: skip
    snapshot_id: Optional[str] = field(default=None, metadata={"description": "The ID of the snapshot."})  # fmt: skip
    volume_size: Optional[int] = field(default=None, metadata={"description": "The size of the volume, in GiB."})  # fmt: skip
    volume_type: Optional[str] = field(default=None, metadata={"description": "The volume type."})  # fmt: skip
    throughput: Optional[int] = field(default=None, metadata={"description": "The throughput that the volume supports, in MiB/s."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateBlockDeviceMapping:
    kind: ClassVar[str] = "aws_ec2_launch_template_block_device_mapping"
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_name": S("DeviceName"),
        "virtual_name": S("VirtualName"),
        "ebs": S("Ebs") >> Bend(AwsEc2LaunchTemplateEbsBlockDevice.mapping),
        "no_device": S("NoDevice"),
    }
    device_name: Optional[str] = field(default=None, metadata={"description": "The device name."})  # fmt: skip
    virtual_name: Optional[str] = field(default=None, metadata={"description": "The virtual device name (ephemeralN)."})  # fmt: skip
    ebs: Optional[AwsEc2LaunchTemplateEbsBlockDevice] = field(default=None, metadata={"description": "Information about the block device for an EBS volume."})  # fmt: skip
    no_device: Optional[str] = field(default=None, metadata={"description": "To omit the device from the block device mapping, specify an empty string."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateInstanceIpv6Address:
    kind: ClassVar[str] = "aws_ec2_launch_template_instance_ipv6_address"
    mapping: ClassVar[Dict[str, Bender]] = {"ipv6_address": S("Ipv6Address"), "is_primary_ipv6": S("IsPrimaryIpv6")}
    ipv6_address: Optional[str] = field(default=None, metadata={"description": "The IPv6 address."})  # fmt: skip
    is_primary_ipv6: Optional[bool] = field(default=None, metadata={"description": "Determines if an IPv6 address associated with a network interface is the primary IPv6 address. When you enable an IPv6 GUA address to be a primary IPv6, the first IPv6 GUA will be made the primary IPv6 address until the instance is terminated or the network interface is detached. For more information, see RunInstances."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplatePrivateIpAddressSpecification:
    kind: ClassVar[str] = "aws_ec2_launch_template_private_ip_address_specification"
    mapping: ClassVar[Dict[str, Bender]] = {"primary": S("Primary"), "private_ip_address": S("PrivateIpAddress")}
    primary: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the private IPv4 address is the primary private IPv4 address. Only one IPv4 address can be designated as primary."})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={"description": "The private IPv4 address."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateEnaSrdSpecification:
    kind: ClassVar[str] = "aws_ec2_launch_template_ena_srd_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ena_srd_enabled": S("EnaSrdEnabled"),
        "ena_srd_udp_specification": S("EnaSrdUdpSpecification", "EnaSrdUdpEnabled"),
    }
    ena_srd_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether ENA Express is enabled for the network interface."})  # fmt: skip
    ena_srd_udp_specification: Optional[bool] = field(default=None, metadata={"description": "Configures ENA Express for UDP network traffic."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateConnectionTrackingSpecification:
    kind: ClassVar[str] = "aws_ec2_launch_template_connection_tracking_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "tcp_established_timeout": S("TcpEstablishedTimeout"),
        "udp_timeout": S("UdpTimeout"),
        "udp_stream_timeout": S("UdpStreamTimeout"),
    }
    tcp_established_timeout: Optional[int] = field(default=None, metadata={"description": "Timeout (in seconds) for idle TCP connections in an established state. Min: 60 seconds. Max: 432000 seconds (5 days). Default: 432000 seconds. Recommended: Less than 432000 seconds."})  # fmt: skip
    udp_timeout: Optional[int] = field(default=None, metadata={"description": "Timeout (in seconds) for idle UDP flows that have seen traffic only in a single direction or a single request-response transaction. Min: 30 seconds. Max: 60 seconds. Default: 30 seconds."})  # fmt: skip
    udp_stream_timeout: Optional[int] = field(default=None, metadata={"description": "Timeout (in seconds) for idle UDP flows classified as streams which have seen more than one request-response transaction. Min: 60 seconds. Max: 180 seconds (3 minutes). Default: 180 seconds."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateInstanceNetworkInterfaceSpecification:
    kind: ClassVar[str] = "aws_ec2_launch_template_instance_network_interface_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "associate_carrier_ip_address": S("AssociateCarrierIpAddress"),
        "associate_public_ip_address": S("AssociatePublicIpAddress"),
        "delete_on_termination": S("DeleteOnTermination"),
        "description": S("Description"),
        "device_index": S("DeviceIndex"),
        "groups": S("Groups", default=[]),
        "interface_type": S("InterfaceType"),
        "ipv6_address_count": S("Ipv6AddressCount"),
        "ipv6_addresses": S("Ipv6Addresses", default=[]) >> ForallBend(AwsEc2LaunchTemplateInstanceIpv6Address.mapping),
        "network_interface_id": S("NetworkInterfaceId"),
        "private_ip_address": S("PrivateIpAddress"),
        "private_ip_addresses": S("PrivateIpAddresses", default=[])
        >> ForallBend(AwsEc2LaunchTemplatePrivateIpAddressSpecification.mapping),
        "secondary_private_ip_address_count": S("SecondaryPrivateIpAddressCount"),
        "subnet_id": S("SubnetId"),
        "network_card_index": S("NetworkCardIndex"),
        "ipv4_prefixes": S("Ipv4Prefixes", default=[]) >> ForallBend(S("Ipv4Prefix")),
        "ipv4_prefix_count": S("Ipv4PrefixCount"),
        "ipv6_prefixes": S("Ipv6Prefixes", default=[]) >> ForallBend(S("Ipv6Prefix")),
        "ipv6_prefix_count": S("Ipv6PrefixCount"),
        "primary_ipv6": S("PrimaryIpv6"),
        "ena_srd_specification": S("EnaSrdSpecification") >> Bend(AwsEc2LaunchTemplateEnaSrdSpecification.mapping),
        "connection_tracking_specification": S("ConnectionTrackingSpecification")
        >> Bend(AwsEc2LaunchTemplateConnectionTrackingSpecification.mapping),
    }
    associate_carrier_ip_address: Optional[bool] = field(default=None, metadata={"description": "Indicates whether to associate a Carrier IP address with eth0 for a new network interface. Use this option when you launch an instance in a Wavelength Zone and want to associate a Carrier IP address with the network interface. For more information about Carrier IP addresses, see Carrier IP addresses in the Wavelength Developer Guide."})  # fmt: skip
    associate_public_ip_address: Optional[bool] = field(default=None, metadata={"description": "Indicates whether to associate a public IPv4 address with eth0 for a new network interface. Starting on February 1, 2024, Amazon Web Services will charge for all public IPv4 addresses, including public IPv4 addresses associated with running instances and Elastic IP addresses. For more information, see the Public IPv4 Address tab on the Amazon VPC pricing page."})  # fmt: skip
    delete_on_termination: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the network interface is deleted when the instance is terminated."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "A description for the network interface."})  # fmt: skip
    device_index: Optional[int] = field(default=None, metadata={"description": "The device index for the network interface attachment."})  # fmt: skip
    groups: Optional[List[str]] = field(factory=list, metadata={"description": "The IDs of one or more security groups."})  # fmt: skip
    interface_type: Optional[str] = field(default=None, metadata={"description": "The type of network interface."})  # fmt: skip
    ipv6_address_count: Optional[int] = field(default=None, metadata={"description": "The number of IPv6 addresses for the network interface."})  # fmt: skip
    ipv6_addresses: Optional[List[AwsEc2LaunchTemplateInstanceIpv6Address]] = field(factory=list, metadata={"description": "The IPv6 addresses for the network interface."})  # fmt: skip
    network_interface_id: Optional[str] = field(default=None, metadata={"description": "The ID of the network interface."})  # fmt: skip
    private_ip_address: Optional[str] = field(default=None, metadata={"description": "The primary private IPv4 address of the network interface."})  # fmt: skip
    private_ip_addresses: Optional[List[AwsEc2LaunchTemplatePrivateIpAddressSpecification]] = field(factory=list, metadata={"description": "One or more private IPv4 addresses."})  # fmt: skip
    secondary_private_ip_address_count: Optional[int] = field(default=None, metadata={"description": "The number of secondary private IPv4 addresses for the network interface."})  # fmt: skip
    subnet_id: Optional[str] = field(default=None, metadata={"description": "The ID of the subnet for the network interface."})  # fmt: skip
    network_card_index: Optional[int] = field(default=None, metadata={"description": "The index of the network card."})  # fmt: skip
    ipv4_prefixes: Optional[List[str]] = field(factory=list, metadata={"description": "One or more IPv4 prefixes assigned to the network interface."})  # fmt: skip
    ipv4_prefix_count: Optional[int] = field(default=None, metadata={"description": "The number of IPv4 prefixes that Amazon Web Services automatically assigned to the network interface."})  # fmt: skip
    ipv6_prefixes: Optional[List[str]] = field(factory=list, metadata={"description": "One or more IPv6 prefixes assigned to the network interface."})  # fmt: skip
    ipv6_prefix_count: Optional[int] = field(default=None, metadata={"description": "The number of IPv6 prefixes that Amazon Web Services automatically assigned to the network interface."})  # fmt: skip
    primary_ipv6: Optional[bool] = field(default=None, metadata={"description": "The primary IPv6 address of the network interface. When you enable an IPv6 GUA address to be a primary IPv6, the first IPv6 GUA will be made the primary IPv6 address until the instance is terminated or the network interface is detached. For more information about primary IPv6 addresses, see RunInstances."})  # fmt: skip
    ena_srd_specification: Optional[AwsEc2LaunchTemplateEnaSrdSpecification] = field(default=None, metadata={"description": "Contains the ENA Express settings for instances launched from your launch template."})  # fmt: skip
    connection_tracking_specification: Optional[AwsEc2LaunchTemplateConnectionTrackingSpecification] = field(default=None, metadata={"description": "A security group connection tracking specification that enables you to set the timeout for connection tracking on an Elastic network interface. For more information, see Connection tracking timeouts in the Amazon Elastic Compute Cloud User Guide."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplatePlacement:
    kind: ClassVar[str] = "aws_ec2_launch_template_placement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "availability_zone": S("AvailabilityZone"),
        "affinity": S("Affinity"),
        "group_name": S("GroupName"),
        "host_id": S("HostId"),
        "tenancy": S("Tenancy"),
        "spread_domain": S("SpreadDomain"),
        "host_resource_group_arn": S("HostResourceGroupArn"),
        "partition_number": S("PartitionNumber"),
        "group_id": S("GroupId"),
    }
    availability_zone: Optional[str] = field(default=None, metadata={"description": "The Availability Zone of the instance."})  # fmt: skip
    affinity: Optional[str] = field(default=None, metadata={"description": "The affinity setting for the instance on the Dedicated Host."})  # fmt: skip
    group_name: Optional[str] = field(default=None, metadata={"description": "The name of the placement group for the instance."})  # fmt: skip
    host_id: Optional[str] = field(default=None, metadata={"description": "The ID of the Dedicated Host for the instance."})  # fmt: skip
    tenancy: Optional[str] = field(default=None, metadata={"description": "The tenancy of the instance. An instance with a tenancy of dedicated runs on single-tenant hardware."})  # fmt: skip
    spread_domain: Optional[str] = field(default=None, metadata={"description": "Reserved for future use."})  # fmt: skip
    host_resource_group_arn: Optional[str] = field(default=None, metadata={"description": "The ARN of the host resource group in which to launch the instances."})  # fmt: skip
    partition_number: Optional[int] = field(default=None, metadata={"description": "The number of the partition the instance should launch in. Valid only if the placement group strategy is set to partition."})  # fmt: skip
    group_id: Optional[str] = field(default=None, metadata={"description": "The Group ID of the placement group. You must specify the Placement Group Group ID to launch an instance in a shared placement group."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateTagSpecification:
    kind: ClassVar[str] = "aws_ec2_launch_template_tag_specification"
    mapping: ClassVar[Dict[str, Bender]] = {"resource_type": S("ResourceType")}
    resource_type: Optional[str] = field(default=None, metadata={"description": "The type of resource to tag."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateElasticInferenceAcceleratorResponse:
    kind: ClassVar[str] = "aws_ec2_launch_template_elastic_inference_accelerator_response"
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("Type"), "count": S("Count")}
    type: Optional[str] = field(default=None, metadata={"description": "The type of elastic inference accelerator. The possible values are eia1.medium, eia1.large, and eia1.xlarge."})  # fmt: skip
    count: Optional[int] = field(default=None, metadata={"description": "The number of elastic inference accelerators to attach to the instance.  Default: 1"})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateSpotMarketOptions:
    kind: ClassVar[str] = "aws_ec2_launch_template_spot_market_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_price": S("MaxPrice"),
        "spot_instance_type": S("SpotInstanceType"),
        "block_duration_minutes": S("BlockDurationMinutes"),
        "valid_until": S("ValidUntil"),
        "instance_interruption_behavior": S("InstanceInterruptionBehavior"),
    }
    max_price: Optional[str] = field(default=None, metadata={"description": "The maximum hourly price you're willing to pay for the Spot Instances. We do not recommend using this parameter because it can lead to increased interruptions. If you do not specify this parameter, you will pay the current Spot price.  If you specify a maximum price, your Spot Instances will be interrupted more frequently than if you do not specify this parameter."})  # fmt: skip
    spot_instance_type: Optional[str] = field(default=None, metadata={"description": "The Spot Instance request type."})  # fmt: skip
    block_duration_minutes: Optional[int] = field(default=None, metadata={"description": "The required duration for the Spot Instances (also known as Spot blocks), in minutes. This value must be a multiple of 60 (60, 120, 180, 240, 300, or 360)."})  # fmt: skip
    valid_until: Optional[datetime] = field(default=None, metadata={"description": "The end date of the request. For a one-time request, the request remains active until all instances launch, the request is canceled, or this date is reached. If the request is persistent, it remains active until it is canceled or this date and time is reached."})  # fmt: skip
    instance_interruption_behavior: Optional[str] = field(default=None, metadata={"description": "The behavior when a Spot Instance is interrupted."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateInstanceMarketOptions:
    kind: ClassVar[str] = "aws_ec2_launch_template_instance_market_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "market_type": S("MarketType"),
        "spot_options": S("SpotOptions") >> Bend(AwsEc2LaunchTemplateSpotMarketOptions.mapping),
    }
    market_type: Optional[str] = field(default=None, metadata={"description": "The market type."})  # fmt: skip
    spot_options: Optional[AwsEc2LaunchTemplateSpotMarketOptions] = field(default=None, metadata={"description": "The options for Spot Instances."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateCpuOptions:
    kind: ClassVar[str] = "aws_ec2_launch_template_cpu_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "core_count": S("CoreCount"),
        "threads_per_core": S("ThreadsPerCore"),
        "amd_sev_snp": S("AmdSevSnp"),
    }
    core_count: Optional[int] = field(default=None, metadata={"description": "The number of CPU cores for the instance."})  # fmt: skip
    threads_per_core: Optional[int] = field(default=None, metadata={"description": "The number of threads per CPU core."})  # fmt: skip
    amd_sev_snp: Optional[str] = field(default=None, metadata={"description": "Indicates whether the instance is enabled for AMD SEV-SNP. For more information, see AMD SEV-SNP."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateCapacityReservationTargetResponse:
    kind: ClassVar[str] = "aws_ec2_launch_template_capacity_reservation_target_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_reservation_id": S("CapacityReservationId"),
        "capacity_reservation_resource_group_arn": S("CapacityReservationResourceGroupArn"),
    }
    capacity_reservation_id: Optional[str] = field(default=None, metadata={"description": "The ID of the targeted Capacity Reservation."})  # fmt: skip
    capacity_reservation_resource_group_arn: Optional[str] = field(default=None, metadata={"description": "The ARN of the targeted Capacity Reservation group."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateCapacityReservationSpecificationResponse:
    kind: ClassVar[str] = "aws_ec2_launch_template_capacity_reservation_specification_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_reservation_preference": S("CapacityReservationPreference"),
        "capacity_reservation_target": S("CapacityReservationTarget")
        >> Bend(AwsEc2LaunchTemplateCapacityReservationTargetResponse.mapping),
    }
    capacity_reservation_preference: Optional[str] = field(default=None, metadata={"description": "Indicates the instance's Capacity Reservation preferences. Possible preferences include:    open - The instance can run in any open Capacity Reservation that has matching attributes (instance type, platform, Availability Zone).    none - The instance avoids running in a Capacity Reservation even if one is available. The instance runs in On-Demand capacity."})  # fmt: skip
    capacity_reservation_target: Optional[AwsEc2LaunchTemplateCapacityReservationTargetResponse] = field(default=None, metadata={"description": "Information about the target Capacity Reservation or Capacity Reservation group."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateInstanceMetadataOptions:
    kind: ClassVar[str] = "aws_ec2_launch_template_instance_metadata_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "state": S("State"),
        "http_tokens": S("HttpTokens"),
        "http_put_response_hop_limit": S("HttpPutResponseHopLimit"),
        "http_endpoint": S("HttpEndpoint"),
        "http_protocol_ipv6": S("HttpProtocolIpv6"),
        "instance_metadata_tags": S("InstanceMetadataTags"),
    }
    state: Optional[str] = field(default=None, metadata={"description": "The state of the metadata option changes.  pending - The metadata options are being updated and the instance is not ready to process metadata traffic with the new selection.  applied - The metadata options have been successfully applied on the instance."})  # fmt: skip
    http_tokens: Optional[str] = field(default=None, metadata={"description": "Indicates whether IMDSv2 is required.    optional - IMDSv2 is optional. You can choose whether to send a session token in your instance metadata retrieval requests. If you retrieve IAM role credentials without a session token, you receive the IMDSv1 role credentials. If you retrieve IAM role credentials using a valid session token, you receive the IMDSv2 role credentials.    required - IMDSv2 is required. You must send a session token in your instance metadata retrieval requests. With this option, retrieving the IAM role credentials always returns IMDSv2 credentials; IMDSv1 credentials are not available."})  # fmt: skip
    http_put_response_hop_limit: Optional[int] = field(default=None, metadata={"description": "The desired HTTP PUT response hop limit for instance metadata requests. The larger the number, the further instance metadata requests can travel. Default: 1 Possible values: Integers from 1 to 64"})  # fmt: skip
    http_endpoint: Optional[str] = field(default=None, metadata={"description": "Enables or disables the HTTP metadata endpoint on your instances. If the parameter is not specified, the default state is enabled.  If you specify a value of disabled, you will not be able to access your instance metadata."})  # fmt: skip
    http_protocol_ipv6: Optional[str] = field(default=None, metadata={"description": "Enables or disables the IPv6 endpoint for the instance metadata service. Default: disabled"})  # fmt: skip
    instance_metadata_tags: Optional[str] = field(default=None, metadata={"description": "Set to enabled to allow access to instance tags from the instance metadata. Set to disabled to turn off access to instance tags from the instance metadata. For more information, see Work with instance tags using the instance metadata. Default: disabled"})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateVCpuCountRange:
    kind: ClassVar[str] = "aws_ec2_launch_template_v_cpu_count_range"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[int] = field(default=None, metadata={"description": "The minimum number of vCPUs. If the value is 0, there is no minimum limit."})  # fmt: skip
    max: Optional[int] = field(default=None, metadata={"description": "The maximum number of vCPUs. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateMemoryMiB:
    kind: ClassVar[str] = "aws_ec2_launch_template_memory_mi_b"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[int] = field(default=None, metadata={"description": "The minimum amount of memory, in MiB. If this parameter is not specified, there is no minimum limit."})  # fmt: skip
    max: Optional[int] = field(default=None, metadata={"description": "The maximum amount of memory, in MiB. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateMemoryGiBPerVCpu:
    kind: ClassVar[str] = "aws_ec2_launch_template_memory_gi_b_per_v_cpu"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[float] = field(default=None, metadata={"description": "The minimum amount of memory per vCPU, in GiB. If this parameter is not specified, there is no minimum limit."})  # fmt: skip
    max: Optional[float] = field(default=None, metadata={"description": "The maximum amount of memory per vCPU, in GiB. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateNetworkInterfaceCount:
    kind: ClassVar[str] = "aws_ec2_launch_template_network_interface_count"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[int] = field(default=None, metadata={"description": "The minimum number of network interfaces. If this parameter is not specified, there is no minimum limit."})  # fmt: skip
    max: Optional[int] = field(default=None, metadata={"description": "The maximum number of network interfaces. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateTotalLocalStorageGB:
    kind: ClassVar[str] = "aws_ec2_launch_template_total_local_storage_gb"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[float] = field(default=None, metadata={"description": "The minimum amount of total local storage, in GB. If this parameter is not specified, there is no minimum limit."})  # fmt: skip
    max: Optional[float] = field(default=None, metadata={"description": "The maximum amount of total local storage, in GB. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateBaselineEbsBandwidthMbps:
    kind: ClassVar[str] = "aws_ec2_launch_template_baseline_ebs_bandwidth_mbps"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[int] = field(default=None, metadata={"description": "The minimum baseline bandwidth, in Mbps. If this parameter is not specified, there is no minimum limit."})  # fmt: skip
    max: Optional[int] = field(default=None, metadata={"description": "The maximum baseline bandwidth, in Mbps. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateAcceleratorCount:
    kind: ClassVar[str] = "aws_ec2_launch_template_accelerator_count"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[int] = field(default=None, metadata={"description": "The minimum number of accelerators. If this parameter is not specified, there is no minimum limit."})  # fmt: skip
    max: Optional[int] = field(default=None, metadata={"description": "The maximum number of accelerators. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateAcceleratorTotalMemoryMiB:
    kind: ClassVar[str] = "aws_ec2_launch_template_accelerator_total_memory_mi_b"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[int] = field(default=None, metadata={"description": "The minimum amount of accelerator memory, in MiB. If this parameter is not specified, there is no minimum limit."})  # fmt: skip
    max: Optional[int] = field(default=None, metadata={"description": "The maximum amount of accelerator memory, in MiB. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateNetworkBandwidthGbps:
    kind: ClassVar[str] = "aws_ec2_launch_template_network_bandwidth_gbps"
    mapping: ClassVar[Dict[str, Bender]] = {"min": S("Min"), "max": S("Max")}
    min: Optional[float] = field(default=None, metadata={"description": "The minimum amount of network bandwidth, in Gbps. If this parameter is not specified, there is no minimum limit."})  # fmt: skip
    max: Optional[float] = field(default=None, metadata={"description": "The maximum amount of network bandwidth, in Gbps. If this parameter is not specified, there is no maximum limit."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateInstanceRequirements:
    kind: ClassVar[str] = "aws_ec2_launch_template_instance_requirements"
    mapping: ClassVar[Dict[str, Bender]] = {
        "v_cpu_count": S("VCpuCount") >> Bend(AwsEc2LaunchTemplateVCpuCountRange.mapping),
        "memory_mi_b": S("MemoryMiB") >> Bend(AwsEc2LaunchTemplateMemoryMiB.mapping),
        "cpu_manufacturers": S("CpuManufacturers", default=[]),
        "memory_gi_b_per_v_cpu": S("MemoryGiBPerVCpu") >> Bend(AwsEc2LaunchTemplateMemoryGiBPerVCpu.mapping),
        "excluded_instance_types": S("ExcludedInstanceTypes", default=[]),
        "instance_generations": S("InstanceGenerations", default=[]),
        "spot_max_price_percentage_over_lowest_price": S("SpotMaxPricePercentageOverLowestPrice"),
        "on_demand_max_price_percentage_over_lowest_price": S("OnDemandMaxPricePercentageOverLowestPrice"),
        "bare_metal": S("BareMetal"),
        "burstable_performance": S("BurstablePerformance"),
        "require_hibernate_support": S("RequireHibernateSupport"),
        "network_interface_count": S("NetworkInterfaceCount")
        >> Bend(AwsEc2LaunchTemplateNetworkInterfaceCount.mapping),
        "local_storage": S("LocalStorage"),
        "local_storage_types": S("LocalStorageTypes", default=[]),
        "total_local_storage_gb": S("TotalLocalStorageGB") >> Bend(AwsEc2LaunchTemplateTotalLocalStorageGB.mapping),
        "baseline_ebs_bandwidth_mbps": S("BaselineEbsBandwidthMbps")
        >> Bend(AwsEc2LaunchTemplateBaselineEbsBandwidthMbps.mapping),
        "accelerator_types": S("AcceleratorTypes", default=[]),
        "accelerator_count": S("AcceleratorCount") >> Bend(AwsEc2LaunchTemplateAcceleratorCount.mapping),
        "accelerator_manufacturers": S("AcceleratorManufacturers", default=[]),
        "accelerator_names": S("AcceleratorNames", default=[]),
        "accelerator_total_memory_mi_b": S("AcceleratorTotalMemoryMiB")
        >> Bend(AwsEc2LaunchTemplateAcceleratorTotalMemoryMiB.mapping),
        "network_bandwidth_gbps": S("NetworkBandwidthGbps") >> Bend(AwsEc2LaunchTemplateNetworkBandwidthGbps.mapping),
        "allowed_instance_types": S("AllowedInstanceTypes", default=[]),
    }
    v_cpu_count: Optional[AwsEc2LaunchTemplateVCpuCountRange] = field(default=None, metadata={"description": "The minimum and maximum number of vCPUs."})  # fmt: skip
    memory_mi_b: Optional[AwsEc2LaunchTemplateMemoryMiB] = field(default=None, metadata={"description": "The minimum and maximum amount of memory, in MiB."})  # fmt: skip
    cpu_manufacturers: Optional[List[str]] = field(factory=list, metadata={"description": "The CPU manufacturers to include.   For instance types with Intel CPUs, specify intel.   For instance types with AMD CPUs, specify amd.   For instance types with Amazon Web Services CPUs, specify amazon-web-services.    Don't confuse the CPU manufacturer with the CPU architecture. Instances will be launched with a compatible CPU architecture based on the Amazon Machine Image (AMI) that you specify in your launch template.  Default: Any manufacturer"})  # fmt: skip
    memory_gi_b_per_v_cpu: Optional[AwsEc2LaunchTemplateMemoryGiBPerVCpu] = field(default=None, metadata={"description": "The minimum and maximum amount of memory per vCPU, in GiB. Default: No minimum or maximum limits"})  # fmt: skip
    excluded_instance_types: Optional[List[str]] = field(factory=list, metadata={"description": "The instance types to exclude. You can use strings with one or more wild cards, represented by an asterisk (*), to exclude an instance type, size, or generation. The following are examples: m5.8xlarge, c5*.*, m5a.*, r*, *3*. For example, if you specify c5*,Amazon EC2 will exclude the entire C5 instance family, which includes all C5a and C5n instance types. If you specify m5a.*, Amazon EC2 will exclude all the M5a instance types, but not the M5n instance types.  If you specify ExcludedInstanceTypes, you can't specify AllowedInstanceTypes.  Default: No excluded instance types"})  # fmt: skip
    instance_generations: Optional[List[str]] = field(factory=list, metadata={"description": "Indicates whether current or previous generation instance types are included. The current generation instance types are recommended for use. Current generation instance types are typically the latest two to three generations in each instance family. For more information, see Instance types in the Amazon EC2 User Guide. For current generation instance types, specify current. For previous generation instance types, specify previous. Default: Current and previous generation instance types"})  # fmt: skip
    spot_max_price_percentage_over_lowest_price: Optional[int] = field(default=None, metadata={"description": "The price protection threshold for Spot Instances. This is the maximum you’ll pay for a Spot Instance, expressed as a percentage above the least expensive current generation M, C, or R instance type with your specified attributes. When Amazon EC2 selects instance types with your attributes, it excludes instance types priced above your threshold. The parameter accepts an integer, which Amazon EC2 interprets as a percentage. To turn off price protection, specify a high value, such as 999999. This parameter is not supported for GetSpotPlacementScores and GetInstanceTypesFromInstanceRequirements.  If you set TargetCapacityUnitType to vcpu or memory-mib, the price protection threshold is applied based on the per-vCPU or per-memory price instead of the per-instance price.  Default: 100"})  # fmt: skip
    on_demand_max_price_percentage_over_lowest_price: Optional[int] = field(default=None, metadata={"description": "The price protection threshold for On-Demand Instances. This is the maximum you’ll pay for an On-Demand Instance, expressed as a percentage above the least expensive current generation M, C, or R instance type with your specified attributes. When Amazon EC2 selects instance types with your attributes, it excludes instance types priced above your threshold. The parameter accepts an integer, which Amazon EC2 interprets as a percentage. To turn off price protection, specify a high value, such as 999999. This parameter is not supported for GetSpotPlacementScores and GetInstanceTypesFromInstanceRequirements.  If you set TargetCapacityUnitType to vcpu or memory-mib, the price protection threshold is applied based on the per-vCPU or per-memory price instead of the per-instance price.  Default: 20"})  # fmt: skip
    bare_metal: Optional[str] = field(default=None, metadata={"description": "Indicates whether bare metal instance types must be included, excluded, or required.   To include bare metal instance types, specify included.   To require only bare metal instance types, specify required.   To exclude bare metal instance types, specify excluded.   Default: excluded"})  # fmt: skip
    burstable_performance: Optional[str] = field(default=None, metadata={"description": "Indicates whether burstable performance T instance types are included, excluded, or required. For more information, see Burstable performance instances.   To include burstable performance instance types, specify included.   To require only burstable performance instance types, specify required.   To exclude burstable performance instance types, specify excluded.   Default: excluded"})  # fmt: skip
    require_hibernate_support: Optional[bool] = field(default=None, metadata={"description": "Indicates whether instance types must support hibernation for On-Demand Instances. This parameter is not supported for GetSpotPlacementScores. Default: false"})  # fmt: skip
    network_interface_count: Optional[AwsEc2LaunchTemplateNetworkInterfaceCount] = field(default=None, metadata={"description": "The minimum and maximum number of network interfaces. Default: No minimum or maximum limits"})  # fmt: skip
    local_storage: Optional[str] = field(default=None, metadata={"description": "Indicates whether instance types with instance store volumes are included, excluded, or required. For more information, Amazon EC2 instance store in the Amazon EC2 User Guide.   To include instance types with instance store volumes, specify included.   To require only instance types with instance store volumes, specify required.   To exclude instance types with instance store volumes, specify excluded.   Default: included"})  # fmt: skip
    local_storage_types: Optional[List[str]] = field(factory=list, metadata={"description": "The type of local storage that is required.   For instance types with hard disk drive (HDD) storage, specify hdd.   For instance types with solid state drive (SSD) storage, specify ssd.   Default: hdd and ssd"})  # fmt: skip
    total_local_storage_gb: Optional[AwsEc2LaunchTemplateTotalLocalStorageGB] = field(default=None, metadata={"description": "The minimum and maximum amount of total local storage, in GB. Default: No minimum or maximum limits"})  # fmt: skip
    baseline_ebs_bandwidth_mbps: Optional[AwsEc2LaunchTemplateBaselineEbsBandwidthMbps] = field(default=None, metadata={"description": "The minimum and maximum baseline bandwidth to Amazon EBS, in Mbps. For more information, see Amazon EBS–optimized instances in the Amazon EC2 User Guide. Default: No minimum or maximum limits"})  # fmt: skip
    accelerator_types: Optional[List[str]] = field(factory=list, metadata={"description": "The accelerator types that must be on the instance type.   For instance types with GPU accelerators, specify gpu.   For instance types with FPGA accelerators, specify fpga.   For instance types with inference accelerators, specify inference.   Default: Any accelerator type"})  # fmt: skip
    accelerator_count: Optional[AwsEc2LaunchTemplateAcceleratorCount] = field(default=None, metadata={"description": "The minimum and maximum number of accelerators (GPUs, FPGAs, or Amazon Web Services Inferentia chips) on an instance. To exclude accelerator-enabled instance types, set Max to 0. Default: No minimum or maximum limits"})  # fmt: skip
    accelerator_manufacturers: Optional[List[str]] = field(factory=list, metadata={"description": "Indicates whether instance types must have accelerators by specific manufacturers.   For instance types with Amazon Web Services devices, specify amazon-web-services.   For instance types with AMD devices, specify amd.   For instance types with Habana devices, specify habana.   For instance types with NVIDIA devices, specify nvidia.   For instance types with Xilinx devices, specify xilinx.   Default: Any manufacturer"})  # fmt: skip
    accelerator_names: Optional[List[str]] = field(factory=list, metadata={"description": "The accelerators that must be on the instance type.   For instance types with NVIDIA A10G GPUs, specify a10g.   For instance types with NVIDIA A100 GPUs, specify a100.   For instance types with NVIDIA H100 GPUs, specify h100.   For instance types with Amazon Web Services Inferentia chips, specify inferentia.   For instance types with NVIDIA GRID K520 GPUs, specify k520.   For instance types with NVIDIA K80 GPUs, specify k80.   For instance types with NVIDIA M60 GPUs, specify m60.   For instance types with AMD Radeon Pro V520 GPUs, specify radeon-pro-v520.   For instance types with NVIDIA T4 GPUs, specify t4.   For instance types with NVIDIA T4G GPUs, specify t4g.   For instance types with Xilinx VU9P FPGAs, specify vu9p.   For instance types with NVIDIA V100 GPUs, specify v100.   Default: Any accelerator"})  # fmt: skip
    accelerator_total_memory_mi_b: Optional[AwsEc2LaunchTemplateAcceleratorTotalMemoryMiB] = field(default=None, metadata={"description": "The minimum and maximum amount of total accelerator memory, in MiB. Default: No minimum or maximum limits"})  # fmt: skip
    network_bandwidth_gbps: Optional[AwsEc2LaunchTemplateNetworkBandwidthGbps] = field(default=None, metadata={"description": "The minimum and maximum amount of network bandwidth, in gigabits per second (Gbps). Default: No minimum or maximum limits"})  # fmt: skip
    allowed_instance_types: Optional[List[str]] = field(factory=list, metadata={"description": "The instance types to apply your specified attributes against. All other instance types are ignored, even if they match your specified attributes. You can use strings with one or more wild cards, represented by an asterisk (*), to allow an instance type, size, or generation. The following are examples: m5.8xlarge, c5*.*, m5a.*, r*, *3*. For example, if you specify c5*,Amazon EC2 will allow the entire C5 instance family, which includes all C5a and C5n instance types. If you specify m5a.*, Amazon EC2 will allow all the M5a instance types, but not the M5n instance types.  If you specify AllowedInstanceTypes, you can't specify ExcludedInstanceTypes.  Default: All instance types"})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplatePrivateDnsNameOptions:
    kind: ClassVar[str] = "aws_ec2_launch_template_private_dns_name_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname_type": S("HostnameType"),
        "enable_resource_name_dns_a_record": S("EnableResourceNameDnsARecord"),
        "enable_resource_name_dns_aaaa_record": S("EnableResourceNameDnsAAAARecord"),
    }
    hostname_type: Optional[str] = field(default=None, metadata={"description": "The type of hostname to assign to an instance."})  # fmt: skip
    enable_resource_name_dns_a_record: Optional[bool] = field(default=None, metadata={"description": "Indicates whether to respond to DNS queries for instance hostnames with DNS A records."})  # fmt: skip
    enable_resource_name_dns_aaaa_record: Optional[bool] = field(default=None, metadata={"description": "Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplateData:
    kind: ClassVar[str] = "aws_ec2_launch_template_data"
    mapping: ClassVar[Dict[str, Bender]] = {
        "kernel_id": S("KernelId"),
        "ebs_optimized": S("EbsOptimized"),
        "iam_instance_profile": S("IamInstanceProfile")
        >> Bend(AwsEc2LaunchTemplateIamInstanceProfileSpecification.mapping),
        "block_device_mappings": S("BlockDeviceMappings", default=[])
        >> ForallBend(AwsEc2LaunchTemplateBlockDeviceMapping.mapping),
        "network_interfaces": S("NetworkInterfaces", default=[])
        >> ForallBend(AwsEc2LaunchTemplateInstanceNetworkInterfaceSpecification.mapping),
        "image_id": S("ImageId"),
        "instance_type": S("InstanceType"),
        "key_name": S("KeyName"),
        "monitoring": S("Monitoring", "Enabled"),
        "placement": S("Placement") >> Bend(AwsEc2LaunchTemplatePlacement.mapping),
        "ram_disk_id": S("RamDiskId"),
        "disable_api_termination": S("DisableApiTermination"),
        "instance_initiated_shutdown_behavior": S("InstanceInitiatedShutdownBehavior"),
        "user_data": S("UserData"),
        "tag_specifications": S("TagSpecifications", default=[])
        >> ForallBend(AwsEc2LaunchTemplateTagSpecification.mapping),
        "elastic_gpu_specifications": S("ElasticGpuSpecifications", default=[]) >> ForallBend(S("Type")),
        "elastic_inference_accelerators": S("ElasticInferenceAccelerators", default=[])
        >> ForallBend(AwsEc2LaunchTemplateElasticInferenceAcceleratorResponse.mapping),
        "security_group_ids": S("SecurityGroupIds", default=[]),
        "security_groups": S("SecurityGroups", default=[]),
        "instance_market_options": S("InstanceMarketOptions")
        >> Bend(AwsEc2LaunchTemplateInstanceMarketOptions.mapping),
        "credit_specification": S("CreditSpecification", "CpuCredits"),
        "cpu_options": S("CpuOptions") >> Bend(AwsEc2LaunchTemplateCpuOptions.mapping),
        "capacity_reservation_specification": S("CapacityReservationSpecification")
        >> Bend(AwsEc2LaunchTemplateCapacityReservationSpecificationResponse.mapping),
        "license_specifications": S("LicenseSpecifications", default=[]) >> ForallBend(S("LicenseConfigurationArn")),
        "hibernation_options": S("HibernationOptions", "Configured"),
        "metadata_options": S("MetadataOptions") >> Bend(AwsEc2LaunchTemplateInstanceMetadataOptions.mapping),
        "enclave_options": S("EnclaveOptions", "Enabled"),
        "instance_requirements": S("InstanceRequirements") >> Bend(AwsEc2LaunchTemplateInstanceRequirements.mapping),
        "private_dns_name_options": S("PrivateDnsNameOptions")
        >> Bend(AwsEc2LaunchTemplatePrivateDnsNameOptions.mapping),
        "maintenance_options": S("MaintenanceOptions", "AutoRecovery"),
        "disable_api_stop": S("DisableApiStop"),
    }
    kernel_id: Optional[str] = field(default=None, metadata={"description": "The ID of the kernel, if applicable."})  # fmt: skip
    ebs_optimized: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the instance is optimized for Amazon EBS I/O."})  # fmt: skip
    iam_instance_profile: Optional[AwsEc2LaunchTemplateIamInstanceProfileSpecification] = field(default=None, metadata={"description": "The IAM instance profile."})  # fmt: skip
    block_device_mappings: Optional[List[AwsEc2LaunchTemplateBlockDeviceMapping]] = field(factory=list, metadata={"description": "The block device mappings."})  # fmt: skip
    network_interfaces: Optional[List[AwsEc2LaunchTemplateInstanceNetworkInterfaceSpecification]] = field(factory=list, metadata={"description": "The network interfaces."})  # fmt: skip
    image_id: Optional[str] = field(default=None, metadata={"description": "The ID of the AMI or a Systems Manager parameter. The Systems Manager parameter will resolve to the ID of the AMI at instance launch. The value depends on what you specified in the request. The possible values are:   If an AMI ID was specified in the request, then this is the AMI ID.   If a Systems Manager parameter was specified in the request, and ResolveAlias was configured as true, then this is the AMI ID that the parameter is mapped to in the Parameter Store.   If a Systems Manager parameter was specified in the request, and ResolveAlias was configured as false, then this is the parameter value.   For more information, see Use a Systems Manager parameter instead of an AMI ID in the Amazon Elastic Compute Cloud User Guide."})  # fmt: skip
    instance_type: Optional[str] = field(default=None, metadata={"description": "The instance type."})  # fmt: skip
    key_name: Optional[str] = field(default=None, metadata={"description": "The name of the key pair."})  # fmt: skip
    monitoring: Optional[bool] = field(default=None, metadata={"description": "The monitoring for the instance."})  # fmt: skip
    placement: Optional[AwsEc2LaunchTemplatePlacement] = field(default=None, metadata={"description": "The placement of the instance."})  # fmt: skip
    ram_disk_id: Optional[str] = field(default=None, metadata={"description": "The ID of the RAM disk, if applicable."})  # fmt: skip
    disable_api_termination: Optional[bool] = field(default=None, metadata={"description": "If set to true, indicates that the instance cannot be terminated using the Amazon EC2 console, command line tool, or API."})  # fmt: skip
    instance_initiated_shutdown_behavior: Optional[str] = field(default=None, metadata={"description": "Indicates whether an instance stops or terminates when you initiate shutdown from the instance (using the operating system command for system shutdown)."})  # fmt: skip
    user_data: Optional[str] = field(default=None, metadata={"description": "The user data for the instance."})  # fmt: skip
    tag_specifications: Optional[List[AwsEc2LaunchTemplateTagSpecification]] = field(factory=list, metadata={"description": "The tags that are applied to the resources that are created during instance launch."})  # fmt: skip
    elastic_gpu_specifications: Optional[List[str]] = field(factory=list, metadata={"description": "The elastic GPU specification."})  # fmt: skip
    elastic_inference_accelerators: Optional[List[AwsEc2LaunchTemplateElasticInferenceAcceleratorResponse]] = field(factory=list, metadata={"description": "An elastic inference accelerator to associate with the instance. Elastic inference accelerators are a resource you can attach to your Amazon EC2 instances to accelerate your Deep Learning (DL) inference workloads. You cannot specify accelerators from different generations in the same request.  Starting April 15, 2023, Amazon Web Services will not onboard new customers to Amazon Elastic Inference (EI), and will help current customers migrate their workloads to options that offer better price and performance. After April 15, 2023, new customers will not be able to launch instances with Amazon EI accelerators in Amazon SageMaker, Amazon ECS, or Amazon EC2. However, customers who have used Amazon EI at least once during the past 30-day period are considered current customers and will be able to continue using the service."})  # fmt: skip
    security_group_ids: Optional[List[str]] = field(factory=list, metadata={"description": "The security group IDs."})  # fmt: skip
    security_groups: Optional[List[str]] = field(factory=list, metadata={"description": "The security group names."})  # fmt: skip
    instance_market_options: Optional[AwsEc2LaunchTemplateInstanceMarketOptions] = field(default=None, metadata={"description": "The market (purchasing) option for the instances."})  # fmt: skip
    credit_specification: Optional[str] = field(default=None, metadata={"description": "The credit option for CPU usage of the instance."})  # fmt: skip
    cpu_options: Optional[AwsEc2LaunchTemplateCpuOptions] = field(default=None, metadata={"description": "The CPU options for the instance. For more information, see Optimizing CPU options in the Amazon Elastic Compute Cloud User Guide."})  # fmt: skip
    capacity_reservation_specification: Optional[AwsEc2LaunchTemplateCapacityReservationSpecificationResponse] = field(default=None, metadata={"description": "Information about the Capacity Reservation targeting option."})  # fmt: skip
    license_specifications: Optional[List[str]] = field(factory=list, metadata={"description": "The license configurations."})  # fmt: skip
    hibernation_options: Optional[bool] = field(default=None, metadata={"description": "Indicates whether an instance is configured for hibernation. For more information, see Hibernate your instance in the Amazon Elastic Compute Cloud User Guide."})  # fmt: skip
    metadata_options: Optional[AwsEc2LaunchTemplateInstanceMetadataOptions] = field(default=None, metadata={"description": "The metadata options for the instance. For more information, see Instance metadata and user data in the Amazon Elastic Compute Cloud User Guide."})  # fmt: skip
    enclave_options: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the instance is enabled for Amazon Web Services Nitro Enclaves."})  # fmt: skip
    instance_requirements: Optional[AwsEc2LaunchTemplateInstanceRequirements] = field(default=None, metadata={"description": "The attributes for the instance types. When you specify instance attributes, Amazon EC2 will identify instance types with these attributes. If you specify InstanceRequirements, you can't specify InstanceTypes."})  # fmt: skip
    private_dns_name_options: Optional[AwsEc2LaunchTemplatePrivateDnsNameOptions] = field(default=None, metadata={"description": "The options for the instance hostname."})  # fmt: skip
    maintenance_options: Optional[str] = field(default=None, metadata={"description": "The maintenance options for your instance."})  # fmt: skip
    disable_api_stop: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the instance is enabled for stop protection. For more information, see Stop protection in the Amazon Elastic Compute Cloud User Guide."})  # fmt: skip


@define(eq=False, slots=False)
class AwsEc2LaunchTemplate(EC2Taggable, AwsResource):
    kind: ClassVar[str] = "aws_ec2_launch_template"
    kind_display: ClassVar[str] = "AWS EC2 Launch Template"
    kind_description: ClassVar[str] = "An AWS EC2 Launch Template provides a configurable blueprint for launching EC2 instances, allowing for the specification of settings like instance type, AMI, security groups, and block device mappings for consistency and automation in instance creation."  # fmt: skip
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/ec2/v2/home?region={region}#LaunchTemplateDetails:launchTemplateId={LaunchTemplateId}", "arn_tpl": "arn:{partition}:ec2:{region}:{account}:launch-template/{id}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        "ec2", "describe-launch-template-versions", "LaunchTemplateVersions", {"Versions": ["$Default"]}
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("LaunchTemplateId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("LaunchTemplateName"),
        "ctime": S("CreateTime"),
        "version_number": S("VersionNumber"),
        "version_description": S("VersionDescription"),
        "created_by": S("CreatedBy"),
        "is_default_version": S("DefaultVersion"),
        "launch_template_data": S("LaunchTemplateData") >> Bend(AwsEc2LaunchTemplateData.mapping),
    }
    version_number: Optional[int] = field(default=None, metadata={"description": "The version number."})  # fmt: skip
    version_description: Optional[str] = field(default=None, metadata={"description": "The description for the version."})  # fmt: skip
    created_by: Optional[str] = field(default=None, metadata={"description": "The principal that created the version."})  # fmt: skip
    is_default_version: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the version is the default version."})  # fmt: skip
    launch_template_data: Optional[AwsEc2LaunchTemplateData] = field(default=None, metadata={"description": "Information about the launch template."})  # fmt: skip


# endregion

resources: List[Type[AwsResource]] = [
    AwsEc2InstanceType,
    AwsEc2ElasticIp,
    AwsEc2FlowLog,
    AwsEc2Host,
    AwsEc2Instance,
    AwsEc2InternetGateway,
    AwsEc2Image,
    AwsEc2KeyPair,
    AwsEc2LaunchTemplate,
    AwsEc2NatGateway,
    AwsEc2NetworkAcl,
    AwsEc2NetworkInterface,
    AwsEc2ReservedInstances,
    AwsEc2RouteTable,
    AwsEc2SecurityGroup,
    AwsEc2Snapshot,
    AwsEc2Subnet,
    AwsEc2Volume,
    AwsEc2Vpc,
    AwsEc2VpcEndpoint,
    AwsEc2VpcPeeringConnection,
]
