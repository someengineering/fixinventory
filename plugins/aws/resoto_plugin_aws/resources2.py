from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from resoto_plugin_aws.base import AWSResource, GraphBuilder
from resoto_plugin_aws.resources import AWSEC2InstanceType
from resoto_plugin_aws.utils import TagsToDict, TagsValue
from resotolib.baseresources import BaseInstance, BaseAccount, EdgeType, BaseVolume
from resotolib.json_bender import Bender, S, Bend, ForallBend, K, bend
from resotolib.types import Json


# region Volume


@dataclass(eq=False)
class AWSEC2VolumeAttachment:
    kind: ClassVar[str] = "aws_ec2_volume_attachment"
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


@dataclass(eq=False)
class AWSEC2Volume(AWSResource, BaseVolume):
    kind: ClassVar[str] = "aws_ec2_volume"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("VolumeId"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("CreateTime"),
        "volume_size": S("Size"),
        "volume_type": S("VolumeType"),
        "volume_status": S("State"),
        "volume_iops": S("Iops"),
        "volume_throughput": S("Throughput"),
        "volume_encrypted": S("Encrypted"),
        "volume_attachments": S("Attachments", default=[]) >> ForallBend(AWSEC2VolumeAttachment.mapping),
        "availability_zone": S("AvailabilityZone"),
        "volume_kms_key_id": S("KmsKeyId"),
        "volume_outpost_arn": S("OutpostArn"),
        "volume_snapshot_id": S("SnapshotId"),
        "volume_fast_restored": S("FastRestored"),
        "volume_multi_attach_enabled": S("MultiAttachEnabled"),
    }
    volume_attachments: List[AWSEC2VolumeAttachment] = field(default_factory=list)
    availability_zone: Optional[str] = field(default=None)
    volume_encrypted: Optional[bool] = field(default=None)
    volume_kms_key_id: Optional[str] = field(default=None)
    volume_outpost_arn: Optional[str] = field(default=None)
    volume_size: Optional[int] = field(default=None)
    volume_snapshot_id: Optional[str] = field(default=None)
    volume_iops: Optional[int] = field(default=None)
    volume_fast_restored: Optional[bool] = field(default=None)
    volume_multi_attach_enabled: Optional[bool] = field(default=None)
    volume_throughput: Optional[int] = field(default=None)

    def _volume_status_getter(self) -> str:
        return self._volume_status

    def _volume_status_setter(self, value: str) -> None:
        self._volume_status = value

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        builder.add_edge(self, EdgeType.default, reverse=True, name=self.volume_type)
        for attachment in self.volume_attachments:
            builder.add_edge(self, EdgeType.default, clazz=AWSEC2Instance, id=attachment.instance_id)
            builder.add_edge(self, EdgeType.delete, reverse=True, clazz=AWSEC2Instance, id=attachment.instance_id)


AWSEC2Volume.volume_status = property(AWSEC2Volume._volume_status_getter, AWSEC2Volume._volume_status_setter)


# endregion

# region KeyPair


@dataclass(eq=False)
class AWSEC2KeyPair(AWSResource):
    kind: ClassVar[str] = "aws_ec2_key_pair_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("KeyPairId"),
        "name": S("KeyName"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
        "key_fingerprint": S("KeyFingerprint"),
        "key_type": S("KeyType"),
        "public_key": S("PublicKey"),
        "ctime": S("CreateTime"),
    }
    key_pair_id: Optional[str] = field(default=None)
    key_fingerprint: Optional[str] = field(default=None)
    key_name: Optional[str] = field(default=None)
    key_type: Optional[str] = field(default=None)
    public_key: Optional[str] = field(default=None)
    create_time: Optional[datetime] = field(default=None)


# endregion

# region Instance


@dataclass(eq=False)
class AWSEC2Placement:
    kind: ClassVar[str] = "aws_ec2_placement"
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


@dataclass(eq=False)
class AWSEC2ProductCode:
    kind: ClassVar[str] = "aws_ec2_product_code"
    mapping: ClassVar[Dict[str, Bender]] = {
        "product_code_id": S("ProductCodeId"),
        "product_code_type": S("ProductCodeType"),
    }
    product_code_id: Optional[str] = field(default=None)
    product_code_type: Optional[str] = field(default=None)


@dataclass(eq=False)
class AWSEC2InstanceState:
    kind: ClassVar[str] = "aws_ec2_instance_state"
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "name": S("Name")}
    code: Optional[int] = field(default=None)
    name: Optional[str] = field(default=None)


@dataclass(eq=False)
class AWSEC2EbsInstanceBlockDevice:
    kind: ClassVar[str] = "aws_ec2_ebs_instance_block_device"
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


@dataclass(eq=False)
class AWSEC2InstanceBlockDeviceMapping:
    kind: ClassVar[str] = "aws_ec2_instance_block_device_mapping"
    mapping: ClassVar[Dict[str, Bender]] = {
        "device_name": S("DeviceName"),
        "ebs": S("Ebs") >> Bend(AWSEC2EbsInstanceBlockDevice.mapping),
    }
    device_name: Optional[str] = field(default=None)
    ebs: Optional[AWSEC2EbsInstanceBlockDevice] = field(default=None)


@dataclass(eq=False)
class AWSEC2IamInstanceProfile:
    kind: ClassVar[str] = "aws_ec2_iam_instance_profile"
    mapping: ClassVar[Dict[str, Bender]] = {"arn": S("Arn"), "id": S("Id")}
    arn: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)


@dataclass(eq=False)
class AWSEC2ElasticGpuAssociation:
    kind: ClassVar[str] = "aws_ec2_elastic_gpu_association"
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


@dataclass(eq=False)
class AWSEC2ElasticInferenceAcceleratorAssociation:
    kind: ClassVar[str] = "aws_ec2_elastic_inference_accelerator_association"
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


@dataclass(eq=False)
class AWSEC2InstanceNetworkInterfaceAssociation:
    kind: ClassVar[str] = "aws_ec2_instance_network_interface_association"
    mapping: ClassVar[Dict[str, Bender]] = {
        "carrier_ip": S("CarrierIp"),
        "customer_owned_ip": S("CustomerOwnedIp"),
        "ip_owner_id": S("IpOwnerId"),
        "public_dns_name": S("PublicDnsName"),
        "public_ip": S("PublicIp"),
    }
    carrier_ip: Optional[str] = field(default=None)
    customer_owned_ip: Optional[str] = field(default=None)
    ip_owner_id: Optional[str] = field(default=None)
    public_dns_name: Optional[str] = field(default=None)
    public_ip: Optional[str] = field(default=None)


@dataclass(eq=False)
class AWSEC2InstanceNetworkInterfaceAttachment:
    kind: ClassVar[str] = "aws_ec2_instance_network_interface_attachment"
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


@dataclass(eq=False)
class AWSEC2GroupIdentifier:
    kind: ClassVar[str] = "aws_ec2_group_identifier"
    mapping: ClassVar[Dict[str, Bender]] = {"group_name": S("GroupName"), "group_id": S("GroupId")}
    group_name: Optional[str] = field(default=None)
    group_id: Optional[str] = field(default=None)


@dataclass(eq=False)
class AWSEC2InstancePrivateIpAddress:
    kind: ClassVar[str] = "aws_ec2_instance_private_ip_address"
    mapping: ClassVar[Dict[str, Bender]] = {
        "association": S("Association") >> Bend(AWSEC2InstanceNetworkInterfaceAssociation.mapping),
        "primary": S("Primary"),
        "private_dns_name": S("PrivateDnsName"),
        "private_ip_address": S("PrivateIpAddress"),
    }
    association: Optional[AWSEC2InstanceNetworkInterfaceAssociation] = field(default=None)
    primary: Optional[bool] = field(default=None)
    private_dns_name: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)


@dataclass(eq=False)
class AWSEC2InstanceNetworkInterface:
    kind: ClassVar[str] = "aws_ec2_instance_network_interface"
    mapping: ClassVar[Dict[str, Bender]] = {
        "association": S("Association") >> Bend(AWSEC2InstanceNetworkInterfaceAssociation.mapping),
        "attachment": S("Attachment") >> Bend(AWSEC2InstanceNetworkInterfaceAttachment.mapping),
        "description": S("Description"),
        "groups": S("Groups", default=[]) >> ForallBend(AWSEC2GroupIdentifier.mapping),
        "ipv6_addresses": S("Ipv6Addresses", default=[]) >> ForallBend(S("Ipv6Address")),
        "mac_address": S("MacAddress"),
        "network_interface_id": S("NetworkInterfaceId"),
        # "owner_id": S("OwnerId"),
        "private_dns_name": S("PrivateDnsName"),
        "private_ip_address": S("PrivateIpAddress"),
        "private_ip_addresses": S("PrivateIpAddresses", default=[])
        >> ForallBend(AWSEC2InstancePrivateIpAddress.mapping),
        "source_dest_check": S("SourceDestCheck"),
        "status": S("Status"),
        # "subnet_id": S("SubnetId"),
        # "vpc_id": S("VpcId"),
        "interface_type": S("InterfaceType"),
        "ipv4_prefixes": S("Ipv4Prefixes", default=[]) >> ForallBend(S("Ipv4Prefix")),
        "ipv6_prefixes": S("Ipv6Prefixes", default=[]) >> ForallBend(S("Ipv6Prefix")),
    }
    association: Optional[AWSEC2InstanceNetworkInterfaceAssociation] = field(default=None)
    attachment: Optional[AWSEC2InstanceNetworkInterfaceAttachment] = field(default=None)
    description: Optional[str] = field(default=None)
    groups: List[AWSEC2GroupIdentifier] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    mac_address: Optional[str] = field(default=None)
    network_interface_id: Optional[str] = field(default=None)
    private_dns_name: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)
    private_ip_addresses: List[AWSEC2InstancePrivateIpAddress] = field(default_factory=list)
    source_dest_check: Optional[bool] = field(default=None)
    status: Optional[str] = field(default=None)
    interface_type: Optional[str] = field(default=None)
    ipv4_prefixes: List[str] = field(default_factory=list)
    ipv6_prefixes: List[str] = field(default_factory=list)


@dataclass(eq=False)
class AWSEC2StateReason:
    kind: ClassVar[str] = "aws_ec2_state_reason"
    mapping: ClassVar[Dict[str, Bender]] = {"code": S("Code"), "message": S("Message")}
    code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)


@dataclass(eq=False)
class AWSEC2CpuOptions:
    kind: ClassVar[str] = "aws_ec2_cpu_options"
    mapping: ClassVar[Dict[str, Bender]] = {"core_count": S("CoreCount"), "threads_per_core": S("ThreadsPerCore")}
    core_count: Optional[int] = field(default=None)
    threads_per_core: Optional[int] = field(default=None)


@dataclass(eq=False)
class AWSEC2CapacityReservationTargetResponse:
    kind: ClassVar[str] = "aws_ec2_capacity_reservation_target_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_reservation_id": S("CapacityReservationId"),
        "capacity_reservation_resource_group_arn": S("CapacityReservationResourceGroupArn"),
    }
    capacity_reservation_id: Optional[str] = field(default=None)
    capacity_reservation_resource_group_arn: Optional[str] = field(default=None)


@dataclass(eq=False)
class AWSEC2CapacityReservationSpecificationResponse:
    kind: ClassVar[str] = "aws_ec2_capacity_reservation_specification_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "capacity_reservation_preference": S("CapacityReservationPreference"),
        "capacity_reservation_target": S("CapacityReservationTarget")
        >> Bend(AWSEC2CapacityReservationTargetResponse.mapping),
    }
    capacity_reservation_preference: Optional[str] = field(default=None)
    capacity_reservation_target: Optional[AWSEC2CapacityReservationTargetResponse] = field(default=None)


@dataclass(eq=False)
class AWSEC2InstanceMetadataOptionsResponse:
    kind: ClassVar[str] = "aws_ec2_instance_metadata_options_response"
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


@dataclass(eq=False)
class AWSEC2PrivateDnsNameOptionsResponse:
    kind: ClassVar[str] = "aws_ec2_private_dns_name_options_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hostname_type": S("HostnameType"),
        "enable_resource_name_dns_a_record": S("EnableResourceNameDnsARecord"),
        "enable_resource_name_dns_aaaa_record": S("EnableResourceNameDnsAAAARecord"),
    }
    hostname_type: Optional[str] = field(default=None)
    enable_resource_name_dns_a_record: Optional[bool] = field(default=None)
    enable_resource_name_dns_aaaa_record: Optional[bool] = field(default=None)


@dataclass(eq=False)
class AWSEC2Instance(AWSResource, BaseInstance):
    kind: ClassVar[str] = "aws_ec2_instance"
    mapping: ClassVar[Dict[str, Bender]] = {
        # base properties
        "id": S("InstanceId"),
        "tags": S("Tags", default=[]) >> TagsToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("LaunchTime"),
        "mtime": K(None),
        "instance_status": S("State", "Name"),
        "instance_cores": S("CpuOptions", "CoreCount"),
        # "instance_memory": cores and memory are set from the instance type
        # specific properties
        "ami_launch_index": S("AmiLaunchIndex"),
        "image_id": S("ImageId"),
        "instance_id": S("InstanceId"),
        "instance_type": S("InstanceType"),
        "kernel_id": S("KernelId"),
        "key_name": S("KeyName"),
        "launch_time": S("LaunchTime"),
        "monitoring": S("Monitoring", "State"),
        "placement": S("Placement") >> Bend(AWSEC2Placement.mapping),
        "platform": S("Platform"),
        "private_dns_name": S("PrivateDnsName"),
        "private_ip_address": S("PrivateIpAddress"),
        "product_codes": S("ProductCodes", default=[]) >> ForallBend(AWSEC2ProductCode.mapping),
        "public_dns_name": S("PublicDnsName"),
        "public_ip_address": S("PublicIpAddress"),
        "ramdisk_id": S("RamdiskId"),
        "state": S("State") >> Bend(AWSEC2InstanceState.mapping),
        "state_transition_reason": S("StateTransitionReason"),
        "subnet_id": S("SubnetId"),
        "vpc_id": S("VpcId"),
        "architecture": S("Architecture"),
        "block_device_mappings": S("BlockDeviceMappings", default=[])
        >> ForallBend(AWSEC2InstanceBlockDeviceMapping.mapping),
        "client_token": S("ClientToken"),
        "ebs_optimized": S("EbsOptimized"),
        "ena_support": S("EnaSupport"),
        "hypervisor": S("Hypervisor"),
        "iam_instance_profile": S("IamInstanceProfile") >> Bend(AWSEC2IamInstanceProfile.mapping),
        "instance_lifecycle": S("InstanceLifecycle"),
        "elastic_gpu_associations": S("ElasticGpuAssociations", default=[])
        >> ForallBend(AWSEC2ElasticGpuAssociation.mapping),
        "elastic_inference_accelerator_associations": S("ElasticInferenceAcceleratorAssociations", default=[])
        >> ForallBend(AWSEC2ElasticInferenceAcceleratorAssociation.mapping),
        "network_interfaces": S("NetworkInterfaces", default=[]) >> ForallBend(AWSEC2InstanceNetworkInterface.mapping),
        "outpost_arn": S("OutpostArn"),
        "root_device_name": S("RootDeviceName"),
        "root_device_type": S("RootDeviceType"),
        "security_groups": S("SecurityGroups", default=[]) >> ForallBend(AWSEC2GroupIdentifier.mapping),
        "source_dest_check": S("SourceDestCheck"),
        "spot_instance_request_id": S("SpotInstanceRequestId"),
        "sriov_net_support": S("SriovNetSupport"),
        "state_reason": S("StateReason") >> Bend(AWSEC2StateReason.mapping),
        "virtualization_type": S("VirtualizationType"),
        "cpu_options": S("CpuOptions") >> Bend(AWSEC2CpuOptions.mapping),
        "capacity_reservation_id": S("CapacityReservationId"),
        "capacity_reservation_specification": S("CapacityReservationSpecification")
        >> Bend(AWSEC2CapacityReservationSpecificationResponse.mapping),
        "hibernation_options": S("HibernationOptions", "Configured"),
        "licenses": S("Licenses", default=[]) >> ForallBend(S("LicenseConfigurationArn")),
        "metadata_options": S("MetadataOptions") >> Bend(AWSEC2InstanceMetadataOptionsResponse.mapping),
        "enclave_options": S("EnclaveOptions", "Enabled"),
        "boot_mode": S("BootMode"),
        "platform_details": S("PlatformDetails"),
        "usage_operation": S("UsageOperation"),
        "usage_operation_update_time": S("UsageOperationUpdateTime"),
        "private_dns_name_options": S("PrivateDnsNameOptions") >> Bend(AWSEC2PrivateDnsNameOptionsResponse.mapping),
        "ipv6_address": S("Ipv6Address"),
        "tpm_support": S("TpmSupport"),
        "maintenance_options": S("MaintenanceOptions", "AutoRecovery"),
    }
    ami_launch_index: Optional[int] = field(default=None)
    image_id: Optional[str] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    kernel_id: Optional[str] = field(default=None)
    key_name: Optional[str] = field(default=None)
    launch_time: Optional[datetime] = field(default=None)
    monitoring: Optional[str] = field(default=None)
    placement: Optional[AWSEC2Placement] = field(default=None)
    platform: Optional[str] = field(default=None)
    private_dns_name: Optional[str] = field(default=None)
    private_ip_address: Optional[str] = field(default=None)
    product_codes: List[AWSEC2ProductCode] = field(default_factory=list)
    public_dns_name: Optional[str] = field(default=None)
    public_ip_address: Optional[str] = field(default=None)
    ramdisk_id: Optional[str] = field(default=None)
    state: Optional[AWSEC2InstanceState] = field(default=None)
    state_transition_reason: Optional[str] = field(default=None)
    subnet_id: Optional[str] = field(default=None)
    vpc_id: Optional[str] = field(default=None)
    architecture: Optional[str] = field(default=None)
    block_device_mappings: List[AWSEC2InstanceBlockDeviceMapping] = field(default_factory=list)
    client_token: Optional[str] = field(default=None)
    ebs_optimized: Optional[bool] = field(default=None)
    ena_support: Optional[bool] = field(default=None)
    hypervisor: Optional[str] = field(default=None)
    iam_instance_profile: Optional[AWSEC2IamInstanceProfile] = field(default=None)
    instance_lifecycle: Optional[str] = field(default=None)
    elastic_gpu_associations: List[AWSEC2ElasticGpuAssociation] = field(default_factory=list)
    elastic_inference_accelerator_associations: List[AWSEC2ElasticInferenceAcceleratorAssociation] = field(
        default_factory=list
    )
    network_interfaces: List[AWSEC2InstanceNetworkInterface] = field(default_factory=list)
    outpost_arn: Optional[str] = field(default=None)
    root_device_name: Optional[str] = field(default=None)
    root_device_type: Optional[str] = field(default=None)
    security_groups: List[AWSEC2GroupIdentifier] = field(default_factory=list)
    source_dest_check: Optional[bool] = field(default=None)
    spot_instance_request_id: Optional[str] = field(default=None)
    sriov_net_support: Optional[str] = field(default=None)
    state_reason: Optional[AWSEC2StateReason] = field(default=None)
    virtualization_type: Optional[str] = field(default=None)
    cpu_options: Optional[AWSEC2CpuOptions] = field(default=None)
    capacity_reservation_id: Optional[str] = field(default=None)
    capacity_reservation_specification: Optional[AWSEC2CapacityReservationSpecificationResponse] = field(default=None)
    hibernation_options: Optional[bool] = field(default=None)
    licenses: List[str] = field(default_factory=list)
    metadata_options: Optional[AWSEC2InstanceMetadataOptionsResponse] = field(default=None)
    enclave_options: Optional[bool] = field(default=None)
    boot_mode: Optional[str] = field(default=None)
    platform_details: Optional[str] = field(default=None)
    usage_operation: Optional[str] = field(default=None)
    usage_operation_update_time: Optional[datetime] = field(default=None)
    private_dns_name_options: Optional[AWSEC2PrivateDnsNameOptionsResponse] = field(default=None)
    ipv6_address: Optional[str] = field(default=None)
    tpm_support: Optional[str] = field(default=None)
    maintenance_options: Optional[str] = field(default=None)

    def _instance_status_getter(self) -> str:
        return self._instance_status

    def _instance_status_setter(self, value: str) -> None:
        self._instance_status = value

    @classmethod
    def collect(cls: Type[AWSResource], json: List[Json], builder: GraphBuilder) -> None:
        for reservation in json:
            for instance_in in reservation["Instances"]:
                mapped = bend(cls.mapping, instance_in)
                instance = AWSEC2Instance.from_json(mapped)
                # copy data from the instance type
                if instance_type := builder.instance_type(instance.instance_type):
                    instance.instance_cores = instance_type.instance_cores
                    instance.instance_memory = instance_type.instance_memory
                builder.add_node(instance, instance_in)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        super().connect_in_graph(builder, source)
        builder.add_edge(self, EdgeType.default, reverse=True, clazz=AWSEC2InstanceType, name=self.instance_type)
        if self.key_name:
            builder.add_edge(self, EdgeType.default, clazz=AWSEC2KeyPair, name=self.key_name)
            builder.add_edge(self, EdgeType.delete, reverse=True, clazz=AWSEC2KeyPair, name=self.key_name)


AWSEC2Instance.instance_status = property(
    AWSEC2Instance._instance_status_getter, AWSEC2Instance._instance_status_setter
)

# endregion
