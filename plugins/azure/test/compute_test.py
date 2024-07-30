from conftest import roundtrip_check, connect_resources
from fix_plugin_azure.resource.base import GraphBuilder, MicrosoftResource
from fix_plugin_azure.resource.compute import *
from fix_plugin_azure.resource.network import (
    AzureLoadBalancer,
    AzureNetworkInterface,
    AzureNetworkSecurityGroup,
)
from fixlib.baseresources import VolumeStatus, InstanceStatus
from typing import List, Type


def test_availability_sets(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAvailabilitySet, builder)
    assert len(collected) == 4

    resource_types: List[Type[MicrosoftResource]] = [AzureProximityPlacementGroup, AzureVirtualMachine]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureAvailabilitySet, AzureProximityPlacementGroup)) == 2
    assert len(builder.edges_of(AzureAvailabilitySet, AzureVirtualMachine)) == 2


def test_capacity_reservation_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCapacityReservationGroup, builder)
    assert len(collected) == 2

    resource_type: List[Type[MicrosoftResource]] = [AzureVirtualMachine]
    connect_resources(builder, resource_type)

    assert len(builder.edges_of(AzureCapacityReservationGroup, AzureVirtualMachine)) == 2


def test_cloud_service(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCloudService, builder)
    assert len(collected) == 1


def test_dedicated_host_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDedicatedHostGroup, builder)
    assert len(collected) == 1


def test_disks(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDisk, builder, all_props=True, ignore_props={"etag"})
    assert len(collected) == 3

    resource_types: List[Type[MicrosoftResource]] = [AzureDiskAccess, AzureDiskEncryptionSet]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureDiskAccess, AzureDisk)) == 2
    assert len(builder.edges_of(AzureDisk, AzureDiskEncryptionSet)) == 2

    first = collected[0]
    assert first.volume_size == 200
    assert first.volume_type == "Premium_LRS"
    assert first.volume_status == VolumeStatus.UNKNOWN
    assert first.volume_iops == 120
    assert first.volume_throughput == 25
    assert first.volume_encrypted is True


def test_disk_type(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDiskType, builder, check_correct_ser=False)
    assert len(collected) > 0

    roundtrip_check(AzureDisk, builder)

    resource_types: List[Type[MicrosoftResource]] = [AzureDisk]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureDisk, AzureDiskType)) == 2


def test_disk_access(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDiskAccess, builder)
    assert len(collected) == 2


def test_disk_encryption_set(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDiskEncryptionSet, builder)
    assert len(collected) == 2


def test_gallery(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureGallery, builder)
    assert len(collected) == 1


def test_image(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureImage, builder)
    assert len(collected) == 1


def test_placement_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureProximityPlacementGroup, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureVirtualMachineScaleSet]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureProximityPlacementGroup, AzureVirtualMachineScaleSet)) == 1


def test_restore_point_collection(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureRestorePointCollection, builder)
    assert len(collected) == 2

    resource_type: List[Type[MicrosoftResource]] = [AzureVirtualMachine]
    connect_resources(builder, resource_type)

    assert len(builder.edges_of(AzureRestorePointCollection, AzureVirtualMachine)) == 2


def test_ssh_key(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSshPublicKeyResource, builder)
    assert len(collected) == 1


def test_virtual_machine(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachine, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [
        AzureProximityPlacementGroup,
        AzureImage,
        AzureDisk,
        AzureNetworkInterface,
        AzureNetworkSecurityGroup,
        AzureLoadBalancer,
        AzureVirtualMachineSize,
    ]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureProximityPlacementGroup, AzureVirtualMachine)) == 2
    assert len(builder.edges_of(AzureVirtualMachine, AzureImage)) == 2
    assert len(builder.edges_of(AzureVirtualMachine, AzureDisk)) == 2
    assert len(builder.edges_of(AzureVirtualMachine, AzureNetworkInterface)) == 1
    assert len(builder.edges_of(AzureNetworkSecurityGroup, AzureVirtualMachine)) == 1
    assert len(builder.edges_of(AzureLoadBalancer, AzureVirtualMachine)) == 1
    assert len(builder.edges_of(AzureVirtualMachine, AzureVirtualMachineSize)) == 2


def test_virtual_machine_resources(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachine, builder)[0]
    assert collected.instance_type == "Standard_A1_V2"
    assert collected.instance_status == InstanceStatus.RUNNING


def test_virtual_machine_scale_set(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachineScaleSet, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [
        AzureLoadBalancer,
    ]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureLoadBalancer, AzureVirtualMachineScaleSet)) == 1


def test_virtual_machine_size(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachineSize, builder)
    assert len(collected) == 12

    resource_types: List[Type[MicrosoftResource]] = [
        AzureVirtualMachine,
    ]
    connect_resources(builder, resource_types)
    assert len(builder.edges_of(AzureVirtualMachine, AzureVirtualMachineSize)) == 2


def test_virtual_machine_size_resources(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachineSize, builder)[0]
    assert collected.instance_type == "Standard_A1_V2"
    assert collected.instance_cores == 1.0
    assert collected.instance_memory == 2.0


def test_snapshot(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachineSnapshot, builder)
    assert len(collected) == 2

    resource_type: List[Type[MicrosoftResource]] = [AzureDisk]
    connect_resources(builder, resource_type)

    assert len(builder.edges_of(AzureDisk, AzureVirtualMachineSnapshot)) == 1


def test_snapshot_resources(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachineSnapshot, builder)[1]
    assert collected.snapshot_status == "None"
    assert (
        collected.volume_id
        == "/subscriptions/{subscriptionId}/resourceGroups/myResourceGroup/providers/Microsoft.Compute/snapshots/mySnapshot2"
    )
    assert collected.volume_size == 200
    assert collected.encrypted is True
    assert (
        collected.owner_id
        == "subscriptions/{subscriptionId}/resourceGroups/myResourceGroup/providers/Microsoft.Storage/storageAccounts/myStorageAccount"
    )
