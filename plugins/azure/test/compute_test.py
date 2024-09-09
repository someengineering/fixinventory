from conftest import roundtrip_check, connect_resources
from fix_plugin_azure.resource.base import GraphBuilder, MicrosoftResource
from fix_plugin_azure.resource.compute import *
from fix_plugin_azure.resource.network import (
    AzureNetworkLoadBalancer,
    AzureNetworkInterface,
    AzureNetworkSecurityGroup,
)
from fixlib.baseresources import VolumeStatus, InstanceStatus
from typing import List, Type


def test_availability_sets(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeAvailabilitySet, builder)
    assert len(collected) == 4

    resource_types: List[Type[MicrosoftResource]] = [AzureComputeProximityPlacementGroup, AzureComputeVirtualMachine]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureComputeAvailabilitySet, AzureComputeProximityPlacementGroup)) == 2
    assert len(builder.edges_of(AzureComputeAvailabilitySet, AzureComputeVirtualMachine)) == 2


def test_capacity_reservation_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeCapacityReservationGroup, builder)
    assert len(collected) == 2

    resource_type: List[Type[MicrosoftResource]] = [AzureComputeVirtualMachine]
    connect_resources(builder, resource_type)

    assert len(builder.edges_of(AzureComputeCapacityReservationGroup, AzureComputeVirtualMachine)) == 2


def test_cloud_service(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeCloudService, builder)
    assert len(collected) == 1


def test_dedicated_host_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeDedicatedHostGroup, builder)
    assert len(collected) == 1


def test_disks(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeDisk, builder, all_props=True, ignore_props={"etag"})
    assert len(collected) == 3

    resource_types: List[Type[MicrosoftResource]] = [AzureComputeDiskEncryptionSet]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureComputeDisk, AzureComputeDiskEncryptionSet)) == 2

    first = collected[0]
    assert first.volume_size == 200
    assert first.volume_type == "Premium_LRS"
    assert first.volume_status == VolumeStatus.UNKNOWN
    assert first.volume_iops == 120
    assert first.volume_throughput == 25
    assert first.volume_encrypted is True


def test_disk_access(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeDiskAccess, builder)
    assert len(collected) == 2


def test_disk_encryption_set(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeDiskEncryptionSet, builder)
    assert len(collected) == 2


def test_gallery(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeGallery, builder)
    assert len(collected) == 1


def test_image(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeImage, builder)
    assert len(collected) == 1


def test_placement_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeProximityPlacementGroup, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureComputeVirtualMachineScaleSet]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureComputeProximityPlacementGroup, AzureComputeVirtualMachineScaleSet)) == 1


def test_restore_point_collection(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeRestorePointCollection, builder)
    assert len(collected) == 2

    resource_type: List[Type[MicrosoftResource]] = [AzureComputeVirtualMachine]
    connect_resources(builder, resource_type)

    assert len(builder.edges_of(AzureComputeRestorePointCollection, AzureComputeVirtualMachine)) == 2


def test_ssh_key(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeSshPublicKey, builder)
    assert len(collected) == 1


def test_virtual_machine(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeVirtualMachine, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [
        AzureComputeProximityPlacementGroup,
        AzureComputeImage,
        AzureComputeDisk,
        AzureNetworkInterface,
        AzureNetworkSecurityGroup,
        AzureNetworkLoadBalancer,
        AzureComputeVirtualMachineSize,
    ]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureComputeProximityPlacementGroup, AzureComputeVirtualMachine)) == 2
    assert len(builder.edges_of(AzureComputeVirtualMachine, AzureComputeImage)) == 2
    assert len(builder.edges_of(AzureComputeVirtualMachine, AzureComputeDisk)) == 2
    assert len(builder.edges_of(AzureComputeVirtualMachine, AzureNetworkInterface)) == 1
    assert len(builder.edges_of(AzureNetworkSecurityGroup, AzureComputeVirtualMachine)) == 1
    assert len(builder.edges_of(AzureNetworkLoadBalancer, AzureComputeVirtualMachine)) == 1
    assert len(builder.edges_of(AzureComputeVirtualMachine, AzureComputeVirtualMachineSize)) == 2


def test_virtual_machine_resources(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeVirtualMachine, builder)[0]
    assert collected.instance_type == "Standard_A1_V2"
    assert collected.instance_status == InstanceStatus.RUNNING


def test_virtual_machine_scale_set(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeVirtualMachineScaleSet, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [
        AzureNetworkLoadBalancer,
    ]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkLoadBalancer, AzureComputeVirtualMachineScaleSet)) == 1


def test_snapshot(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeVirtualMachineSnapshot, builder)
    assert len(collected) == 2

    resource_type: List[Type[MicrosoftResource]] = [AzureComputeDisk]
    connect_resources(builder, resource_type)

    assert len(builder.edges_of(AzureComputeDisk, AzureComputeVirtualMachineSnapshot)) == 1


def test_snapshot_resources(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeVirtualMachineSnapshot, builder)[1]
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
