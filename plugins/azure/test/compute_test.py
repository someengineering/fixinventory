from conftest import roundtrip_check
from resoto_plugin_azure.resource.base import GraphBuilder
from resoto_plugin_azure.resource.compute import *


def test_availability_sets(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAvailabilitySet, builder)
    assert len(collected) == 4


def test_capacity_reservation_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCapacityReservationGroup, builder)
    assert len(collected) == 2


def test_cloud_service(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCloudService, builder)
    assert len(collected) == 1


def test_compute_operation_value(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeOperationValue, builder)
    assert len(collected) == 1


def test_dedicated_host_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDedicatedHostGroup, builder)
    assert len(collected) == 1


def test_disks(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDisk, builder, all_props=True)
    assert len(collected) == 3


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


def test_sku(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureResourceSku, builder)
    assert len(collected) == 3


def test_restore_point_collection(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureRestorePointCollection, builder)
    assert len(collected) == 2


def test_ssh_key(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSshPublicKeyResource, builder)
    assert len(collected) == 1


def test_virtual_machine(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachine, builder)
    assert len(collected) == 2


def test_scale_set(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachineScaleSet, builder)
    assert len(collected) == 1
