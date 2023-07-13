from conftest import roundtrip_check
from resoto_plugin_azure.resource.base import GraphBuilder
from resoto_plugin_azure.resource.compute import *


def test_availability_sets(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAvailabilitySet, graph_builder)
    assert len(collected) == 4


def test_capacity_reservation_group(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCapacityReservationGroup, graph_builder)
    assert len(collected) == 2


def test_cloud_service(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCloudService, graph_builder)
    assert len(collected) == 1


def test_compute_operation_value(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureComputeOperationValue, graph_builder)
    assert len(collected) == 1


def test_dedicated_host_group(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDedicatedHostGroup, graph_builder)
    assert len(collected) == 1


def test_disks(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDisk, graph_builder, all_props=True)
    assert len(collected) == 3


def test_disk_access(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDiskAccess, graph_builder)
    assert len(collected) == 2


def test_disk_encryption_set(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDiskEncryptionSet, graph_builder)
    assert len(collected) == 2


def test_gallery(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureGallery, graph_builder)
    assert len(collected) == 1


def test_image(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureImage, graph_builder)
    assert len(collected) == 1


def test_placement_group(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureProximityPlacementGroup, graph_builder)
    assert len(collected) == 1


def test_sku(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureResourceSku, graph_builder)
    assert len(collected) == 3


def test_restore_point_collection(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureRestorePointCollection, graph_builder)
    assert len(collected) == 2


def test_ssh_key(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSshPublicKeyResource, graph_builder)
    assert len(collected) == 1


def test_virtual_machine(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachine, graph_builder)
    assert len(collected) == 2


def test_scale_set(graph_builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualMachineScaleSet, graph_builder)
    assert len(collected) == 1
