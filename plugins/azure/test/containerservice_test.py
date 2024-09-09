from conftest import roundtrip_check, connect_resources
from fix_plugin_azure.resource.base import GraphBuilder, MicrosoftResource
from fix_plugin_azure.resource.containerservice import AzureFleet, AzureManagedCluster, AzureManagedClusterSnapshot
from fix_plugin_azure.resource.compute import AzureComputeDiskEncryptionSet, AzureComputeVirtualMachineScaleSet
from typing import List, Type


def test_fleet(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureFleet, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureManagedCluster]
    roundtrip_check(AzureManagedCluster, builder)

    connect_resources(builder, resource_types)
    assert len(builder.edges_of(AzureFleet, AzureManagedCluster)) == 1


def test_managed_cluster(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureManagedCluster, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureComputeDiskEncryptionSet, AzureComputeVirtualMachineScaleSet]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureManagedCluster, AzureComputeDiskEncryptionSet)) == 1
    assert len(builder.edges_of(AzureManagedCluster, AzureComputeVirtualMachineScaleSet)) == 1


def test_kub_snapshot(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureManagedClusterSnapshot, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureManagedCluster]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureManagedCluster, AzureManagedClusterSnapshot)) == 1
