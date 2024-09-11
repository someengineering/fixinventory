from conftest import roundtrip_check, connect_resources
from fix_plugin_azure.resource.base import GraphBuilder, MicrosoftResource
from fix_plugin_azure.resource.containerservice import (
    AzureContainerServiceFleet,
    AzureContainerServiceManagedCluster,
    AzureContainerServiceManagedClusterSnapshot,
)
from fix_plugin_azure.resource.compute import AzureComputeDiskEncryptionSet, AzureComputeVirtualMachineScaleSet
from typing import List, Type


def test_fleet(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureContainerServiceFleet, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureContainerServiceManagedCluster]
    roundtrip_check(AzureContainerServiceManagedCluster, builder)

    connect_resources(builder, resource_types)
    assert len(builder.edges_of(AzureContainerServiceFleet, AzureContainerServiceManagedCluster)) == 1


def test_managed_cluster(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureContainerServiceManagedCluster, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureComputeDiskEncryptionSet, AzureComputeVirtualMachineScaleSet]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureContainerServiceManagedCluster, AzureComputeDiskEncryptionSet)) == 1
    assert len(builder.edges_of(AzureContainerServiceManagedCluster, AzureComputeVirtualMachineScaleSet)) == 1


def test_kub_snapshot(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureContainerServiceManagedClusterSnapshot, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureContainerServiceManagedCluster]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureContainerServiceManagedCluster, AzureContainerServiceManagedClusterSnapshot)) == 1
