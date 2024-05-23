from conftest import roundtrip_check, connect_resources
from fix_plugin_azure.resource.base import GraphBuilder, AzureResource
from fix_plugin_azure.resource.containerservice import AzureFleet, AzureManagedCluster, AzureManagedClusterSnapshot
from fix_plugin_azure.resource.compute import AzureDiskEncryptionSet, AzureVirtualMachineScaleSet
from typing import List, Type


def test_fleet(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureFleet, builder)
    assert len(collected) == 1

    resource_types: List[Type[AzureResource]] = [AzureManagedCluster]
    roundtrip_check(AzureManagedCluster, builder)

    connect_resources(builder, resource_types)
    assert len(builder.edges_of(AzureFleet, AzureManagedCluster)) == 1


def test_managed_cluster(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureManagedCluster, builder)
    assert len(collected) == 1

    resource_types: List[Type[AzureResource]] = [AzureDiskEncryptionSet, AzureVirtualMachineScaleSet]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureManagedCluster, AzureDiskEncryptionSet)) == 1
    assert len(builder.edges_of(AzureManagedCluster, AzureVirtualMachineScaleSet)) == 1


def test_kub_snapshot(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureManagedClusterSnapshot, builder)
    assert len(collected) == 1

    resource_types: List[Type[AzureResource]] = [AzureManagedCluster]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureManagedCluster, AzureManagedClusterSnapshot)) == 1
