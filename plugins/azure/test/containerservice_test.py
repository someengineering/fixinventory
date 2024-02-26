from conftest import roundtrip_check, connect_resources
from fix_plugin_azure.resource.base import GraphBuilder, AzureResource
from fix_plugin_azure.resource.containerservice import AzureFleet, AzureManagedCluster, AzureKubernetesSnapshot
from fix_plugin_azure.resource.compute import AzureDiskEncryptionSet
from typing import List, Type


def test_fleet(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureFleet, builder)
    assert len(collected) == 1

    resource_types: List[Type[AzureResource]] = [AzureManagedCluster]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureFleet, AzureManagedCluster)) == 1


def test_managed_cluster(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureManagedCluster, builder)
    assert len(collected) == 1

    resource_types: List[Type[AzureResource]] = [AzureDiskEncryptionSet]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureManagedCluster, AzureDiskEncryptionSet)) == 1


def test_kub_snapshot(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureKubernetesSnapshot, builder)
    assert len(collected) == 1

    resource_types: List[Type[AzureResource]] = [AzureManagedCluster]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureManagedCluster, AzureKubernetesSnapshot)) == 1
