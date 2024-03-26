import os
import json
from queue import Queue
from typing import List, Type

from conftest import connect_resources

from fix_plugin_azure.azure_client import AzureClient
from fix_plugin_azure.collector import AzureSubscriptionCollector
from fix_plugin_azure.config import AzureCredentials, AzureConfig
from fix_plugin_azure.resource.base import AzureResource, AzureSubscription, GraphBuilder
from fix_plugin_azure.resource.compute import AzureVirtualMachine, AzureVirtualMachineSize, AzureDisk, AzureDiskType
from fixlib.baseresources import Cloud
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph


def collector_with_graph(
    graph: Graph,
    credentials: AzureCredentials,
) -> AzureSubscriptionCollector:
    collector = AzureSubscriptionCollector(
        config=AzureConfig(),
        cloud=Cloud(id="azure"),
        subscription=AzureSubscription(id="test", subscription_id="test"),
        credentials=credentials,
        core_feedback=CoreFeedback("test", "test", "test", Queue()),
    )
    collector.graph = graph
    return collector


def test_collect(
    config: AzureConfig,
    azure_subscription: AzureSubscription,
    credentials: AzureCredentials,
    core_feedback: CoreFeedback,
    azure_client: AzureClient,
) -> None:
    collector = AzureSubscriptionCollector(config, Cloud(id="azure"), azure_subscription, credentials, core_feedback)
    collector.collect()
    assert len(collector.graph.nodes) == 201
    assert len(collector.graph.edges) == 277


def test_filter(credentials: AzureCredentials, builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/compute/vmSizes.json") as f:
        AzureVirtualMachineSize.collect(raw=json.load(f)["value"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/virtualMachines.json") as f:
        AzureVirtualMachine.collect(raw=json.load(f)["value"], builder=builder)

    collector = collector_with_graph(builder.graph, credentials)

    num_all_virtual_machine_types = list(collector.graph.search("kind", "azure_virtual_machine_size"))

    collector.filter_nodes()

    assert len(list(collector.graph.search("kind", "azure_virtual_machine_size"))) < len(num_all_virtual_machine_types)


def test_collect_cost(credentials: AzureCredentials, builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/compute/vmSizes.json") as f:
        AzureVirtualMachineSize.collect(raw=json.load(f)["value"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/virtualMachines.json") as f:
        AzureVirtualMachine.collect(raw=json.load(f)["value"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/prices.json") as f:
        AzureDiskType.collect(raw=json.load(f)["Items"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/disks.json") as f:
        AzureDisk.collect(raw=json.load(f)["value"], builder=builder)

    collector = collector_with_graph(builder.graph, credentials)

    resource_types: List[Type[AzureResource]] = [
        AzureVirtualMachine,
        AzureDisk,
    ]
    connect_resources(builder, resource_types)

    for node, data in list(collector.graph.nodes(data=True)):
        if isinstance(node, AzureVirtualMachineSize):
            node.after_collect(builder, data.get("source", {}))

    assert list(collector.graph.search("kind", "azure_virtual_machine_size"))[0].ondemand_cost == 13.14  # type: ignore[attr-defined]
    assert list(collector.graph.search("kind", "azure_disk_type"))[2].ondemand_cost == 0.3640833333333333  # type: ignore[attr-defined]
