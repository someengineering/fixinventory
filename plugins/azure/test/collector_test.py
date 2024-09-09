import os
import json
from queue import Queue
from typing import List, Type

from conftest import connect_resources

from fix_plugin_azure.resource.microsoft_graph import MicrosoftGraphOrganization
from fix_plugin_azure.azure_client import MicrosoftClient
from fix_plugin_azure.collector import AzureSubscriptionCollector, MicrosoftGraphOrganizationCollector
from fix_plugin_azure.config import AzureCredentials, AzureConfig
from fix_plugin_azure.resource.base import MicrosoftResource, AzureSubscription, GraphBuilder
from fix_plugin_azure.resource.compute import (
    AzureComputeDiskTypePricing,
    AzureComputeVirtualMachine,
    AzureComputeVirtualMachineSize,
    AzureComputeDisk,
    AzureComputeDiskType,
)
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
        account=AzureSubscription(id="test", subscription_id="test"),
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
    azure_client: MicrosoftClient,
) -> None:
    subscription_collector = AzureSubscriptionCollector(
        config, Cloud(id="azure"), azure_subscription, credentials, core_feedback
    )
    subscription_collector.collect()
    assert len(subscription_collector.graph.nodes) == 646
    assert len(subscription_collector.graph.edges) == 1038

    graph_collector = MicrosoftGraphOrganizationCollector(
        config, Cloud(id="azure"), MicrosoftGraphOrganization(id="test", name="test"), credentials, core_feedback
    )
    graph_collector.collect()

    assert len(graph_collector.graph.nodes) == 14
    assert len(graph_collector.graph.edges) == 13


def test_filter(credentials: AzureCredentials, builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/compute/vmSizes.json") as f:
        AzureComputeVirtualMachineSize.collect(raw=json.load(f)["value"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/virtualMachines.json") as f:
        AzureComputeVirtualMachine.collect(raw=json.load(f)["value"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/calculator.json") as f:
        AzureComputeDiskTypePricing.collect(raw=json.load(f), builder=builder)

    collector = collector_with_graph(builder.graph, credentials)

    num_all_virtual_machine_types = list(collector.graph.search("kind", "azure_compute_virtual_machine_size"))

    collector.remove_unused()

    assert len(list(collector.graph.search("kind", "azure_compute_virtual_machine_size"))) < len(
        num_all_virtual_machine_types
    )

    pricing_info = list(collector.graph.search("kind", "azure_compute_disk_type_pricing"))

    assert len(pricing_info) > 0

    collector.after_collect()
    assert len(list(collector.graph.search("kind", "azure_compute_disk_type_pricing"))) < len(pricing_info)


def test_collect_cost(credentials: AzureCredentials, builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/compute/vmSizes.json") as f:
        AzureComputeVirtualMachineSize.collect(raw=json.load(f)["value"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/virtualMachines.json") as f:
        AzureComputeVirtualMachine.collect(raw=json.load(f)["value"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/prices.json") as f:
        AzureComputeDiskType.collect(raw=json.load(f)["Items"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/disks.json") as f:
        AzureComputeDisk.collect(raw=json.load(f)["value"], builder=builder)

    collector = collector_with_graph(builder.graph, credentials)

    resource_types: List[Type[MicrosoftResource]] = [
        AzureComputeVirtualMachine,
        AzureComputeDisk,
    ]
    connect_resources(builder, resource_types)

    for node, data in list(collector.graph.nodes(data=True)):
        if isinstance(node, AzureComputeVirtualMachineSize):
            node.after_collect(builder, data.get("source", {}))

    assert list(collector.graph.search("kind", "azure_compute_virtual_machine_size"))[12].ondemand_cost == 13.14  # type: ignore[attr-defined]
    assert list(collector.graph.search("kind", "azure_compute_disk_type"))[2].ondemand_cost == 0.3640833333333333  # type: ignore[attr-defined]
