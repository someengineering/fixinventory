import os
import json
from queue import Queue

from fix_plugin_azure.azure_client import AzureClient
from fix_plugin_azure.collector import AzureSubscriptionCollector
from fix_plugin_azure.config import AzureCredentials, AzureConfig
from fix_plugin_azure.resource.base import AzureSubscription, GraphBuilder
from fix_plugin_azure.resource.compute import AzureVirtualMachine, AzureVirtualMachineSize
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
    assert len(collector.graph.nodes) == 398
    assert len(collector.graph.edges) == 473


def test_filter(credentials: AzureCredentials, builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/compute/vmSizes.json") as f:
        AzureVirtualMachineSize.collect(raw=json.load(f)["value"], builder=builder)
    with open(os.path.dirname(__file__) + "/files/compute/virtualMachines.json") as f:
        AzureVirtualMachine.collect(raw=json.load(f)["value"], builder=builder)

    collector = collector_with_graph(builder.graph, credentials)

    num_all_virtual_machine_types = list(collector.graph.search("kind", "azure_virtual_machine_size"))

    collector.filter_nodes()

    assert len(list(collector.graph.search("kind", "azure_virtual_machine_size"))) < len(num_all_virtual_machine_types)
