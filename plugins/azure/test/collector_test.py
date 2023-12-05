from resoto_plugin_azure.azure_client import AzureClient
from resoto_plugin_azure.collector import AzureSubscriptionCollector
from resoto_plugin_azure.config import AzureCredentials, AzureConfig
from resoto_plugin_azure.resource.base import AzureSubscription
from resotolib.baseresources import Cloud
from resotolib.core.actions import CoreFeedback


def test_collect(
    config: AzureConfig,
    azure_subscription: AzureSubscription,
    credentials: AzureCredentials,
    core_feedback: CoreFeedback,
    azure_client: AzureClient,
) -> None:
    collector = AzureSubscriptionCollector(config, Cloud(id="azure"), azure_subscription, credentials, core_feedback)
    collector.collect()
    assert len(collector.graph.nodes) == 471
    assert len(collector.graph.edges) == 498
