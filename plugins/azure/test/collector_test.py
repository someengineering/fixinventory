import json

from azure.identity import DefaultAzureCredential

from resoto_plugin_azure.resource.base import AzureSubscription
from resoto_plugin_azure.collector import AzureSubscriptionCollector
from resoto_plugin_azure.azure_client import AzureClient
from resoto_plugin_azure.config import AzureCredentials, AzureConfig
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
    assert len(collector.graph.nodes) == 40
    assert len(collector.graph.edges) == 39


def test_foo() -> None:
    client = AzureClient.create(DefaultAzureCredential(), "38b02a39-99c8-45bd-a92e-38b616f109df")
    res = client.list(AzureSubscription.api_spec)
    print(json.dumps(res, indent=2))
