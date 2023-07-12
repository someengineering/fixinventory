from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from typing import Iterator

from azure.identity import DefaultAzureCredential
from pytest import fixture

from resoto_plugin_azure.azure_client import AzureClient
from resoto_plugin_azure.resource.base import GraphBuilder, AzureSubscription
from resotolib.baseresources import Cloud
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph
from resotolib.threading import ExecutorQueue


@fixture
def executor_queue() -> Iterator[ExecutorQueue]:
    with ThreadPoolExecutor(1) as executor:
        queue = ExecutorQueue(executor, "dummy")
        yield queue


@fixture
def azure_subscription() -> AzureSubscription:
    return AzureSubscription(id="test")


@fixture
def credentials() -> DefaultAzureCredential:
    return DefaultAzureCredential()


@fixture
def azure_client(credentials: DefaultAzureCredential, azure_subscription: AzureSubscription) -> AzureClient:
    return AzureClient(credentials, azure_subscription.safe_name)


@fixture
def core_feedback() -> CoreFeedback:
    return CoreFeedback("test", "test", "test", Queue())


@fixture
def graph_builder(
    executor_queue: ExecutorQueue,
    azure_subscription: AzureSubscription,
    azure_client: AzureClient,
    core_feedback: CoreFeedback,
) -> GraphBuilder:
    return GraphBuilder(
        graph=Graph(),
        cloud=Cloud(id="azure"),
        subscription=azure_subscription,
        client=azure_client,
        executor=executor_queue,
        core_feedback=core_feedback,
    )
