from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from typing import Any, List, Type, Set, Optional
from typing import Iterator

from attr import fields
from azure.identity import DefaultAzureCredential
from pytest import fixture

from resoto_plugin_azure.config import AzureConfig
from resoto_plugin_azure.azure_client import AzureClient, AzureApiSpec
from resoto_plugin_azure.resource.base import GraphBuilder, AzureSubscription, AzureResourceType, AzureLocation
from resotolib.baseresources import Cloud
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph
from resotolib.threading import ExecutorQueue
from resotolib.types import Json


class StaticFileAzureClient(AzureClient):
    def list(self, spec: AzureApiSpec, **kwargs: Any) -> List[Json]:
        last = spec.path.rsplit("/", maxsplit=1)[-1]
        path = os.path.dirname(__file__) + f"/files/{spec.service}/{last}.json"
        with open(path) as f:
            js = json.load(f)
            return js[spec.access_path] if spec.access_path else js  # type: ignore

    @staticmethod
    def create(*args: Any, **kwargs: Any) -> StaticFileAzureClient:
        return StaticFileAzureClient()

    def for_location(self, location: str) -> AzureClient:
        return self

    def delete(self, resource_id: str) -> bool:
        return False

    def delete_resource_tag(self, tag_name: str, resource_id: str) -> bool:
        return False

    def update_resource_tag(self, tag_name: str, tag_value: str, resource_id: str) -> bool:
        return False


@fixture
def config() -> AzureConfig:
    return AzureConfig()


@fixture
def executor_queue() -> Iterator[ExecutorQueue]:
    with ThreadPoolExecutor(1) as executor:
        queue = ExecutorQueue(executor, "dummy")
        yield queue


@fixture
def azure_subscription() -> AzureSubscription:
    return AzureSubscription(id="test", subscription_id="test")


@fixture
def credentials() -> DefaultAzureCredential:
    return DefaultAzureCredential()


@fixture
def azure_client() -> Iterator[AzureClient]:
    original = AzureClient.create
    AzureClient.create = StaticFileAzureClient.create
    yield StaticFileAzureClient()
    AzureClient.create = original


@fixture
def core_feedback() -> CoreFeedback:
    return CoreFeedback("test", "test", "test", Queue())


@fixture
def builder(
    executor_queue: ExecutorQueue,
    azure_subscription: AzureSubscription,
    azure_client: AzureClient,
    core_feedback: CoreFeedback,
) -> GraphBuilder:
    builder = GraphBuilder(
        graph=Graph(),
        cloud=Cloud(id="azure"),
        subscription=azure_subscription,
        client=azure_client,
        executor=executor_queue,
        core_feedback=core_feedback,
    )
    location_west = AzureLocation(id="westeurope", display_name="West Europe", name="westeurope")
    location_east = AzureLocation(id="eastus", display_name="East US", name="eastus")
    builder.location_lookup = {"westeurope": location_west, "eastus": location_east}
    builder.location = location_east
    return builder


def all_props_set(obj: AzureResourceType, ignore_props: Optional[Set[str]] = None) -> None:
    for field in fields(type(obj)):
        prop = field.name
        if not prop.startswith("_") and prop not in {
            "account",
            "arn",
            "atime",
            "mtime",
            "ctime",
            "changes",
            "chksum",
            "last_access",
            "last_update",
        } | (ignore_props or set()):
            if getattr(obj, prop) is None:
                raise Exception(f"Prop >{prop}< is not set: {obj}")


def roundtrip_check(
    resource_clazz: Type[AzureResourceType], builder: GraphBuilder, *, all_props: bool = False
) -> List[AzureResourceType]:
    resources = resource_clazz.collect_resources(builder)
    assert len(resources) > 0
    if all_props:
        all_props_set(resources[0])
    for resource in resources:
        # create json representation
        js_repr = resource.to_json()
        # make sure that the resource can be json serialized and read back
        again = resource_clazz.from_json(js_repr)
        # since we can not compare objects, we use the json representation to see that no information is lost
        again_js = again.to_json()
        assert js_repr == again_js, f"Left: {js_repr}\nRight: {again_js}"
    return resources


def connect_resources(
    builder: GraphBuilder,
    collect_resources: Optional[List[Type[AzureResourceType]]] = None,
    filter_class: Optional[Type[AzureResourceType]] = None,
) -> None:
    # collect all defined resource kinds before we can connect them
    for resource_kind in collect_resources or []:
        resource_kind.collect_resources(builder)
    # connect all resources
    for node, data in list(builder.graph.nodes(data=True)):
        if not filter_class or isinstance(node, filter_class):
            node.connect_in_graph(builder, data.get("source", {}))
