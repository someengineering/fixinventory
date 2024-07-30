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

from fix_plugin_azure.config import AzureConfig
from fix_plugin_azure.azure_client import MicrosoftClient, AzureResourceSpec, MicrosoftRestSpec, RestApiSpec
from fix_plugin_azure.resource.base import GraphBuilder, AzureSubscription, MicrosoftResourceType, AzureLocation
from fixlib.baseresources import Cloud
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph
from fixlib.threading import ExecutorQueue
from fixlib.types import Json


class StaticFileMicrosoftClient(MicrosoftClient):
    def list(self, spec: MicrosoftRestSpec, **kwargs: Any) -> List[Json]:
        assert isinstance(spec, (AzureResourceSpec, RestApiSpec))
        if isinstance(spec, AzureResourceSpec):
            query_start_index = spec.path.find("?")
            spec_path = spec.path[:query_start_index] if query_start_index != -1 else spec.path
            splitted_path = spec_path.rsplit("/")

            last = splitted_path[-1] if splitted_path[-1] != "" else splitted_path[-2]

            path = os.path.dirname(__file__) + f"/files/{spec.service}/{last}.json"
            with open(path) as f:
                js = json.load(f)

                if spec.expect_array:
                    js = js[spec.access_path] if spec.access_path else [js]
                if spec.expect_array and isinstance(js, list):
                    return js
                else:
                    return [js]
        else:
            last = spec.url.rsplit("/", maxsplit=1)[1]

            path = os.path.dirname(__file__) + f"/files/{spec.service}/{last}.json"
            with open(path) as f:
                js = json.load(f)

                if spec.expect_array:
                    js = js[spec.access_path]
                if spec.expect_array and isinstance(js, list):
                    return js
                else:
                    return [js]

    @staticmethod
    def create(*args: Any, **kwargs: Any) -> StaticFileMicrosoftClient:
        return StaticFileMicrosoftClient()

    def for_location(self, location: str) -> MicrosoftClient:
        return self

    def delete(self, resource_id: str) -> bool:
        return False

    def delete_resource_tag(self, tag_name: str, resource_id: str) -> bool:
        return False

    def update_resource_tag(self, tag_name: str, tag_value: str, resource_id: str) -> bool:
        return False

    @property
    def config(self) -> AzureConfig:
        return AzureConfig()


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
def azure_client() -> Iterator[MicrosoftClient]:
    original = MicrosoftClient.create
    MicrosoftClient.create = StaticFileMicrosoftClient.create
    yield StaticFileMicrosoftClient()
    MicrosoftClient.create = original


@fixture
def core_feedback() -> CoreFeedback:
    return CoreFeedback("test", "test", "test", Queue())


@fixture
def builder(
    executor_queue: ExecutorQueue,
    azure_subscription: AzureSubscription,
    azure_client: MicrosoftClient,
    core_feedback: CoreFeedback,
    config: AzureConfig,
) -> GraphBuilder:
    builder = GraphBuilder(
        graph=Graph(),
        cloud=Cloud(id="azure"),
        account=azure_subscription,
        client=azure_client,
        executor=executor_queue,
        core_feedback=core_feedback,
        config=config,
    )
    location_west = AzureLocation(id="westeurope", display_name="West Europe", name="westeurope")
    location_east = AzureLocation(id="eastus", display_name="East US", name="eastus")
    builder.location_lookup = {"westeurope": location_west, "eastus": location_east}
    builder.location = location_east
    return builder


def all_props_set(obj: MicrosoftResourceType, ignore_props: Optional[Set[str]] = None) -> None:
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
    resource_clazz: Type[MicrosoftResourceType],
    builder: GraphBuilder,
    *,
    all_props: bool = False,
    check_correct_ser: bool = True,
    ignore_props: Optional[Set[str]] = None,
) -> List[MicrosoftResourceType]:
    resources = resource_clazz.collect_resources(builder)
    assert len(resources) > 0
    if all_props:
        all_props_set(resources[0], ignore_props)
    # Check correct json serialization
    if check_correct_ser:
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
    collect_resources: Optional[List[Type[MicrosoftResourceType]]] = None,
    filter_class: Optional[Type[MicrosoftResourceType]] = None,
) -> None:
    # collect all defined resource kinds before we can connect them
    for resource_kind in collect_resources or []:
        resource_kind.collect_resources(builder)
    builder.executor.wait_for_submitted_work()
    # connect all resources
    for node, data in list(builder.graph.nodes(data=True)):
        if not filter_class or isinstance(node, filter_class):
            node.connect_in_graph(builder, data.get("source", {}))
    builder.executor.wait_for_submitted_work()
