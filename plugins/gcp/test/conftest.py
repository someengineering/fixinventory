from concurrent.futures import Executor, Future
from queue import Queue
from typing import Any, Callable, Iterator

from google.auth.credentials import AnonymousCredentials
from googleapiclient import discovery
from pytest import fixture

from resoto_plugin_gcp import gcp_client
from resoto_plugin_gcp.config import GcpConfig
from resoto_plugin_gcp.resources.base import ExecutorQueue, GraphBuilder, GcpProject
from resotolib.baseresources import Cloud
from resotolib.config import Config
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph
from .random_client import build_random_data_client, random_predefined


class DummyExecutor(Executor):
    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Future[Any]:  # type: ignore
        result = fn(*args, **kwargs)
        f: Future[Any] = Future()
        f.set_result(result)
        return f


@fixture
def random_builder() -> Iterator[GraphBuilder]:
    # Initialise config
    Config.add_config(GcpConfig)
    Config.init_default_config()
    # change discovery function factory for tests
    gcp_client._discovery_function = build_random_data_client
    queue = ExecutorQueue(DummyExecutor(), "dummy")
    feedback = CoreFeedback("test", "test", "test", Queue())
    builder = GraphBuilder(Graph(), Cloud(id="gcp"), GcpProject(id="test"), AnonymousCredentials(), queue, feedback)
    # add predefined regions and zones
    for predefined in random_predefined:
        builder.add_node(predefined)
    builder.prepare_region_zone_lookup()
    # provide the builder to the test method
    yield builder
    # rest the original discovery function
    gcp_client._discovery_function = discovery.build
