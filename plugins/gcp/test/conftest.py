from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from typing import Iterator

from google.auth.credentials import AnonymousCredentials
from googleapiclient import discovery
from pytest import fixture

from fix_plugin_gcp import gcp_client
from fix_plugin_gcp.config import GcpConfig
from fix_plugin_gcp.resources.base import GcpRegion, GraphBuilder, GcpProject
from fixlib.baseresources import Cloud
from fixlib.config import Config
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph
from fixlib.threading import ExecutorQueue
from .random_client import build_random_data_client, random_predefined


@fixture
def random_builder() -> Iterator[GraphBuilder]:
    with ThreadPoolExecutor(1) as executor:
        # Initialise config
        Config.add_config(GcpConfig)
        Config.init_default_config()
        # change discovery function factory for tests
        gcp_client._discovery_function = build_random_data_client
        queue = ExecutorQueue(executor, "dummy")
        feedback = CoreFeedback("test", "test", "test", Queue())
        project = GcpProject(id="test")
        project_global_region = GcpRegion.fallback_global_region(project)
        builder = GraphBuilder(
            Graph(), Cloud(id="gcp"), project, AnonymousCredentials(), queue, feedback, project_global_region
        )
        builder.add_node(project_global_region, {})
        # add predefined regions and zones
        for predefined in random_predefined:
            builder.add_node(predefined)
        builder.prepare_region_zone_lookup()
        # provide the builder to the test method
        yield builder
        # rest the original discovery function
        gcp_client._discovery_function = discovery.build
