import json
import os
from queue import Queue
from resoto_plugin_gcp import GcpConfig
from resoto_plugin_gcp.project_collector import GcpProjectCollector, all_resources
from resoto_plugin_gcp.resources.base import GcpProject, GraphBuilder
from resoto_plugin_gcp.resources.billing import GcpSku
from resoto_plugin_gcp.resources.compute import GcpMachineType
from resotolib.baseresources import Cloud
from resotolib.config import current_config
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph


def collector_with_graph(graph: Graph) -> GcpProjectCollector:
    collector = GcpProjectCollector(
        config=None,
        cloud=Cloud(id="gcp"),
        project=GcpProject(id="test"),
        core_feedback=CoreFeedback("test", "test", "test", Queue()),
    )
    collector.graph = graph
    return collector


def test_project_collection(random_builder: GraphBuilder) -> None:
    # create the collector from the builder values
    config: GcpConfig = current_config().gcp
    project = GcpProjectCollector(config, random_builder.cloud, random_builder.project, random_builder.core_feedback)
    # use the graph provided by the random builder - it already has regions and zones
    # the random builder will not create new regions or zones during the test
    project.graph = random_builder.graph
    project.collect()
    # the number of resources in the graph is not fixed, but it should be at least the number of resource kinds
    assert len(project.graph.nodes) >= len(all_resources)


def test_remove_unconnected_nodes(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/machine_type.json") as f:
        GcpMachineType.collect(raw=json.load(f)["items"]["machineTypes"], builder=random_builder)
    with open(os.path.dirname(__file__) + "/files/skus.json") as f:
        GcpSku.collect(raw=json.load(f)["skus"], builder=random_builder)

    collector = collector_with_graph(random_builder.graph)

    num_all_machine_types = len(list(collector.graph.search("kind", "gcp_machine_type")))
    num_all_skus = len(list(collector.graph.search("kind", "gcp_sku")))

    collector.remove_unconnected_nodes()

    assert len(list(collector.graph.search("kind", "gcp_machine_type"))) < num_all_machine_types
    assert len(list(collector.graph.search("kind", "gcp_sku"))) < num_all_skus
