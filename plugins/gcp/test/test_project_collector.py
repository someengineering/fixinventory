from resoto_plugin_gcp import GcpConfig
from resoto_plugin_gcp.project_collector import GcpProjectCollector, all_resources
from resoto_plugin_gcp.resources.base import GraphBuilder
from resotolib.config import current_config


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
