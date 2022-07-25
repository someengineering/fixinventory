from typing import Type

import pytest
from networkx import DiGraph, is_directed_acyclic_graph

from resoto_plugin_aws.collector import AwsAccountCollector, all_resources
from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.resource.base import AwsAccount, AwsResource
from resotolib.baseresources import Cloud
from resotolib.core.model_export import dataclasses_to_resotocore_model
from test.resources import BotoFileBasedSession


def test_collect() -> None:
    config = AwsConfig("test", "test", "test")
    config.sessions().session_class_factory = BotoFileBasedSession
    account = AwsAccount(id="123")
    ac = AwsAccountCollector(config, Cloud(id="aws"), account, ["us-east-1"])
    ac.collect()

    def count_kind(clazz: Type[AwsResource]) -> int:
        count = 0
        for node in ac.graph.nodes:
            if isinstance(node, clazz):
                count += 1
        return count

    assert len(ac.graph.edges) == 280
    assert count_kind(AwsResource) == 110
    for resource in all_resources:
        assert count_kind(resource) > 0, "No instances of {} found".format(resource.__name__)


@pytest.mark.skipif(True, reason="Enable this once the old collector is gone")
def test_dependencies() -> None:
    model = dataclasses_to_resotocore_model({AwsResource})

    def for_edge_type(edge_type: str) -> DiGraph:
        graph = DiGraph()
        for kind in model:
            if (successors := kind.get("successor_kinds")) and edge_type in successors:
                for successor in successors[edge_type]:
                    graph.add_edge(kind["fqn"], successor)
        return graph

    def show_graph(graph: DiGraph) -> str:
        result = "digraph {\n"
        for start, end in graph.edges:
            result += "  " + start + "->" + end + "\n"
        result += "}"
        return result

    assert is_directed_acyclic_graph(for_edge_type("default")), show_graph(for_edge_type("default"))
    assert is_directed_acyclic_graph(for_edge_type("delete")), show_graph(for_edge_type("delete"))
