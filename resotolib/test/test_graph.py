from resotolib.graph import Graph, GraphContainer
from resotolib.baseresources import BaseResource
import resotolib.logging as logging
from dataclasses import dataclass
from typing import ClassVar

logging.getLogger("cloudkeeper").setLevel(logging.DEBUG)


@dataclass(eq=False)
class SomeTestResource(BaseResource):
    kind: ClassVar[str] = "some_test_resource"

    def delete(self, graph) -> bool:
        return False


def test_graph():
    g = Graph()
    n1 = SomeTestResource("foo", {})
    n2 = SomeTestResource("bar", {})
    g.add_node(n1)
    g.add_node(n2)
    g.add_edge(n1, n2)
    assert len(g.nodes) == 2
    assert len(g.edges) == 1


def test_graph_container():
    gc = GraphContainer(cache_graph=False)
    g = Graph()
    n1 = SomeTestResource("foo", {})
    n2 = SomeTestResource("bar", {})
    g.add_node(n1)
    gc.graph.add_resource(gc.GRAPH_ROOT, n2)
    gc.add(g)
    gc.graph.add_edge(n1, n2)
    assert len(gc.graph.nodes) == 3
    assert len(gc.graph.edges) == 2
    assert gc.graph.search_first("id", "bar") == n2
    assert gc.graph.search_first_parent_class(n2, SomeTestResource) == n1
