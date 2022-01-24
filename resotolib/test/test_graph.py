from resotolib.graph import Graph, GraphContainer, EdgeType
from resotolib.baseresources import BaseResource
import resotolib.logging as logging
from dataclasses import dataclass
from typing import ClassVar

logging.getLogger("resoto").setLevel(logging.DEBUG)


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


def test_graph_merge():
    rg1 = Graph()
    rg2 = Graph()
    a = SomeTestResource("a", {})
    b = SomeTestResource("b", {})
    c = SomeTestResource("c", {})
    d = SomeTestResource("d", {})
    rg1.add_node(a)
    rg1.add_node(b)
    rg2.add_node(c)
    rg2.add_node(d)
    rg1.add_edge(a, b, edge_type=EdgeType.delete)
    rg2.add_edge(c, d, edge_type=EdgeType.delete)
    rg1.merge(rg2)
    assert len(rg1.nodes) == 4
    assert len(rg1.edges) == 2
    for edge in rg1.edges:
        assert len(edge) == 3
        key = edge[2]
        assert len(key) == 3
        edge_type = key[2]
        assert edge_type == EdgeType.delete
