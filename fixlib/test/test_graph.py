from platform import python_implementation

import pytest
from fixlib.graph import Graph, GraphExportIterator, EdgeKey
from fixlib.baseresources import BaseResource, EdgeType, GraphRoot
import fixlib.logger as logger
from attrs import define
from typing import ClassVar

logger.getLogger("fix").setLevel(logger.DEBUG)


@define(eq=False, slots=False)
class SomeTestResource(BaseResource):
    kind: ClassVar[str] = "some_test_resource"

    def delete(self, graph) -> bool:
        return False


def test_graph():
    g = Graph()
    n1 = SomeTestResource(id="foo", tags={})
    n2 = SomeTestResource(id="bar", tags={})
    g.add_node(n1)
    g.add_node(n2)
    g.add_edge(n1, n2)
    assert len(g.nodes) == 2
    assert len(g.edges) == 1


def test_graph_merge():
    rg1 = Graph()
    rg2 = Graph()
    a = SomeTestResource(id="a", tags={})
    b = SomeTestResource(id="b", tags={})
    c = SomeTestResource(id="c", tags={})
    d = SomeTestResource(id="d", tags={})
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


def test_multidigraph():
    g = Graph()
    a = SomeTestResource(id="a", tags={})
    b = SomeTestResource(id="b", tags={})
    c = SomeTestResource(id="c", tags={})
    d = SomeTestResource(id="d", tags={})
    g.add_resource(a, b)
    g.add_resource(b, c)
    g.add_resource(c, d)
    g.add_edge(b, a, edge_type=EdgeType.delete)
    g.add_edge(b, d, edge_type=EdgeType.delete)
    assert len(g.nodes) == 4
    assert len(g.edges) == 5
    assert len(list(g.successors(a))) == 1
    g.add_edge(a, b)
    assert len(list(g.successors(a))) == 1
    assert len(list(g.predecessors(b))) == 1
    assert len(list(g.predecessors(a))) == 0
    assert len(list(g.successors(b))) == 1
    assert len(list(g.successors(c))) == 1
    assert len(list(g.successors(d))) == 0
    assert len(list(g.predecessors(a, edge_type=EdgeType.delete))) == 1
    assert len(list(g.successors(b, edge_type=EdgeType.delete))) == 2
    assert len(list(g.successors(a, edge_type=EdgeType.delete))) == 0
    assert len(list(g.predecessors(b, edge_type=EdgeType.delete))) == 0
    assert len(list(g.ancestors(a))) == 0
    assert len(list(g.descendants(a))) == 3
    assert len(list(g.descendants(a, edge_type=EdgeType.delete))) == 0
    assert len(list(g.descendants(b))) == 2
    assert len(list(g.descendants(b, edge_type=EdgeType.delete))) == 2
    assert g.is_acyclic_per_edge_type()
    g.add_edge(b, a)
    assert g.is_acyclic_per_edge_type() is False


# noinspection PyStatementEffect
def test_baseresource_chksum():
    g = Graph()
    a = SomeTestResource(id="a", tags={})
    with pytest.raises(RuntimeError):
        a.chksum
    g.add_node(a)
    assert isinstance(a.chksum, str)


@pytest.mark.skipif(condition=python_implementation() != "CPython", reason="not implemented")
def test_graph_export_iterator():
    from sys import getrefcount

    g = Graph(root=GraphRoot(id="root", tags={}))
    a = SomeTestResource(id="a", tags={})
    g.add_resource(g.root, a)
    assert getrefcount(g) == 2
    gei = GraphExportIterator(g)
    gei.export_graph()
    # one ref for g and for the variable passed to getrefcount ==> 2
    assert getrefcount(g) == 2
    assert len(list(gei)) == 3


def test_find_cycles():
    g = Graph()
    n1 = SomeTestResource(id="foo", tags={})
    n2 = SomeTestResource(id="bar", tags={})
    g.add_node(n1)
    g.add_node(n2)
    g.add_edge(n1, n2)
    assert g.is_acyclic_per_edge_type() is True
    g.add_edge(n2, n1)
    assert g.is_acyclic_per_edge_type() is False
    cycle = g.find_cycle()
    assert cycle == [
        EdgeKey(edge_type=EdgeType.default, src=n1, dst=n2),
        EdgeKey(edge_type=EdgeType.default, src=n2, dst=n1),
    ]
