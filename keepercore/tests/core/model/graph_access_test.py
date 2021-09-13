import collections
from datetime import date

import jsons
import pytest
from deepdiff import DeepDiff
from networkx import MultiDiGraph
from pytest import fixture

from core.model.graph_access import GraphAccess, GraphBuilder, EdgeType, NodeData
from core.model.model import Model
from core.model.typed_model import to_js
from tests.core.db.graphdb_test import Foo

# noinspection PyUnresolvedReferences
from tests.core.model.model_test import person_model


FooTuple = collections.namedtuple(
    "FooTuple",
    ["a", "b", "c", "d", "e", "f", "g", "kind"],
    defaults=["", 0, [], "foo", {"a": 12, "b": 32}, date.fromisoformat("2021-03-29"), 1.234567, "foo"],
)


# noinspection PyArgumentList
@fixture
def graph_access() -> GraphAccess:
    g = MultiDiGraph()
    g.add_node("1", reported=to_js(FooTuple("1")), desired={"name": "a"}, metadata={"version": 1}, kinds=["foo"])
    g.add_node("2", reported=to_js(FooTuple("2")), desired={"name": "b"}, metadata={"version": 2}, kinds=["foo"])
    g.add_node("3", reported=to_js(FooTuple("3")), desired={"name": "c"}, metadata={"version": 3}, kinds=["foo"])
    g.add_node("4", reported=to_js(FooTuple("4")), desired={"name": "d"}, metadata={"version": 4}, kinds=["foo"])
    g.add_edge("1", "2", "1_2_dependency", edge_type=EdgeType.dependency)
    g.add_edge("1", "3", "1_3_dependency", edge_type=EdgeType.dependency)
    g.add_edge("2", "3", "2_3_dependency", edge_type=EdgeType.dependency)
    g.add_edge("2", "4", "2_4_dependency", edge_type=EdgeType.dependency)
    g.add_edge("3", "4", "3_4_dependency", edge_type=EdgeType.dependency)
    g.add_edge("1", "2", "1_2_delete", edge_type=EdgeType.delete)
    g.add_edge("1", "3", "1_3_delete", edge_type=EdgeType.delete)
    g.add_edge("1", "4", "1_4_delete", edge_type=EdgeType.delete)
    return GraphAccess(g)


# noinspection PyArgumentList
def test_access_node() -> None:
    g = MultiDiGraph()
    g.add_node("1", reported=to_js(FooTuple(a="1")))
    access: GraphAccess = GraphAccess(g)
    _, json, _, _, _, sha, _, _ = node(access, "1")
    assert sha == "4f226c613e168b79a94aa93493c3770ffc189f06a2569ce65f4a586f50682558"
    assert json == {
        "a": "1",
        "b": 0,
        "c": [],
        "d": "foo",
        "e": {"a": 12, "b": 32},
        "f": "2021-03-29",
        "g": 1.234567,
        "kind": "foo",
    }
    assert access.node("2") is None


def test_marshal_unmarshal() -> None:
    foo = Foo("12")
    name = type(foo).__name__
    clazz = globals()[name]
    js = jsons.dumps(foo)
    again = jsons.loads(js, cls=clazz)
    assert DeepDiff(foo, again, truncate_datetime="second") == {}
    assert 4 == 4


def test_content_hash() -> None:
    # the order of properties should not matter for the content hash
    g = MultiDiGraph()
    g.add_node("1", reported={"a": {"a": 1, "c": 2, "b": 3}, "c": 2, "b": 3, "d": "foo", "z": True, "kind": "a"})
    g.add_node("2", reported={"z": True, "c": 2, "b": 3, "a": {"b": 3, "c": 2, "a": 1}, "d": "foo", "kind": "a"})

    access = GraphAccess(g)
    sha1 = node(access, "1")[2]
    sha2 = node(access, "2")[2]
    assert sha1 == sha2


def test_root(graph_access: GraphAccess) -> None:
    assert graph_access.root() == "1"


def test_not_visited(graph_access: GraphAccess) -> None:
    graph_access.node("1")
    graph_access.node("3")
    not_visited = list(graph_access.not_visited_nodes())
    assert len(not_visited) == 2
    assert not_visited[0][5] == "a9efa612d3c5a231c643d0b9f9aab3297b84c7433a009e772f4692cc016927aa"
    assert not_visited[1][5] == "28cd705c4a5378520969ab3e0ad229edda361536b581aa4a94d5f9dcdf2dcb87"


def test_edges(graph_access: GraphAccess) -> None:
    assert graph_access.has_edge("1", "2", EdgeType.dependency)
    assert not graph_access.has_edge("1", "9", EdgeType.dependency)
    assert graph_access.has_edge("2", "3", EdgeType.dependency)
    assert list(graph_access.not_visited_edges(EdgeType.dependency)) == [("1", "3"), ("2", "4"), ("3", "4")]
    assert list(graph_access.not_visited_edges(EdgeType.delete)) == [("1", "2"), ("1", "3"), ("1", "4")]


def test_desired(graph_access: GraphAccess) -> None:
    desired = {a[0]: a[2] for a in graph_access.not_visited_nodes()}
    assert desired == {"1": {"name": "a"}, "2": {"name": "b"}, "3": {"name": "c"}, "4": {"name": "d"}}


def test_metadata(graph_access: GraphAccess) -> None:
    desired = {a[0]: a[3] for a in graph_access.not_visited_nodes()}
    assert desired == {"1": {"version": 1}, "2": {"version": 2}, "3": {"version": 3}, "4": {"version": 4}}


def test_flatten() -> None:
    js = {"id": "blub", "d": "2021-06-18T10:31:34Z", "i": 0, "s": "hello", "a": [{"a": "one"}, {"b": "two"}]}
    flat = GraphBuilder.flatten(js)
    assert flat == "blub 2021-06-18T10:31:34Z 0 hello one two"


def node(access: GraphAccess, node_id: str) -> NodeData:
    res = access.node(node_id)
    if res:
        return res
    else:
        raise AttributeError(f"Expected {node_id} to be defined!")


def test_builder(person_model: Model) -> None:
    max_m = {"id": "max", "kind": "Person", "name": "Max"}
    builder = GraphBuilder(person_model)
    builder.add_from_json({"id": "1", "reported": max_m})
    builder.add_from_json({"from": "1", "to": "2"})
    with pytest.raises(AssertionError) as no_node:
        builder.check_complete()
    assert str(no_node.value) == "Vertex 2 was used in an edge definition but not provided as vertex!"
    builder.add_from_json({"id": "2", "reported": max_m})
    builder.add_from_json({"id": "3", "reported": max_m})
    with pytest.raises(AssertionError) as no_node:
        builder.check_complete()
    assert str(no_node.value) == "Given subgraph has more than one root: ['1', '3']"
    builder.add_from_json({"from": "1", "to": "3"})
    builder.check_complete()


def multi_cloud_graph(merge_on: str) -> MultiDiGraph:
    g = MultiDiGraph()
    root = "root"

    def add_node(node_id: str) -> None:
        reported = {"some": {"deep": {"nested": node_id}}}
        g.add_node(node_id, merge=node_id.startswith(merge_on), reported=reported, kind=node_id, kinds=[node_id])

    def add_edge(from_node: str, to_node: str, edge_type: str = EdgeType.default) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        g.add_edge(from_node, to_node, key, edge_type=edge_type)

    add_node(root)
    for collector_d in ["aws", "gcp"]:
        collector = f"collector_{collector_d}"
        add_node(collector)
        add_edge(root, collector)
        for account_d in range(0, 3):
            account = f"account_{collector}_{account_d}"
            add_node(account)
            add_edge(collector, account)
            add_edge(account, collector, EdgeType.delete)
            for region_d in ["europe", "america", "asia", "africa", "antarctica", "australia"]:
                region = f"region_{account}_{region_d}"
                add_node(region)
                add_edge(account, region)
                add_edge(region, account, EdgeType.delete)
                for parent_d in range(0, 3):
                    parent = f"parent_{region}_{parent_d}"
                    add_node(parent)
                    add_edge(region, parent)
                    add_edge(parent, region, EdgeType.delete)
                    for children_d in range(0, 3):
                        children = f"child_{parent}_{children_d}"
                        add_node(children)
                        add_edge(parent, children)
                        add_edge(children, parent, EdgeType.delete)

    return g


def test_sub_graphs_from_graph_collector() -> None:
    graph = multi_cloud_graph("collector")
    merges, parent, graph_it = GraphAccess.merge_graphs(graph)
    graphs = list(graph_it)
    assert len(graphs) == 6
    for root, succ in graphs:
        assert len(parent.nodes) == 3
        assert succ.root().startswith("account")
        assert len(list(succ.not_visited_nodes())) == 79
        assert len(succ.nodes) == 82
        # make sure there is no node from another subgraph
        for node_id in succ.not_visited_nodes():
            assert succ.root() in node_id[0]
        assert len(list(succ.not_visited_edges(EdgeType.default))) == 79
        assert len(list(succ.not_visited_edges(EdgeType.delete))) == 79


def test_sub_graphs_from_graph_account() -> None:
    graph = multi_cloud_graph("account")
    merges, parent, graph_it = GraphAccess.merge_graphs(graph)
    graphs = list(graph_it)
    assert len(graphs) == 36
    for root, succ in graphs:
        assert len(parent.nodes) == 9  # root + collector + account
        assert succ.root().startswith("region")
        assert len(list(succ.not_visited_nodes())) == 13
        assert len(succ.nodes) == 22
        # make sure there is no node from another subgraph
        for node_id in succ.not_visited_nodes():
            assert succ.root() in node_id[0]
        assert len(list(succ.not_visited_edges(EdgeType.default))) == 13
        assert len(list(succ.not_visited_edges(EdgeType.delete))) == 13


def test_sub_graphs_with_cycle() -> None:
    graph = multi_cloud_graph("account")
    # add an edge from one merge graph to another merge graph
    graph.add_edge("parent_region_account_collector_aws_0_asia_1", "parent_region_account_collector_aws_0_africa_1")
    # the cycle should fail creating sub-graphs
    with pytest.raises(AttributeError):
        _, _, graph_it = GraphAccess.merge_graphs(graph)
        list(graph_it)


def test_predecessors() -> None:
    graph = GraphAccess(multi_cloud_graph("account"))
    child = "child_parent_region_account_collector_gcp_2_europe_1_0"
    parent = "parent_region_account_collector_gcp_2_europe_1"
    region = "region_account_collector_gcp_2_europe"

    # dependency: region -> parent -> child
    assert list(graph.predecessors(child, EdgeType.dependency)) == [parent]
    assert list(graph.predecessors(parent, EdgeType.dependency)) == [region]
    assert child in list(graph.successors(parent, EdgeType.dependency))
    assert parent in list(graph.successors(region, EdgeType.dependency))

    # delete: child -> parent -> region
    assert list(graph.successors(child, EdgeType.delete)) == [parent]
    assert list(graph.successors(parent, EdgeType.delete)) == [region]
    assert parent in list(graph.successors(child, EdgeType.delete))
    assert region in list(graph.successors(parent, EdgeType.delete))


def test_ancestor_with() -> None:
    graph = GraphAccess(multi_cloud_graph("account"))
    nid = "child_parent_region_account_collector_gcp_2_europe_1_0"
    assert graph.ancestor_of(nid, EdgeType.dependency, "root") is not None
    assert graph.ancestor_of(nid, EdgeType.delete, "root") is None
    assert graph.ancestor_of(nid, EdgeType.dependency, "foo") is None
    assert graph.ancestor_of(nid, EdgeType.dependency, "foo") is None
