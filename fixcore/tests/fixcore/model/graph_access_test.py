import collections
import re
from datetime import date
from typing import Optional, cast, Dict

import jsons
import pytest
from deepdiff import DeepDiff
from networkx import MultiDiGraph
from pytest import fixture

from fixcore.ids import NodeId
from fixcore.model.graph_access import GraphAccess, GraphBuilder, EdgeTypes, EdgeKey
from fixcore.model.model import Model, AnyKind, ComplexKind
from fixcore.model.typed_model import to_json
from fixcore.types import Json, EdgeType
from fixcore.util import AccessJson, AccessNone, uuid_str
from tests.fixcore.db.graphdb_test import Foo

FooTuple = collections.namedtuple(
    "FooTuple",
    ["a", "b", "c", "d", "e", "f", "g", "kind"],
    defaults=["", 0, [], "foo", {"a": 12, "b": 32}, date.fromisoformat("2021-03-29"), 1.234567, "foo"],
)


# noinspection PyArgumentList
@fixture
def graph_access() -> GraphAccess:
    g = MultiDiGraph()

    def add_edge(from_node: str, to_node: str, edge_type: EdgeType) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        g.add_edge(from_node, to_node, key, edge_type=edge_type)

    g.add_node("1", reported=to_json(FooTuple("1")), desired={"name": "a"}, metadata={"version": 1}, kinds=["foo"])
    g.add_node("2", reported=to_json(FooTuple("2")), desired={"name": "b"}, metadata={"version": 2}, kinds=["foo"])
    g.add_node("3", reported=to_json(FooTuple("3")), desired={"name": "c"}, metadata={"version": 3}, kinds=["foo"])
    g.add_node("4", reported=to_json(FooTuple("4")), desired={"name": "d"}, metadata={"version": 4}, kinds=["foo"])
    add_edge("1", "2", edge_type=EdgeTypes.default)
    add_edge("1", "3", edge_type=EdgeTypes.default)
    add_edge("2", "3", edge_type=EdgeTypes.default)
    add_edge("2", "4", edge_type=EdgeTypes.default)
    add_edge("3", "4", edge_type=EdgeTypes.default)
    add_edge("1", "2", edge_type=EdgeTypes.delete)
    add_edge("1", "3", edge_type=EdgeTypes.delete)
    add_edge("1", "4", edge_type=EdgeTypes.delete)
    return GraphAccess(g)


# noinspection PyArgumentList
def test_access_node() -> None:
    g = MultiDiGraph()
    g.add_node("1", reported=to_json(FooTuple(a="1")))
    access: GraphAccess = GraphAccess(g)
    elem: Json = node(access, "1")  # type: ignore
    assert elem["hash"] == "153c1a5c"
    assert elem["reported"] == {
        "a": "1",
        "b": 0,
        "c": [],
        "d": "foo",
        "e": {"a": 12, "b": 32},
        "f": "2021-03-29",
        "g": 1.234567,
        "kind": "foo",
    }
    assert access.node(NodeId("2")) is None


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
    sha1 = node(access, "1")["hash"]  # type: ignore
    sha2 = node(access, "2")["hash"]  # type: ignore
    assert sha1 == sha2


def test_root(graph_access: GraphAccess) -> None:
    assert graph_access.root() == "1"


def test_not_visited(graph_access: GraphAccess) -> None:
    graph_access.node(NodeId("1"))
    graph_access.node(NodeId("3"))
    not_visited = list(graph_access.not_visited_nodes())
    assert len(not_visited) == 2
    assert not_visited[0]["hash"] == "05469946"
    assert not_visited[1]["hash"] == "0fead7dd"


def test_edges(graph_access: GraphAccess) -> None:
    assert graph_access.has_edge("1", "2", EdgeTypes.default)
    assert not graph_access.has_edge("1", "9", EdgeTypes.default)
    assert graph_access.has_edge("2", "3", EdgeTypes.default)
    assert list(graph_access.not_visited_edges(EdgeTypes.default)) == [("1", "3"), ("2", "4"), ("3", "4")]
    assert list(graph_access.not_visited_edges(EdgeTypes.delete)) == [("1", "2"), ("1", "3"), ("1", "4")]


def test_desired(graph_access: GraphAccess) -> None:
    desired = {a["id"]: a["desired"] for a in graph_access.not_visited_nodes()}
    assert desired == {"1": {"name": "a"}, "2": {"name": "b"}, "3": {"name": "c"}, "4": {"name": "d"}}


def test_metadata(graph_access: GraphAccess) -> None:
    desired = {a["id"]: a["metadata"] for a in graph_access.not_visited_nodes()}
    assert desired == {"1": {"version": 1}, "2": {"version": 2}, "3": {"version": 3}, "4": {"version": 4}}


def test_flatten() -> None:
    js = {"id": "blub", "d": "2021-06-18T10:31:34Z", "i": 0, "s": "hello", "a": [{"a": "one"}, {"b": "two"}], "c": True}
    flat = GraphBuilder.flatten(js, AnyKind())
    assert flat == "blub 2021-06-18T10:31:34Z 0 hello one two"


def node(access: GraphAccess, node_id: NodeId) -> Optional[Json]:
    res = access.node(node_id)
    if res:
        return res
    else:
        raise AttributeError(f"Expected {node_id} to be defined!")


def test_builder(person_model: Model) -> None:
    max_m = {"id": "max", "kind": "Person", "name": "Max"}
    builder = GraphBuilder(person_model, uuid_str())
    builder.add_from_json({"id": "root", "reported": max_m})
    builder.add_from_json({"from": "root", "to": "2"})
    with pytest.raises(AssertionError) as no_node:
        builder.check_complete()
    assert str(no_node.value) == "2 was used in an edge definition but not provided as vertex!"
    builder.add_from_json({"id": "2", "reported": max_m})
    builder.add_from_json({"id": "3", "reported": max_m})
    with pytest.raises(AssertionError) as no_node:
        builder.check_complete()
    assert str(no_node.value) == "Given subgraph has more than one root: ['root', '3']"
    builder.add_from_json({"from": "root", "to": "3"})
    builder.check_complete()


def test_reassign_root(person_model: Model) -> None:
    max_m = {"id": "max", "kind": "Person", "name": "Max"}
    builder = GraphBuilder(person_model, uuid_str())
    builder.add_from_json({"id": "should_be_root", "reported": {"kind": "graph_root"}})
    builder.add_from_json({"id": "2", "reported": max_m})
    builder.add_from_json({"id": "3", "reported": max_m})
    builder.add_from_json({"from": "should_be_root", "to": "2"})
    builder.add_from_json({"from": "should_be_root", "to": "3"})
    builder.check_complete()
    access = GraphAccess(builder.graph)
    assert access.root() == "root"
    assert set(access.successors(NodeId("root"), EdgeTypes.default)) == {"2", "3"}


def test_replace_nodes(person_model: Model) -> None:
    builder = GraphBuilder(person_model, uuid_str())
    meta = {"metadata": {"replace": True}}
    builder.add_from_json({"id": "root", "reported": {"kind": "graph_root"}})
    builder.add_from_json({"id": "cloud", "reported": {"id": "cloud", "kind": "cloud"}, **meta})
    # add a node above the replace node -> shoud be added to the graph
    builder.add_from_json({"id": "any_foo", "reported": {"id": "any_foo", "kind": "any_foo"}})
    builder.add_from_json({"from": "root", "to": "any_foo"})
    # also mark account and region as replace node -> the flags should be ignored!
    builder.add_from_json({"id": "account", "reported": {"id": "account", "kind": "account"}, **meta})
    builder.add_from_json({"id": "region", "reported": {"id": "region", "kind": "region"}, **meta})
    builder.add_from_json({"from": "root", "to": "cloud"})
    builder.add_from_json({"from": "cloud", "to": "account"})
    builder.add_from_json({"from": "account", "to": "region"})
    roots, parent, gen = GraphAccess.merge_graphs(builder.graph)
    assert roots == ["cloud"]
    cloud, access = list(gen)[0]
    assert cloud == "cloud"
    assert set(access.nodes) == {"cloud", "account", "region"}
    assert set(parent.nodes) == {"cloud", "root", "any_foo"}


def multi_cloud_graph(replace_on: str) -> MultiDiGraph:
    g = MultiDiGraph()
    root = NodeId("root")

    def add_node(node_id: NodeId) -> None:
        kind = re.sub("_.*$", "", node_id)
        reported = {
            "id": f"id_{node_id}",
            "name": f"name_{node_id}",
            "kind": kind,
            "some": {"deep": {"nested": node_id}},
        }
        # for sake of testing: declare parent as phantom resource
        metadata = {"phantom": True} if kind == "parent" else {}
        if node_id.startswith(replace_on):
            metadata["replace"] = True
        g.add_node(
            node_id,
            id=node_id,
            reported=reported,
            metadata=metadata,
            kind=kind,
            kinds=[kind],
            kinds_set={kind},
        )

    def add_edge(from_node: str, to_node: str, edge_type: EdgeType = EdgeTypes.default) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        g.add_edge(from_node, to_node, key, edge_type=edge_type)

    add_node(root)
    for cloud_d in ["aws", "gcp"]:
        cloud = NodeId(f"cloud_{cloud_d}")
        add_node(cloud)
        add_edge(root, cloud)
        for account_d in range(0, 3):
            account = NodeId(f"account_{cloud}_{account_d}")
            add_node(account)
            add_edge(cloud, account)
            add_edge(account, cloud, EdgeTypes.delete)
            for region_d in ["europe", "america", "asia", "africa", "antarctica", "australia"]:
                region = NodeId(f"region_{account}_{region_d}")
                add_node(region)
                add_edge(account, region)
                add_edge(region, account, EdgeTypes.delete)
                for parent_d in range(0, 3):
                    parent = NodeId(f"parent_{region}_{parent_d}")
                    add_node(parent)
                    add_edge(region, parent)
                    add_edge(parent, region, EdgeTypes.delete)
                    for children_d in range(0, 3):
                        children = NodeId(f"child_{parent}_{children_d}")
                        add_node(children)
                        add_edge(parent, children)
                        add_edge(children, parent, EdgeTypes.delete)

    return g


def cyclic_multi_graph(acyclic: bool) -> MultiDiGraph:
    g = MultiDiGraph()
    g.add_nodes_from([1, 2, 3])
    g.add_edge(1, 2, EdgeKey(1, 2, "default"))
    g.add_edge(1, 3, EdgeKey(1, 3, "default"))
    g.add_edge(2, 3, EdgeKey(2, 3, "default"))
    g.add_edge(2, 1, EdgeKey(2, 1, "delete"))
    g.add_edge(3, 2, EdgeKey(3, 2, "delete"))
    g.add_edge(3, 1, EdgeKey(3, 1, "delete"))
    if not acyclic:
        g.add_edge(3, 1, EdgeKey(3, 1, "default"))
        g.add_edge(1, 3, EdgeKey(1, 3, "delete"))
    return g


def test_sub_graphs_from_graph_cloud() -> None:
    graph = multi_cloud_graph("cloud")
    merges, parent, graph_it = GraphAccess.merge_graphs(graph)
    graphs = list(graph_it)
    assert len(graphs) == 2
    for root, succ in graphs:
        assert len(parent.nodes) == 3  # root + 2 x cloud
        assert succ.root().startswith("cloud")
        assert len(list(succ.not_visited_nodes())) == 237
        assert len(succ.nodes) == 238
        # make sure there is no node from another subgraph
        for node_id in succ.not_visited_nodes():
            assert succ.root() in node_id["id"]
        assert len(list(succ.not_visited_edges(EdgeTypes.default))) == 237
        assert len(list(succ.not_visited_edges(EdgeTypes.delete))) == 237


def test_sub_graphs_from_graph_account() -> None:
    graph = multi_cloud_graph("account")
    merges, parent, graph_it = GraphAccess.merge_graphs(graph)
    graphs = list(graph_it)
    assert len(graphs) == 6
    for root, succ in graphs:
        assert len(parent.nodes) == 9
        assert succ.root().startswith("account")
        assert len(list(succ.not_visited_nodes())) == 78
        assert len(succ.nodes) == 79
        # make sure there is no node from another subgraph
        for node_id in succ.not_visited_nodes():
            assert succ.root() in node_id["id"]
        assert len(list(succ.not_visited_edges(EdgeTypes.default))) == 78
        assert len(list(succ.not_visited_edges(EdgeTypes.delete))) == 78


def test_acyclic() -> None:
    assert GraphAccess(cyclic_multi_graph(acyclic=False)).is_acyclic_per_edge_type() is False
    assert GraphAccess(cyclic_multi_graph(acyclic=True)).is_acyclic_per_edge_type() is True


def test_predecessors() -> None:
    graph = GraphAccess(multi_cloud_graph("account"))
    child = NodeId("child_parent_region_account_cloud_gcp_2_europe_1_0")
    parent = NodeId("parent_region_account_cloud_gcp_2_europe_1")
    region = NodeId("region_account_cloud_gcp_2_europe")

    # default: region -> parent -> child
    assert list(graph.predecessors(child, EdgeTypes.default)) == [parent]
    assert list(graph.predecessors(parent, EdgeTypes.default)) == [region]
    assert child in list(graph.successors(parent, EdgeTypes.default))
    assert parent in list(graph.successors(region, EdgeTypes.default))

    # delete: child -> parent -> region
    assert list(graph.successors(child, EdgeTypes.delete)) == [parent]
    assert list(graph.successors(parent, EdgeTypes.delete)) == [region]
    assert parent in list(graph.successors(child, EdgeTypes.delete))
    assert region in list(graph.successors(parent, EdgeTypes.delete))


def test_ancestor_of() -> None:
    nid1 = NodeId("child_parent_region_account_cloud_gcp_1_europe_1_0")
    acc1 = "account_cloud_gcp_1"
    acc2 = "account_cloud_gcp_2"
    g = multi_cloud_graph("account")

    graph = GraphAccess(g)
    assert graph.ancestor_of(nid1, EdgeTypes.default, "root") is not None
    assert graph.ancestor_of(nid1, EdgeTypes.delete, "root") is None
    assert graph.ancestor_of(nid1, EdgeTypes.default, "foo") is None
    assert graph.ancestor_of(nid1, EdgeTypes.default, "foo") is None
    assert graph.ancestor_of(nid1, EdgeTypes.default, "account")["id"] == acc1  # type: ignore
    assert graph.ancestor_of(acc1, EdgeTypes.default, "account")["id"] == acc1  # type: ignore

    # add another "shorter" edge from acc2 -> nid1, so it is shorter that from acc1 -> nid1
    key = GraphAccess.edge_key(acc2, nid1, EdgeTypes.default)
    g.add_edge(acc2, nid1, key, edge_type=EdgeTypes.default)
    assert graph.ancestor_of(nid1, EdgeTypes.default, "account")["id"] == acc2  # type: ignore


def test_resolve_graph_data() -> None:
    g = multi_cloud_graph("account")
    graph = GraphAccess(g)
    graph.resolve()

    # ancestor data should be stored in metadata
    n1 = AccessJson(graph.node("child_parent_region_account_cloud_gcp_1_europe_1_0"))  # type: ignore
    assert n1.refs.region_id == "region_account_cloud_gcp_1_europe"
    assert n1.ancestors.account.reported.id == "id_account_cloud_gcp_1"
    assert n1.ancestors.account.reported.name == "name_account_cloud_gcp_1"
    assert n1.ancestors.region.reported.id == "id_region_account_cloud_gcp_1_europe"
    assert n1.ancestors.region.reported.name == "name_region_account_cloud_gcp_1_europe"
    # make sure there is no summary
    assert n1.descendant_summary == AccessNone(None)

    r1 = AccessJson(graph.node("region_account_cloud_gcp_1_europe"))  # type: ignore
    assert r1.metadata.descendant_summary == {"child": 9}
    assert r1.metadata.descendant_count == 9
    r2 = AccessJson(graph.node("account_cloud_gcp_1"))  # type: ignore
    assert r2.metadata.descendant_summary == {"child": 54, "region": 6}
    assert r2.metadata.descendant_count == 60
    r3 = AccessJson(graph.node("cloud_gcp"))  # type: ignore
    assert r3.metadata.descendant_summary == {"child": 162, "region": 18, "account": 3}
    assert r3.metadata.descendant_count == 183


def test_model_size(person_model: Model) -> None:
    builder = GraphBuilder(person_model, uuid_str())
    tags1 = {"foo": "bar", "bla": "blub" * 22}
    a1 = {"kind": "Address", "id": "a1", "zip": "s1", "city": "c1", "list": ["ccc"]}
    a2 = {"kind": "Address", "id": "aa2", "zip": "s2", "city": "gotham", "tags": tags1}
    p1 = dict(kind="Person", id="pp1", name="pp1", address=a1, list=["a", "bb"], tags=tags1)
    p2 = dict(kind="Person", id="p2", name="ppp2", addresses=[a1, a2], other_addresses=dict(home=a1, work=a2))
    builder.add_node(NodeId("p1"), p1)
    builder.add_node(NodeId("p2"), p2)

    def kind_props(p: ComplexKind) -> Dict[str, int]:
        return {p.name: p.meta_get("len", int, 0) for p in p.all_props() if p.meta("len", int)}

    base = {"id": 3, "kind": 7, "list": 3, "tags": 88}  # base properties shared by person and address
    assert kind_props(cast(ComplexKind, person_model["Person"])) == base | {"name": 4}
    assert kind_props(cast(ComplexKind, person_model["Address"])) == base | {"city": 6, "zip": 2}
