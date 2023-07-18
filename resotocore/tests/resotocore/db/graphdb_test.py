import asyncio
import string
from abc import ABC, abstractmethod
from datetime import date, datetime, timedelta
from random import SystemRandom
from typing import List, Optional, Any, Dict, cast

from arango.database import StandardDatabase
from arango.typings import Json
from attrs import define
from networkx import MultiDiGraph
from pytest import mark, raises

from resotocore.analytics import CoreEvent, InMemoryEventSender
from resotocore.db.graphdb import ArangoGraphDB, GraphDB, EventGraphDB, HistoryChange
from resotocore.db.model import QueryModel, GraphUpdate
from resotocore.db.db_access import DbAccess
from resotocore.error import ConflictingChangeInProgress, NoSuchChangeError, InvalidBatchUpdate
from resotocore.ids import NodeId, GraphName
from resotocore.model.graph_access import GraphAccess, EdgeTypes, Section
from resotocore.model.model import Model, UsageDatapoint
from resotocore.model.typed_model import from_js, to_js
from resotocore.query.model import Query, P, Navigation
from resotocore.query.query_parser import parse_query
from resotocore.types import JsonElement, EdgeType
from resotocore.util import AccessJson, utc, value_in_path, AccessNone
from tests.resotocore.utils import eventually


class BaseResource(ABC):
    def __init__(
        self,
        identifier: str,
    ) -> None:
        self.identifier = str(identifier)

    @abstractmethod
    def kind(self) -> str:
        pass


@define
class Foo(BaseResource):
    identifier: str
    name: Optional[str] = None
    some_int: int = 0
    some_string: str = "hello"
    now_is: datetime = utc()
    ctime: Optional[datetime] = None

    def kind(self) -> str:
        return "foo"


@define
class Inner:
    name: str
    inner: List["Inner"]


@define
class Bla(BaseResource):
    identifier: str
    name: Optional[str] = None
    now: date = date.today()
    f: int = 23
    g: Optional[List[int]] = None
    h: Optional[Inner] = None

    def __attrs_post_init__(self) -> None:
        self.g = self.g if self.g is not None else list(range(0, 5))
        if self.h is None:

            def nested(idx: int, level: int) -> Inner:
                return Inner(f"in_{level}_{idx}", [] if level == 0 else [nested(idx, level - 1) for idx in range(0, 2)])

            self.h = nested(0, 2)

    def kind(self) -> str:
        return "bla"


def create_graph(bla_text: str, width: int = 10) -> MultiDiGraph:
    graph = MultiDiGraph()

    def add_edge(from_node: str, to_node: str, edge_type: EdgeType = EdgeTypes.default) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    def add_node(uid: str, kind: str, node: Optional[Json] = None, replace: bool = False) -> None:
        reported = {**(node if node else to_json(Foo(uid))), "kind": kind}
        graph.add_node(
            uid,
            id=uid,
            kinds=[kind],
            reported=reported,
            desired={"node_id": uid},
            metadata={"node_id": uid},
            replace=replace,
        )

    # root -> collector -> sub_root -> **rest
    add_node("root", "graph_root")
    add_node("collector", "cloud", replace=True)
    add_node("sub_root", "foo")
    add_edge("root", "collector")
    add_edge("collector", "sub_root")

    for o in range(0, width):
        oid = str(o)
        add_node(oid, "foo")
        add_edge("sub_root", oid)
        for i in range(0, width):
            iid = f"{o}_{i}"
            add_node(iid, "bla", node=to_json(Bla(iid, name=bla_text)))
            add_edge(oid, iid)
            add_edge(iid, oid, EdgeTypes.delete)
    return graph


def create_multi_collector_graph(width: int = 3) -> MultiDiGraph:
    graph = MultiDiGraph()

    def add_edge(from_node: str, to_node: str, edge_type: EdgeType = EdgeTypes.default) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    def add_node(node_id: NodeId, kind: NodeId, replace: bool = False) -> NodeId:
        reported = {**to_json(Foo(node_id)), "id": node_id, "name": node_id, "kind": kind}
        graph.add_node(
            node_id,
            id=node_id,
            reported=reported,
            desired={},
            metadata={},
            hash="123",
            replace=replace,
            kind=kind,
            kinds=[kind],
            kinds_set={kind},
        )
        return node_id

    root = add_node(NodeId("root"), NodeId("graph_root"))
    for cloud_num in range(0, 2):
        cloud = add_node(NodeId(f"cloud_{cloud_num}"), NodeId("cloud"))
        add_edge(root, cloud)
        for account_num in range(0, 2):
            aid = f"{cloud_num}:{account_num}"
            account = add_node(NodeId(f"account_{aid}"), NodeId("account"))
            add_edge(cloud, account)
            add_edge(account, cloud, EdgeTypes.delete)
            for region_num in range(0, 2):
                rid = f"{aid}:{region_num}"
                region = add_node(NodeId(f"region_{rid}"), NodeId("region"), replace=True)
                add_edge(account, region)
                add_edge(region, account, EdgeTypes.delete)
                for parent_num in range(0, width):
                    pid = f"{rid}:{parent_num}"
                    parent = add_node(NodeId(f"parent_{pid}"), NodeId("parent"))
                    add_edge(region, parent)
                    add_edge(parent, region, EdgeTypes.delete)
                    for child_num in range(0, width):
                        cid = f"{pid}:{child_num}"
                        child = add_node(NodeId(f"child_{cid}"), NodeId("child"))
                        add_edge(parent, child)
                        add_edge(child, parent, EdgeTypes.delete)

    return graph


async def load_graph(db: GraphDB, model: Model, base_id: str = "sub_root") -> MultiDiGraph:
    blas = Query.by("foo", P("identifier") == base_id).traverse_out(0, Navigation.Max)
    return await db.search_graph(QueryModel(blas.on_section("reported"), model))


@mark.asyncio
async def test_update_merge_batched(graph_db: ArangoGraphDB, foo_model: Model, test_db: StandardDatabase) -> None:
    md = foo_model
    await graph_db.wipe()
    batch_id = "".join(SystemRandom().choice(string.ascii_letters) for _ in range(12))
    g = create_graph("yes or no")
    await graph_db.insert_usage_data(
        [
            UsageDatapoint("0", at=100, v={"cpu": {"min": 42, "avg": 42, "max": 42}}, change_id=batch_id),
            UsageDatapoint("0", at=101, v={"cpu": {"min": 0.42, "avg": 0.42, "max": 0.42}}, change_id="foo"),
        ]
    )

    # empty database: all changes are written to a temp table
    assert await graph_db.merge_graph(g, foo_model, batch_id, True) == (
        ["collector"],
        GraphUpdate(112, 1, 0, 212, 0, 0),
    )
    assert len((await load_graph(graph_db, md)).nodes) == 0
    # not allowed to commit an unknown batch
    with raises(NoSuchChangeError):
        await graph_db.commit_batch_update("does_not_exist")
    # commit the batch and see the changes reflected in the database
    await graph_db.commit_batch_update(batch_id)
    updated_graph = await load_graph(graph_db, md)
    assert len(updated_graph.nodes) == 111
    # ensure that all temp tables are removed
    assert len(list(filter(lambda c: c["name"].startswith("temp_"), cast(List[Json], test_db.collections())))) == 0
    # ensure the usage is there
    n = await graph_db.get_node(foo_model, NodeId("0")) or {}
    assert n.get("usage", {}).get("cpu") == {"min": 42, "avg": 42, "max": 42}
    # create a new batch that gets aborted: make sure all temp tables are gone
    batch_id = "will_be_aborted"
    await graph_db.merge_graph(g, foo_model, batch_id, True)
    await graph_db.abort_update(batch_id)
    assert len(list(filter(lambda c: c["name"].startswith("temp_"), cast(List[Json], test_db.collections())))) == 0


@mark.asyncio
async def test_merge_graph(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()

    def create(txt: str, width: int = 10) -> MultiDiGraph:
        return create_graph(txt, width=width)

    await graph_db.insert_usage_data(
        [
            UsageDatapoint("0", at=100, v={"cpu": {"min": 42, "avg": 42, "max": 42}}, change_id="foo"),
            UsageDatapoint("0", at=101, v={"cpu": {"min": 0.42, "avg": 0.42, "max": 0.42}}, change_id="bar"),
        ]
    )

    p = ["collector"]
    # empty database: all nodes and all edges have to be inserted, the root node is updated and the link to root added
    assert await graph_db.merge_graph(create("yes or no"), foo_model, maybe_change_id="foo") == (
        p,
        GraphUpdate(112, 1, 0, 212, 0, 0),
    )

    # check the usage
    async def check_usage() -> bool:
        n = await graph_db.get_node(foo_model, NodeId("0")) or {}
        node_usage: Dict[str, float] = n.get("usage", {}).get("cpu", {})
        expected = {"min": 42, "avg": 42, "max": 42}
        return node_usage == expected

    await eventually(check_usage)

    # exactly the same graph is updated: expect no changes
    assert await graph_db.merge_graph(create("yes or no"), foo_model) == (p, GraphUpdate(0, 0, 0, 0, 0, 0))
    # all bla entries have different content: expect 100 node updates, but no inserts or deletions
    assert await graph_db.merge_graph(create("maybe"), foo_model) == (p, GraphUpdate(0, 100, 0, 0, 0, 0))
    # the width of the graph is reduced: expect nodes and edges to be removed
    assert await graph_db.merge_graph(create("maybe", width=5), foo_model) == (p, GraphUpdate(0, 0, 80, 0, 0, 155))
    # going back to the previous graph: the same amount of nodes and edges is inserted
    assert await graph_db.merge_graph(create("maybe"), foo_model) == (p, GraphUpdate(80, 0, 0, 155, 0, 0))
    # updating with the same data again, does not perform any changes
    assert await graph_db.merge_graph(create("maybe"), foo_model) == (p, GraphUpdate(0, 0, 0, 0, 0, 0))


@mark.asyncio
async def test_merge_multi_graph(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    # nodes:
    # 2 collectors + 4 accounts + 8 regions + 24 parents + 72 children => 110 nodes to insert
    # 1 root which changes => 1 node to update
    # edges:
    # 110 default, 108 delete connections (missing: collector -> root) => 218 edge inserts
    nodes, info = await graph_db.merge_graph(create_multi_collector_graph(), foo_model)
    assert info == GraphUpdate(110, 1, 0, 218, 0, 0)
    assert len(nodes) == 8
    # doing the same thing again should do nothing
    nodes, info = await graph_db.merge_graph(create_multi_collector_graph(), foo_model)
    assert info == GraphUpdate(0, 0, 0, 0, 0, 0)
    assert len(nodes) == 8


@mark.asyncio
async def test_mark_update(filled_graph_db: ArangoGraphDB) -> None:
    db = filled_graph_db
    # make sure all changes are empty
    await db.db.truncate(db.in_progress)
    # change on 00 is allowed
    await db.mark_update(["00"], ["0", "sub_root", "root"], "update 00", False)
    # change on 01 is allowed
    await db.mark_update(["01"], ["0", "sub_root", "root"], "update 01", True)
    # same change id which tries to update the same subgraph root
    with raises(InvalidBatchUpdate):
        await db.mark_update(["01"], ["0", "sub_root", "root"], "update 01", True)
    # change on 0 is rejected, since there are changes "below" this node
    with raises(ConflictingChangeInProgress):
        await db.mark_update(["0"], ["sub_root"], "update 0 under node sub_root", False)
    # change on sub_root is rejected, since there are changes "below" this node
    with raises(ConflictingChangeInProgress):
        await db.mark_update(["sub_root"], ["root"], "update under node sub_root", False)
    # clean up for later tests
    await db.db.truncate(db.in_progress)


@mark.asyncio
async def test_query_list(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    blas = Query.by("foo", P("identifier") == "9").traverse_out().filter("bla", P("f") == 23)
    async with await filled_graph_db.search_list(QueryModel(blas.on_section("reported"), foo_model)) as gen:
        result = [from_js(x["reported"], Bla) async for x in gen]
        assert len(result) == 10

    foos_or_blas = parse_query("is([foo, bla])")
    async with await filled_graph_db.search_list(QueryModel(foos_or_blas.on_section("reported"), foo_model)) as gen:
        result = [x async for x in gen]
        assert len(result) == 111  # 113 minus 1 graph_root, minus one cloud


@mark.asyncio
async def test_query_not(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    # select everything that is not foo --> should be blas
    blas = Query.by(Query.mk_term("foo").not_term())
    async with await filled_graph_db.search_list(QueryModel(blas.on_section("reported"), foo_model)) as gen:
        result = [from_js(x["reported"], Bla) async for x in gen]
        assert len(result) == 102


@mark.asyncio
async def test_query_history(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    async def nodes(query: Query, **args: Any) -> List[Json]:
        async with await filled_graph_db.search_history(QueryModel(query, foo_model), **args) as crsr:
            return [x async for x in crsr]

    now = utc()
    five_min_ago = now - timedelta(minutes=5)
    assert len(await nodes(Query.by("foo"))) == 11
    assert len(await nodes(Query.by("foo"), after=five_min_ago)) == 11
    assert len(await nodes(Query.by("foo"), before=five_min_ago)) == 0
    assert len(await nodes(Query.by("foo"), after=five_min_ago, change=HistoryChange.node_created)) == 11
    assert len(await nodes(Query.by("foo"), after=five_min_ago, change=HistoryChange.node_deleted)) == 0


@mark.asyncio
async def test_query_graph(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    graph = await load_graph(filled_graph_db, foo_model)
    assert len(graph.edges) == 110
    assert len(graph.nodes.values()) == 111

    # filter data and tag result, and then traverse to the end of the graph in both directions
    around_me = Query.by("foo", P("identifier") == "9").tag("red").traverse_inout(start=0)
    graph = await filled_graph_db.search_graph(QueryModel(around_me.on_section("reported"), foo_model))
    assert len({x for x in graph.nodes}) == 12
    assert GraphAccess.root_id(graph) == "sub_root"
    assert list(graph.successors("sub_root"))[0] == "9"
    assert set(graph.successors("9")) == {f"9_{x}" for x in range(0, 10)}
    for from_node, to_node, data in graph.edges.data(True):
        assert from_node == "9" or to_node == "9"
        assert data == {"edge_type": "default"}

    node_id: str
    node: Json
    for node_id, node in graph.nodes.data(True):
        if node_id == "9":
            assert node["metadata"]["query_tag"] == "red"
        else:
            assert "tag" not in node["metadata"]

    async def assert_result(query: str, nodes: int, edges: int) -> None:
        q = parse_query(query)
        graph = await filled_graph_db.search_graph(QueryModel(q, foo_model))
        assert len(graph.nodes) == nodes
        assert len(graph.edges) == edges

    await assert_result("is(foo) and reported.identifier==9 <-delete[0:]default->", 11, 20)
    await assert_result("is(foo) and reported.identifier==9 <-default[0:]delete->", 4, 3)
    await assert_result("is(foo) and reported.identifier==9 <-default[0:]->", 14, 13)
    await assert_result("is(foo) and reported.identifier==9 <-delete[0:]->", 11, 10)
    await assert_result("is(foo) and reported.identifier==9 -default[0:]->", 11, 10)
    await assert_result("is(foo) and reported.identifier==9 <-delete[0:]-", 11, 10)
    await assert_result("is(foo) and reported.identifier==9 <-default[0:]-", 4, 3)
    await assert_result("is(foo) and reported.identifier==9 -delete[0:]->", 1, 0)


@mark.asyncio
async def test_query_nested(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    async def assert_count(query: str, count: int) -> None:
        q = parse_query(query).on_section("reported")
        async with await filled_graph_db.search_list(QueryModel(q, foo_model), with_count=True) as gen:
            assert gen.cursor.count() == count
            assert len([a async for a in gen]) == count

    await assert_count("is(bla) and h.inner[*].inner[*].name=in_0_1", 100)
    await assert_count("is(bla) and h.inner[*].inner[*].inner == []", 100)
    await assert_count("is(bla) and g[*] = 2", 100)
    await assert_count("is(bla) and g any = 2", 100)
    await assert_count("is(bla) and g all = 2", 0)
    await assert_count("is(bla) and g none = 2", 0)
    await assert_count("is(bla) and g[*] any = 2", 100)
    await assert_count("is(bla) and g[*] all = 2", 0)
    await assert_count("is(bla) and g[*] none = 2", 0)


@mark.asyncio
async def test_query_aggregate(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    agg_query = parse_query("aggregate(kind: count(identifier) as instances): is(foo)").on_section("reported")
    async with await filled_graph_db.search_aggregation(QueryModel(agg_query, foo_model)) as gen:
        assert [x async for x in gen] == [{"group": {"kind": "foo"}, "instances": 11}]

    agg_combined_var_query = parse_query(
        'aggregate("test_{kind}_{some_int}_{does_not_exist}" as kind: count(identifier) as instances): is("foo")'
    ).on_section("reported")

    async with await filled_graph_db.search_aggregation(QueryModel(agg_combined_var_query, foo_model)) as g:
        assert [x async for x in g] == [{"group": {"kind": "test_foo_0_"}, "instances": 11}]

    agg_multi_fn_same_prop = parse_query('aggregate(sum(f) as a, max(f) as b): is("bla")').on_section("reported")
    async with await filled_graph_db.search_aggregation(QueryModel(agg_multi_fn_same_prop, foo_model)) as g:
        assert [x async for x in g] == [{"a": 2300, "b": 23}]


@mark.asyncio
async def test_query_with_fulltext(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    async def search(query: str) -> List[JsonElement]:
        async with await filled_graph_db.search_list(QueryModel(parse_query(query), foo_model)) as cursor:
            return [elem async for elem in cursor]

    # Note: the fulltext index is eventually consistent. Since the database is wiped and cleaned for this test
    # we should not have any assumptions about the results, other than the query succeeds
    await search('(("a" and "b") or ("c" and "d")) and "e"')
    await search('is(foo) and "test" --> "bim bam bom bum"')
    await search('is(foo) {a: --> "some prop" } "some other prop" --> "bim bam bom bum"')


@mark.asyncio
async def test_query_merge(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    q = parse_query(
        "is(foo) --> is(bla) { "
        "foo.bar.parents[]: <-[1:]-, "
        "foo.child: -->, "
        "walk: <-- -->, "
        "bla.agg: aggregate(sum(1) as count): <-[0:]- "
        "}"
    )
    async with await filled_graph_db.search_list(QueryModel(q, foo_model), with_count=True) as cursor:
        assert cursor.count() == 100
        async for bla in cursor:
            b = AccessJson(bla)
            assert b.reported.kind == "bla"
            assert len(b.foo.bar.parents) == 4
            for parent in b.foo.bar.parents:
                assert parent.reported.kind in ["foo", "cloud", "graph_root"]
            assert b.walk.reported.kind == "bla"
            assert b.foo.child == AccessNone()
            assert b.bla.agg == [{"count": 5}]


@mark.asyncio
async def test_query_with_clause(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    async def query(q: str) -> List[Json]:
        agg_query = parse_query(q)
        async with await filled_graph_db.search_list(QueryModel(agg_query.on_section("reported"), foo_model)) as cursor:
            return [bla async for bla in cursor]

    assert len(await query("is(bla) with(any, <-- is(foo))")) == 100
    assert len(await query('is(bla) with(any, <-- is(foo) and identifier=~"1")')) == 10
    assert len(await query("is(bla) with(empty, <-- is(foo))")) == 0
    assert len(await query("is(bla) with(any, <-- is(bla))")) == 0
    assert len(await query("is(bla) with(empty, <-- is(bla))")) == 100
    assert len(await query('is(bla) with(count==1, <-- is(foo) and identifier=~"1")')) == 10
    assert len(await query('is(bla) with(count==2, <-- is(foo) and identifier=~"1")')) == 0
    assert len(await query("is(bla) with(any, <-- with(any, <-- is(foo)))")) == 100


@mark.asyncio
async def test_no_null_if_undefined(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    # imported graph should not have any desired or metadata sections
    graph = create_graph("test", 0)
    for _, node in graph.nodes(True):
        del node["desired"]
        del node["metadata"]
    await graph_db.merge_graph(graph, foo_model)
    async with await graph_db.search_list(QueryModel(parse_query("all"), foo_model)) as cursor:
        async for elem in cursor:
            assert "reported" in elem
            assert "desired" not in elem
            assert "metadata" not in elem


@mark.asyncio
async def test_get_node(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    # load sub_root as foo
    sub_root = to_foo(await filled_graph_db.get_node(foo_model, NodeId("sub_root")))
    assert sub_root is not None
    assert isinstance(sub_root, Foo)
    # load node 7 as foo
    node_7_json = await filled_graph_db.get_node(foo_model, NodeId("7"))
    node_7 = to_foo(node_7_json)
    assert node_7 is not None
    assert isinstance(node_7, Foo)
    # make sure that all synthetic properties are rendered (the age should not be older than 1 second => 0s or 1s)
    assert node_7_json[Section.reported]["age"] in ["0s", "1s"]  # type: ignore
    # load node 1_2 as bla
    node_1_2 = to_bla(await filled_graph_db.get_node(foo_model, NodeId("1_2")))
    assert node_1_2 is not None
    assert isinstance(node_1_2, Bla)


@mark.asyncio
async def test_insert_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    json = await graph_db.create_node(
        foo_model, NodeId("some_new_id"), to_json(Foo("some_new_id", "name")), NodeId("root")
    )
    assert to_foo(json).identifier == "some_new_id"
    assert to_foo(await graph_db.get_node(foo_model, NodeId("some_new_id"))).identifier == "some_new_id"


@mark.asyncio
async def test_update_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    await graph_db.create_node(foo_model, NodeId("some_other"), to_json(Foo("some_other", "foo")), NodeId("root"))
    json_patch = await graph_db.update_node(foo_model, NodeId("some_other"), {"name": "bla"}, False, "reported")
    assert to_foo(json_patch).name == "bla"
    assert to_foo(await graph_db.get_node(foo_model, NodeId("some_other"))).name == "bla"
    json_replace = (
        await graph_db.update_node(
            foo_model, NodeId("some_other"), {"kind": "bla", "identifier": "123"}, True, "reported"
        )
    )["reported"]
    json_replace.pop("ctime")  # ctime is added by the system automatically. remove it
    assert json_replace == {"kind": "bla", "identifier": "123"}


@mark.asyncio
async def test_update_nodes(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    def expect(jsons: List[Json], path: List[str], value: JsonElement) -> None:
        for js in jsons:
            v = value_in_path(js, path)
            assert v is not None
            assert v == value

    await graph_db.wipe()
    await graph_db.create_node(foo_model, NodeId("id1"), to_json(Foo("id1", "foo")), NodeId("root"))
    await graph_db.create_node(foo_model, NodeId("id2"), to_json(Foo("id2", "foo")), NodeId("root"))
    # only change the desired section
    change1 = {"desired": {"test": True}}
    result1 = [a async for a in graph_db.update_nodes(foo_model, {NodeId("id1"): change1, NodeId("id2"): change1})]
    assert len(result1) == 2
    expect(result1, ["desired", "test"], True)
    # only change the metadata section
    change2 = {"metadata": {"test": True}}
    result2 = [a async for a in graph_db.update_nodes(foo_model, {NodeId("id1"): change2, NodeId("id2"): change2})]
    assert len(result2) == 2
    expect(result2, ["metadata", "test"], True)
    # change all sections including the reported section
    change3 = {"desired": {"test": False}, "metadata": {"test": False}, "reported": {"name": "test"}}
    node_raw_id1 = AccessJson.wrap_object(graph_db.db.db.collection(graph_db.name).get("id1"))
    result3 = [a async for a in graph_db.update_nodes(foo_model, {NodeId("id1"): change3, NodeId("id2"): change3})]
    assert len(result3) == 2
    expect(result3, ["desired", "test"], False)
    expect(result3, ["metadata", "test"], False)
    expect(result3, ["reported", "name"], "test")
    # make sure the db is updated
    node_raw_id1_updated = AccessJson.wrap_object(graph_db.db.db.collection(graph_db.name).get("id1"))
    assert node_raw_id1.reported.name != node_raw_id1_updated.reported.name
    assert node_raw_id1.desired.test != node_raw_id1_updated.desired.test
    assert node_raw_id1.metadata.test != node_raw_id1_updated.metadata.test
    assert node_raw_id1.flat != node_raw_id1_updated.flat
    assert node_raw_id1.hash != node_raw_id1_updated.hash
    assert "test" in node_raw_id1_updated.flat
    change4 = {"desired": None, "metadata": None}
    result4 = [
        a
        async for a in graph_db.update_nodes(foo_model, {NodeId("id1"): change4.copy(), NodeId("id2"): change4.copy()})
    ]
    assert len(result4) == 4
    assert all("desired" not in a for a in result4)
    assert len([a for a in result4 if "metadata" not in a]) == 2


@mark.asyncio
async def test_delete_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    await graph_db.create_node(foo_model, NodeId("sub_root"), to_json(Foo("sub_root", "foo")), NodeId("root"))
    await graph_db.create_node(
        foo_model, NodeId("some_other_child"), to_json(Foo("some_other_child", "foo")), NodeId("sub_root")
    )
    await graph_db.create_node(foo_model, NodeId("born_to_die"), to_json(Foo("born_to_die", "foo")), NodeId("sub_root"))
    await graph_db.delete_node(NodeId("born_to_die"))
    assert await graph_db.get_node(foo_model, NodeId("born_to_die")) is None
    with raises(AttributeError) as not_allowed:
        await graph_db.delete_node(NodeId("sub_root"))
    assert str(not_allowed.value) == "Can not delete node, since it has 1 child(ren)!"


@mark.asyncio
async def test_events(
    event_graph_db: EventGraphDB, foo_model: Model, event_sender: InMemoryEventSender, db_access: DbAccess
) -> None:
    await event_graph_db.create_node(foo_model, NodeId("some_other"), to_json(Foo("some_other", "foo")), NodeId("root"))
    await event_graph_db.update_node(foo_model, NodeId("some_other"), {"name": "bla"}, False, "reported")
    await event_graph_db.delete_node(NodeId("some_other"))
    await event_graph_db.merge_graph(create_graph("yes or no", width=1), foo_model)
    await event_graph_db.merge_graph(create_graph("maybe", width=1), foo_model, "batch1", True)
    copy_graph_name = GraphName("graph_copy_for_event")
    await db_access.delete_graph(copy_graph_name)
    await event_graph_db.copy_graph(copy_graph_name)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.kind for a in event_sender.events] == [
        CoreEvent.NodeCreated,
        CoreEvent.NodeUpdated,
        CoreEvent.NodeDeleted,
        CoreEvent.GraphMerged,
        CoreEvent.BatchUpdateGraphMerged,
        CoreEvent.GraphCopied,
    ]
    merge_event = AccessJson(event_sender.events[3].context)
    assert merge_event.graph == event_graph_db.graph_name
    assert merge_event.providers == ["collector"]
    assert merge_event.batch is False
    copy_event = AccessJson(event_sender.events[5].context)
    assert copy_event.graph == event_graph_db.name
    assert copy_event.to_graph == "graph_copy_for_event"
    await db_access.delete_graph(copy_graph_name)


@mark.asyncio
async def test_db_copy(graph_db: ArangoGraphDB, foo_model: Model, db_access: DbAccess) -> None:
    await graph_db.wipe()

    # populate some data in the graphes
    nodes, info = await graph_db.merge_graph(create_multi_collector_graph(), foo_model)
    assert info == GraphUpdate(110, 1, 0, 218, 0, 0)
    assert len(nodes) == 8

    db = graph_db.db
    copy_db_name = GraphName("copy_" + graph_db.name)
    # make sure the copy graph does not exist
    await db_access.delete_graph(copy_db_name)

    # copy the graph
    copy_db = await graph_db.copy_graph(copy_db_name)
    assert copy_db.name == copy_db_name

    async def validate(original_db_name: GraphName, copy_db_name: str) -> None:
        # validate the vertices
        existing_vertex_ids = {a["_key"] for a in await db.all(original_db_name)}
        copy_vertex_ids = {a["_key"] for a in await db.all(copy_db_name)}
        assert existing_vertex_ids == copy_vertex_ids

        # validate the default edges
        existing_default_edge_ids = {a["_key"] for a in await db.all(f"{original_db_name}_default")}
        copy_default_edge_ids = {a["_key"] for a in await db.all(f"{copy_db_name}_default")}
        assert existing_default_edge_ids == copy_default_edge_ids

        # validate the delete edges
        existing_delete_edge_ids = {a["_key"] for a in await db.all(f"{original_db_name}_delete")}
        copy_delete_edge_ids = {a["_key"] for a in await db.all(f"{copy_db_name}_delete")}
        assert existing_delete_edge_ids == copy_delete_edge_ids

    await validate(graph_db.name, copy_db.name)

    # check snapshots
    snapshot_db_name = GraphName("snapshot-" + graph_db.name)
    snapshot_db = await graph_db.copy_graph(snapshot_db_name, to_snapshot=True)
    assert snapshot_db.name == snapshot_db_name
    await validate(graph_db.name, snapshot_db.name)

    # clean up
    await snapshot_db.wipe()


@mark.asyncio
async def test_no_snapshot_usage(graph_db: ArangoGraphDB, foo_model: Model, db_access: DbAccess) -> None:
    await graph_db.wipe()
    await db_access.delete_graph(GraphName("snapshot-" + graph_db.name))

    snapshot_db_name = GraphName("snapshot-" + graph_db.name)
    snapshot_db = await graph_db.copy_graph(snapshot_db_name, to_snapshot=True)

    with raises(ValueError) as ex:
        await snapshot_db.insert_usage_data(
            [UsageDatapoint("foo", 42, "foo", {"cpu": {"min": 0.42, "avg": 0.42, "max": 0.42}})]
        )

    assert str(ex.value) == "Cannot insert usage data into a snapshot graph"

    # clean up
    await snapshot_db.wipe()


def test_render_metadata_section(foo_model: Model) -> None:
    printer = ArangoGraphDB.document_to_instance_fn(foo_model)
    out = printer({"_key": "1", "reported": {"kind": "foo"}, "metadata": {"exported_at": "2023-03-06T19:37:51Z"}})
    assert "exported_age" in out["metadata"]  # exported_age is not part of the document, but should be added


def to_json(obj: BaseResource) -> Json:
    return {"kind": obj.kind(), **to_js(obj)}


def to_bla(json: Optional[Json]) -> Bla:
    assert json is not None
    return from_js(json["reported"], Bla)


def to_foo(json: Optional[Json]) -> Foo:
    assert json is not None
    return from_js(json["reported"], Foo)
