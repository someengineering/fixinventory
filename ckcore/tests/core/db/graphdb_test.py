import asyncio
import string
from abc import ABC
from datetime import date, datetime
from random import SystemRandom
from typing import List, Optional

import pytest
from arango import ArangoClient
from arango.database import StandardDatabase
from arango.typings import Json
from networkx import DiGraph, MultiDiGraph

from core.db.async_arangodb import AsyncArangoDB
from core.db.graphdb import ArangoGraphDB, GraphDB, EventGraphDB
from core.error import ConflictingChangeInProgress, NoSuchChangeError, InvalidBatchUpdate
from core.message_bus import MessageBus, Message
from core.model.adjust_node import NoAdjust
from core.model.graph_access import GraphAccess, EdgeType, Section
from core.model.model import Model, ComplexKind, Property, Kind, SyntheticProperty
from core.model.typed_model import to_js, from_js
from core.query.model import Query, P, Navigation
from core.query.query_parser import parse_query
from core.types import JsonElement
from core.util import AccessJson, utc, value_in_path

# noinspection PyUnresolvedReferences
from core.db.model import QueryModel, GraphUpdate

# noinspection PyUnresolvedReferences
from tests.core.message_bus_test import message_bus, all_events


class BaseResource(ABC):
    def __init__(
        self,
        identifier: str,
    ) -> None:
        self.identifier = str(identifier)

    # this method should be defined in all resources
    def kind(self) -> str:
        pass


class Foo(BaseResource):
    def __init__(
        self,
        identifier: str,
        name: Optional[str] = None,
        some_int: int = 0,
        some_string: str = "hello",
        now_is: datetime = utc(),
        ctime: Optional[datetime] = None,
    ) -> None:
        super().__init__(identifier)
        self.name = name
        self.some_int = some_int
        self.some_string = some_string
        self.now_is = now_is
        self.ctime = ctime

    def kind(self) -> str:
        return "foo"


class Bla(BaseResource):
    def __init__(
        self,
        identifier: str,
        name: Optional[str] = None,
        now: date = date.today(),
        f: int = 23,
        g: Optional[List[int]] = None,
    ) -> None:
        super().__init__(identifier)
        self.name = name
        self.now = now
        self.f = f
        self.g = g if g is not None else list(range(0, 5))

    def kind(self) -> str:
        return "bla"


def create_graph(bla_text: str, width: int = 10) -> MultiDiGraph:
    graph = MultiDiGraph()

    def add_edge(from_node: str, to_node: str, edge_type: str = EdgeType.dependency) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    def add_node(uid: str, kind: str, node: Optional[Json] = None, replace: bool = False) -> None:
        reported = node if node else to_json(Foo(uid))
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
    add_node("root", "foo")
    add_node("collector", "foo", replace=True)
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
    return graph


def create_multi_collector_graph(width: int = 3) -> MultiDiGraph:
    graph = MultiDiGraph()

    def add_edge(from_node: str, to_node: str, edge_type: str = EdgeType.dependency) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    def add_node(node_id: str, replace: bool = False) -> str:
        graph.add_node(node_id, reported=to_json(Foo(node_id)), replace=replace, kinds=["foo"])
        return node_id

    root = add_node("root")
    for collector_num in range(0, 2):
        collector = add_node(f"collector_{collector_num}")
        add_edge(root, collector)
        for account_num in range(0, 2):
            aid = f"{collector_num}:{account_num}"
            account = add_node(f"account_{aid}")
            add_edge(collector, account)
            add_edge(account, collector, EdgeType.delete)
            for region_num in range(0, 2):
                rid = f"{aid}:{region_num}"
                region = add_node(f"region_{rid}", replace=True)
                add_edge(account, region)
                add_edge(region, account, EdgeType.delete)
                for parent_num in range(0, width):
                    pid = f"{rid}:{parent_num}"
                    parent = add_node(f"parent_{pid}")
                    add_edge(region, parent)
                    add_edge(parent, region, EdgeType.delete)
                    for child_num in range(0, width):
                        cid = f"{pid}:{child_num}"
                        child = add_node(f"child_{cid}")
                        add_edge(parent, child)
                        add_edge(child, parent, EdgeType.delete)

    return graph


@pytest.fixture
def foo_kinds() -> List[Kind]:
    base = ComplexKind(
        "base",
        [],
        [
            Property("identifier", "string", required=True),
            Property("kind", "string", required=True),
        ],
    )
    foo = ComplexKind(
        "foo",
        ["base"],
        [
            Property("name", "string"),
            Property("some_int", "int32"),
            Property("some_string", "string"),
            Property("now_is", "datetime"),
            Property("ctime", "datetime"),
            Property("age", "trafo.duration_to_datetime", False, SyntheticProperty(["ctime"])),
        ],
    )
    bla = ComplexKind(
        "bla",
        ["base"],
        [
            Property("name", "string"),
            Property("now", "date"),
            Property("f", "int32"),
            Property("g", "int32[]"),
        ],
    )
    return [base, foo, bla]


@pytest.fixture
def foo_model(foo_kinds: List[Kind]) -> Model:
    return Model.from_kinds(foo_kinds)


@pytest.fixture
def test_db() -> StandardDatabase:
    # Initialize the client for ArangoDB.
    client = ArangoClient(hosts="http://localhost:8529")

    # create test database: assumption is the root user with empty password
    system = client.db("_system", username="root", password="root")
    if not system.has_user("test"):
        system.create_user("test", "test", True)

    if not system.has_database("test"):
        system.create_database("test", [{"username": "test", "password": "test", "active": True}])

    # Connect to "test" database as "test" user.
    return client.db("test", username="test", password="test")


@pytest.fixture
async def graph_db(test_db: StandardDatabase) -> ArangoGraphDB:
    async_db = AsyncArangoDB(test_db)
    graph_db = ArangoGraphDB(async_db, "ns", NoAdjust())
    await graph_db.create_update_schema()
    await async_db.truncate(graph_db.in_progress)
    return graph_db


@pytest.fixture
async def filled_graph_db(graph_db: ArangoGraphDB, foo_model: Model) -> ArangoGraphDB:
    await graph_db.wipe()
    await graph_db.merge_graph(create_graph("yes or no"), foo_model)
    return graph_db


@pytest.fixture
async def event_graph_db(filled_graph_db: ArangoGraphDB, message_bus: MessageBus) -> EventGraphDB:
    return EventGraphDB(filled_graph_db, message_bus)


async def load_graph(db: GraphDB, model: Model, base_id: str = "sub_root") -> DiGraph:
    blas = Query.by("foo", P("identifier") == base_id).traverse_out(0, Navigation.Max)
    return await db.query_graph(QueryModel(blas, model, "reported"))


@pytest.mark.asyncio
async def test_update_merge_batched(graph_db: ArangoGraphDB, foo_model: Model, test_db: StandardDatabase) -> None:
    md = foo_model
    await graph_db.wipe()
    batch_id = "".join(SystemRandom().choice(string.ascii_letters) for _ in range(12))
    g = create_graph("yes or no")

    # empty database: all changes are written to a temp table
    assert await graph_db.merge_graph(g, foo_model, batch_id, True) == (
        ["collector"],
        GraphUpdate(112, 1, 0, 112, 0, 0),
    )
    assert len((await load_graph(graph_db, md)).nodes) == 0
    # not allowed to commit an unknown batch
    with pytest.raises(NoSuchChangeError):
        await graph_db.commit_batch_update("does_not_exist")
    # commit the batch and see the changes reflected in the database
    await graph_db.commit_batch_update(batch_id)
    assert len((await load_graph(graph_db, md)).nodes) == 111
    # ensure that all temp tables are removed
    assert len(list(filter(lambda c: c["name"].startswith("temp"), test_db.collections()))) == 0
    # create a new batch that gets aborted: make sure all temp tables are gone
    batch_id = "will_be_aborted"
    await graph_db.merge_graph(g, foo_model, batch_id, True)
    await graph_db.abort_update(batch_id)
    assert len(list(filter(lambda c: c["name"].startswith("temp"), test_db.collections()))) == 0


@pytest.mark.asyncio
async def test_merge_graph(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()

    def create(txt: str, width: int = 10) -> MultiDiGraph:
        return create_graph(txt, width=width)

    p = ["collector"]
    # empty database: all nodes and all edges have to be inserted, the root node is updated and the link to root added
    assert await graph_db.merge_graph(create("yes or no"), foo_model) == (p, GraphUpdate(112, 1, 0, 112, 0, 0))
    # exactly the same graph is updated: expect no changes
    assert await graph_db.merge_graph(create("yes or no"), foo_model) == (p, GraphUpdate(0, 0, 0, 0, 0, 0))
    # all bla entries have different content: expect 100 node updates, but no inserts or deletions
    assert await graph_db.merge_graph(create("maybe"), foo_model) == (p, GraphUpdate(0, 100, 0, 0, 0, 0))
    # the width of the graph is reduced: expect nodes and edges to be removed
    assert await graph_db.merge_graph(create("maybe", width=5), foo_model) == (p, GraphUpdate(0, 0, 80, 0, 0, 80))
    # going back to the previous graph: the same amount of nodes and edges is inserted
    assert await graph_db.merge_graph(create("maybe"), foo_model) == (p, GraphUpdate(80, 0, 0, 80, 0, 0))
    # updating with the same data again, does not perform any changes
    assert await graph_db.merge_graph(create("maybe"), foo_model) == (p, GraphUpdate(0, 0, 0, 0, 0, 0))


@pytest.mark.asyncio
async def test_merge_multi_graph(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    # nodes:
    # 2 collectors + 4 accounts + 8 regions + 24 parents + 72 children => 110 nodes to insert
    # 1 root which changes => 1 node to update
    # edges:
    # 110 dependency, 108 delete connections (missing: collector -> root) => 218 edge inserts
    nodes, info = await graph_db.merge_graph(create_multi_collector_graph(), foo_model)
    assert info == GraphUpdate(110, 1, 0, 218, 0, 0)
    assert len(nodes) == 8
    # doing the same thing again should do nothing
    nodes, info = await graph_db.merge_graph(create_multi_collector_graph(), foo_model)
    assert info == GraphUpdate(0, 0, 0, 0, 0, 0)
    assert len(nodes) == 8


@pytest.mark.asyncio
async def test_mark_update(filled_graph_db: ArangoGraphDB) -> None:
    db = filled_graph_db
    # make sure all changes are empty
    await db.db.truncate(db.in_progress)
    # change on 00 is allowed
    assert await db.mark_update(["00"], ["0", "sub_root", "root"], "update 00", False) is None
    # change on 01 is allowed
    assert await db.mark_update(["01"], ["0", "sub_root", "root"], "update 01", True) is None
    # same change id which tries to update the same subgraph root
    with pytest.raises(InvalidBatchUpdate):
        assert await db.mark_update(["01"], ["0", "sub_root", "root"], "update 01", True) is None
    # change on 0 is rejected, since there are changes "below" this node
    with pytest.raises(ConflictingChangeInProgress):
        await db.mark_update(["0"], ["sub_root"], "update 0 under node sub_root", False)
    # change on sub_root is rejected, since there are changes "below" this node
    with pytest.raises(ConflictingChangeInProgress):
        await db.mark_update(["sub_root"], ["root"], "update under node sub_root", False)
    # clean up for later tests
    await db.db.truncate(db.in_progress)


@pytest.mark.asyncio
async def test_query_list(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    blas = Query.by("foo", P("identifier") == "9").traverse_out().filter("bla", P("f") == 23)
    async with await filled_graph_db.query_list(QueryModel(blas, foo_model, "reported")) as gen:
        result = [from_js(x["reported"], Bla) async for x in gen]
        assert len(result) == 10
        assert isinstance(result[0], Bla)


@pytest.mark.asyncio
async def test_query_graph(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    graph = await load_graph(filled_graph_db, foo_model)
    assert len(graph.edges) == 110
    assert len(graph.nodes.values()) == 111

    # filter data and tag result, and then traverse to the end of the graph in both directions
    around_me = Query.by("foo", P("identifier") == "9").tag("red").traverse_inout(start=0)
    graph = await filled_graph_db.query_graph(QueryModel(around_me, foo_model, "reported"))
    assert len({x for x in graph.nodes}) == 12
    assert GraphAccess.root_id(graph) == "sub_root"
    assert list(graph.successors("sub_root"))[0] == "9"
    assert set(graph.successors("9")) == {f"9_{x}" for x in range(0, 10)}
    for node_id, node in graph.nodes.data(True):
        if node_id == "9":
            assert node["metadata"]["query_tag"] == "red"
        else:
            assert "tag" not in node["metadata"]


@pytest.mark.asyncio
async def test_query_aggregate(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    agg_query = parse_query("aggregate(kind: count(identifier) as instances): is(foo)")
    async with await filled_graph_db.query_aggregation(QueryModel(agg_query, foo_model, "reported")) as gen:
        assert [x async for x in gen] == [{"group": {"kind": "foo"}, "instances": 13}]

    agg_combined_var_query = parse_query(
        'aggregate("test_{kind}_{some_int}_{does_not_exist}" as kind: count(identifier) as instances): is("foo")'
    )
    async with await filled_graph_db.query_aggregation(QueryModel(agg_combined_var_query, foo_model, "reported")) as g:
        assert [x async for x in g] == [{"group": {"kind": "test_foo_0_"}, "instances": 13}]


@pytest.mark.asyncio
async def test_query_with_merge(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    query = parse_query('(merge_with_ancestors="foo as foobar,bar"): is("bla")')
    async with await filled_graph_db.query_list(QueryModel(query, foo_model, "reported")) as cursor:
        async for bla in cursor:
            js = AccessJson(bla)
            assert "bar" in js.reported  # key exists
            assert "bar" in js.desired  # key exists
            assert "bar" in js.metadata  # key exists
            assert js.reported.bar is None  # bla is not a parent of this node
            assert js.desired.bar is None  # bla is not a parent of this node
            assert js.metadata.bar is None  # bla is not a parent of this node
            assert js.reported.foobar is not None  # foobar is merged into reported
            assert js.desired.foobar is not None  # foobar is merged into reported
            assert js.metadata.foobar is not None  # foobar is merged into reported
            # make sure the correct parent is merged (foobar(1) -> bla(1_xxx))
            assert js.reported.identifier.startswith(js.reported.foobar.identifier)
            assert js.reported.identifier.startswith(js.desired.foobar.node_id)
            assert js.reported.identifier.startswith(js.metadata.foobar.node_id)


@pytest.mark.asyncio
async def test_query_with_clause(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    async def query(q: str) -> List[Json]:
        agg_query = parse_query(q)
        async with await filled_graph_db.query_list(QueryModel(agg_query, foo_model, "reported")) as cursor:
            return [bla async for bla in cursor]

    assert len(await query("is(bla) with(any, <-- is(foo))")) == 100
    assert len(await query('is(bla) with(any, <-- is(foo) and identifier=~"1")')) == 10
    assert len(await query("is(bla) with(empty, <-- is(foo))")) == 0
    assert len(await query("is(bla) with(any, <-- is(bla))")) == 0
    assert len(await query("is(bla) with(empty, <-- is(bla))")) == 100
    assert len(await query('is(bla) with(count==1, <-- is(foo) and identifier=~"1")')) == 10
    assert len(await query('is(bla) with(count==2, <-- is(foo) and identifier=~"1")')) == 0
    assert len(await query("is(bla) with(any, <-- with(any, <-- is(foo)))")) == 100


@pytest.mark.asyncio
async def test_no_null_if_undefined(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    # imported graph should not have any desired or metadata sections
    graph = create_graph("test", 0)
    for _, node in graph.nodes(True):
        del node["desired"]
        del node["metadata"]
    await graph_db.merge_graph(graph, foo_model)
    async with await graph_db.query_list(QueryModel(parse_query("all"), foo_model)) as cursor:
        async for elem in cursor:
            assert "reported" in elem
            assert "desired" not in elem
            assert "metadata" not in elem


@pytest.mark.asyncio
async def test_get_node(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    # load sub_root as foo
    sub_root = to_foo(await filled_graph_db.get_node(foo_model, "sub_root"))
    assert sub_root is not None
    assert isinstance(sub_root, Foo)
    # load node 7 as foo
    node_7_json = await filled_graph_db.get_node(foo_model, "7")
    node_7 = to_foo(node_7_json)
    assert node_7 is not None
    assert isinstance(node_7, Foo)
    # make sure that all synthetic properties are rendered (the age should not be older than 1 second => 0s or 1s)
    assert node_7_json[Section.reported]["age"] in ["0s", "1s"]  # type: ignore
    # load node 1_2 as bla
    node_1_2 = to_bla(await filled_graph_db.get_node(foo_model, "1_2"))
    assert node_1_2 is not None
    assert isinstance(node_1_2, Bla)


@pytest.mark.asyncio
async def test_insert_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    json = await graph_db.create_node(foo_model, "some_new_id", to_json(Foo("some_new_id", "name")), "root")
    assert to_foo(json).identifier == "some_new_id"
    assert to_foo(await graph_db.get_node(foo_model, "some_new_id")).identifier == "some_new_id"


@pytest.mark.asyncio
async def test_update_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    await graph_db.create_node(foo_model, "some_other", to_json(Foo("some_other", "foo")), "root")
    json = await graph_db.update_node(foo_model, "some_other", {"name": "bla"}, "reported")
    assert to_foo(json).name == "bla"
    assert to_foo(await graph_db.get_node(foo_model, "some_other")).name == "bla"


@pytest.mark.asyncio
async def test_update_nodes(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    def expect(jsons: List[Json], path: List[str], value: JsonElement) -> None:
        for js in jsons:
            v = value_in_path(js, path)
            assert v is not None
            assert v == value

    await graph_db.wipe()
    await graph_db.create_node(foo_model, "id1", to_json(Foo("id1", "foo")), "root")
    await graph_db.create_node(foo_model, "id2", to_json(Foo("id2", "foo")), "root")
    change1 = {"desired": {"test": True}}
    result1 = [a async for a in graph_db.update_nodes(foo_model, {"id1": change1, "id2": change1})]
    assert len(result1) == 2
    expect(result1, ["desired", "test"], True)
    change2 = {"metadata": {"test": True}}
    result2 = [a async for a in graph_db.update_nodes(foo_model, {"id1": change2, "id2": change2})]
    assert len(result2) == 2
    expect(result2, ["metadata", "test"], True)
    change3 = {"desired": {"test": True}, "metadata": {"test": True}, "reported": {"name": "test"}}
    result3 = [a async for a in graph_db.update_nodes(foo_model, {"id1": change3, "id2": change3})]
    assert len(result3) == 2
    expect(result3, ["desired", "test"], True)
    expect(result3, ["metadata", "test"], True)
    expect(result3, ["reported", "name"], "test")
    change4 = {"desired": None, "metadata": None}
    result4 = [a async for a in graph_db.update_nodes(foo_model, {"id1": change4, "id2": change4})]
    assert len(result4) == 2
    assert "desired" not in result4
    assert "metadata" not in result4


@pytest.mark.asyncio
async def test_delete_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    await graph_db.create_node(foo_model, "sub_root", to_json(Foo("sub_root", "foo")), "root")
    await graph_db.create_node(foo_model, "some_other_child", to_json(Foo("some_other_child", "foo")), "sub_root")
    await graph_db.create_node(foo_model, "born_to_die", to_json(Foo("born_to_die", "foo")), "sub_root")
    await graph_db.delete_node("born_to_die")
    assert await graph_db.get_node(foo_model, "born_to_die") is None
    with pytest.raises(AttributeError) as not_allowed:
        await graph_db.delete_node("sub_root")
    assert str(not_allowed.value) == "Can not delete node, since it has 1 child(ren)!"


@pytest.mark.asyncio
async def test_events(event_graph_db: EventGraphDB, foo_model: Model, all_events: List[Message]) -> None:
    await event_graph_db.create_node(foo_model, "some_other", to_json(Foo("some_other", "foo")), "root")
    await event_graph_db.update_node(foo_model, "some_other", {"name": "bla"}, "reported")
    await event_graph_db.delete_node("some_other")
    await event_graph_db.merge_graph(create_graph("yes or no", width=1), foo_model)
    await event_graph_db.merge_graph(create_graph("maybe", width=1), foo_model, "batch1", True)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.message_type for a in all_events] == [
        "node-created",
        "node-updated",
        "node-deleted",
        "graph-merged",
        "batch-update-graph-merged",
    ]


def to_json(obj: BaseResource) -> Json:
    return {"kind": obj.kind(), **to_js(obj)}


def to_bla(json: Json) -> Bla:
    return from_js(json["reported"], Bla)


def to_foo(json: Json) -> Foo:
    return from_js(json["reported"], Foo)
