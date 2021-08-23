import asyncio
import string
from abc import ABC
from datetime import date, datetime, timezone
from random import SystemRandom
from typing import List, Optional

import pytest
from arango import ArangoClient
from arango.database import StandardDatabase
from arango.typings import Json
from networkx import DiGraph, MultiDiGraph

from core.db.async_arangodb import AsyncArangoDB
from core.db.graphdb import ArangoGraphDB, GraphDB, EventGraphDB
from core.error import ConflictingChangeInProgress, NoSuchBatchError, InvalidBatchUpdate
from core.event_bus import EventBus, Message
from core.model.graph_access import GraphAccess, EdgeType
from core.model.model import Model, Complex, Property
from core.model.typed_model import to_js, from_js
from core.query.model import Query, P, Navigation
from core.query.query_parser import parse_query

# noinspection PyUnresolvedReferences
from core.db.model import QueryModel, GraphUpdate

# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus, all_events


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
        now_is: datetime = datetime.now(tz=timezone.utc),
    ) -> None:
        super().__init__(identifier)
        self.name = name
        self.some_int = some_int
        self.some_string = some_string
        self.now_is = now_is

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


def create_graph(bla_text: str, with_merge: bool = False, width: int = 10) -> MultiDiGraph:
    graph = MultiDiGraph()

    def add_edge(from_node: str, to_node: str, edge_type: str = EdgeType.dependency) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    graph.add_node("sub_root", data=to_json(Foo("sub_root")))

    # root -> collector -> sub_root -> **rest
    if with_merge:
        graph.add_node("root", data=to_json(Foo("root")))
        graph.add_node("collector", data=to_json(Foo("root")), merge=True)
        add_edge("root", "collector")
        add_edge("collector", "sub_root")

    for o in range(0, width):
        oid = str(o)
        graph.add_node(oid, data=to_json(Foo(oid)))
        add_edge("sub_root", oid)
        for i in range(0, width):
            iid = f"{o}_{i}"
            graph.add_node(iid, data=to_json(Bla(iid, name=bla_text)))
            add_edge(oid, iid)
    return graph


def create_multi_collector_graph(width: int = 3) -> MultiDiGraph:
    graph = MultiDiGraph()

    def add_edge(from_node: str, to_node: str, edge_type: str = EdgeType.dependency) -> None:
        key = GraphAccess.edge_key(from_node, to_node, edge_type)
        graph.add_edge(from_node, to_node, key, edge_type=edge_type)

    def add_node(node_id: str, merge: bool = False) -> str:
        graph.add_node(node_id, data=to_json(Foo(node_id)), merge=merge)
        return node_id

    root = add_node("root")
    for collector_num in range(0, 2):
        collector = add_node(f"collector_{collector_num}")
        add_edge(root, collector)
        for account_num in range(0, 2):
            aid = f"{collector_num}:{account_num}"
            account = add_node(f"account_{aid}", merge=True)
            add_edge(collector, account)
            add_edge(account, collector, EdgeType.delete)
            for region_num in range(0, 2):
                rid = f"{aid}:{region_num}"
                region = add_node(f"region_{rid}")
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
def foo_model() -> Model:
    base = Complex(
        "base",
        [],
        [
            Property("identifier", "string", required=True),
            Property("kind", "string", required=True),
        ],
    )
    foo = Complex(
        "foo",
        ["base"],
        [
            Property("name", "string"),
            Property("some_int", "int32"),
            Property("some_string", "string"),
            Property("now_is", "datetime"),
        ],
    )
    bla = Complex(
        "bla",
        ["base"],
        [
            Property("name", "string"),
            Property("now", "date"),
            Property("f", "int32"),
            Property("g", "int32[]"),
        ],
    )
    return Model.from_kinds([base, foo, bla])


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
    graph_db = ArangoGraphDB(async_db, "ns")
    await graph_db.create_update_schema()
    await async_db.truncate(graph_db.in_progress)
    return graph_db


@pytest.fixture
async def filled_graph_db(graph_db: ArangoGraphDB, foo_model: Model) -> ArangoGraphDB:
    await graph_db.wipe()
    await graph_db.update_sub_graph(foo_model, create_graph("yes or no"), "root")
    return graph_db


@pytest.fixture
async def event_graph_db(filled_graph_db: ArangoGraphDB, event_bus: EventBus) -> EventGraphDB:
    return EventGraphDB(filled_graph_db, event_bus)


async def load_graph(db: GraphDB, model: Model, base_id: str = "sub_root") -> DiGraph:
    blas = Query.by("foo", P("identifier") == base_id).traverse_out(0, Navigation.Max)
    return await db.query_graph(QueryModel(blas, model, "reported"))


@pytest.mark.asyncio
async def test_update_sub_graph_batched(graph_db: ArangoGraphDB, foo_model: Model, test_db: StandardDatabase) -> None:
    md = foo_model
    await graph_db.wipe()
    batch_id = "".join(SystemRandom().choice(string.ascii_letters) for _ in range(12))

    # empty database: all changes are written to a temp table
    assert await graph_db.update_sub_graph(md, create_graph("yes or no"), "root", batch_id) == GraphUpdate(
        111, 0, 0, 111, 0, 0
    )
    assert len((await load_graph(graph_db, md)).nodes) == 0
    # not allowed to commit an unknown batch
    with pytest.raises(NoSuchBatchError):
        await graph_db.commit_batch_update("does_not_exist")
    # commit the batch and see the changes reflected in the database
    await graph_db.commit_batch_update(batch_id)
    assert len((await load_graph(graph_db, md)).nodes) == 111
    # ensure that all temp tables are removed
    assert len(list(filter(lambda c: c["name"].startswith("temp"), test_db.collections()))) == 0
    # create a new batch that gets aborted: make sure all temp tables are gone
    batch_id = "will_be_aborted"
    await graph_db.update_sub_graph(md, create_graph("yes or no"), "root", batch_id)
    await graph_db.abort_batch_update(batch_id)
    assert len(list(filter(lambda c: c["name"].startswith("temp"), test_db.collections()))) == 0


@pytest.mark.asyncio
async def test_update_sub_graph(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    md = foo_model
    await graph_db.wipe()

    # empty database: all nodes and all edges have to be inserted
    assert await graph_db.update_sub_graph(md, create_graph("yes or no"), "root") == GraphUpdate(111, 0, 0, 111, 0, 0)
    # exactly the same graph is updated: expect no changes
    assert await graph_db.update_sub_graph(md, create_graph("yes or no"), "root") == GraphUpdate(0, 0, 0, 0, 0, 0)
    # all bla entries have different content: expect 100 node updates, but no inserts or deletions
    assert await graph_db.update_sub_graph(md, create_graph("maybe"), "root") == GraphUpdate(0, 100, 0, 0, 0, 0)
    # the width of the graph is reduced: expect nodes and edges to be removed
    assert await graph_db.update_sub_graph(md, create_graph("maybe", width=5), "root") == GraphUpdate(
        0, 0, 80, 0, 0, 80
    )
    # going back to the previous graph: the same amount of nodes and edges is inserted
    assert await graph_db.update_sub_graph(md, create_graph("maybe"), "root") == GraphUpdate(80, 0, 0, 80, 0, 0)
    # updating with the same data again, does not perform any changes
    assert await graph_db.update_sub_graph(md, create_graph("maybe"), "root") == GraphUpdate(0, 0, 0, 0, 0, 0)


@pytest.mark.asyncio
async def test_merge_graph(graph_db: ArangoGraphDB) -> None:
    await graph_db.wipe()

    def create(txt: str, width: int = 10) -> MultiDiGraph:
        return create_graph(txt, with_merge=True, width=width)

    # empty database: all nodes and all edges have to be inserted, the root node is updated and the link to root added
    assert await graph_db.update_merge_graphs(create("yes or no")) == GraphUpdate(112, 1, 0, 112, 0, 0)
    # exactly the same graph is updated: expect no changes
    assert await graph_db.update_merge_graphs(create("yes or no")) == GraphUpdate(0, 0, 0, 0, 0, 0)
    # all bla entries have different content: expect 100 node updates, but no inserts or deletions
    assert await graph_db.update_merge_graphs(create("maybe")) == GraphUpdate(0, 100, 0, 0, 0, 0)
    # the width of the graph is reduced: expect nodes and edges to be removed
    assert await graph_db.update_merge_graphs(create("maybe", width=5)) == GraphUpdate(0, 0, 80, 0, 0, 80)
    # going back to the previous graph: the same amount of nodes and edges is inserted
    assert await graph_db.update_merge_graphs(create("maybe")) == GraphUpdate(80, 0, 0, 80, 0, 0)
    # updating with the same data again, does not perform any changes
    assert await graph_db.update_merge_graphs(create("maybe")) == GraphUpdate(0, 0, 0, 0, 0, 0)


@pytest.mark.asyncio
async def test_merge_multi_graph(graph_db: ArangoGraphDB) -> None:
    await graph_db.wipe()

    graph = create_multi_collector_graph()
    # nodes:
    # 2 collectors + 4 accounts + 8 regions + 24 parents + 72 children => 110 nodes to insert
    # 1 root which changes => 1 node to update
    # edges:
    # 110 dependency, 108 delete connections (missing: collector -> root) => 218 edge inserts
    assert await graph_db.update_merge_graphs(graph) == GraphUpdate(110, 1, 0, 218, 0, 0)
    # doing the same thing again should do nothing
    assert await graph_db.update_merge_graphs(graph) == GraphUpdate(0, 0, 0, 0, 0, 0)


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
    gen = filled_graph_db.query_list(QueryModel(blas, foo_model, "reported"))
    result = [from_js(x, Bla) async for x in gen]
    assert len(result) == 10
    assert isinstance(result[0], Bla)


@pytest.mark.asyncio
async def test_query_graph(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    graph = await load_graph(filled_graph_db, foo_model)
    assert len(graph.edges) == 110
    assert len(graph.nodes.values()) == 111


@pytest.mark.asyncio
async def test_query_aggregate(filled_graph_db: ArangoGraphDB, foo_model: Model) -> None:
    agg_query = parse_query('aggregate(kind: count(identifier) as instances): isinstance("foo")')
    gen = filled_graph_db.query_aggregation(QueryModel(agg_query, foo_model, "reported"))
    assert [x async for x in gen] == [{"kind": "foo", "instances": 11}]


@pytest.mark.asyncio
async def test_get_node(filled_graph_db: ArangoGraphDB) -> None:
    root = from_js(await filled_graph_db.get_node("sub_root", "reported"), Foo)
    assert root is not None
    assert isinstance(root, Foo)
    node_7 = from_js(await filled_graph_db.get_node("7", "reported"), Foo)
    assert node_7 is not None
    assert isinstance(node_7, Foo)
    node_1_2 = from_js(await filled_graph_db.get_node("1_2", "reported"), Bla)
    assert node_1_2 is not None
    assert isinstance(node_1_2, Bla)


@pytest.mark.asyncio
async def test_insert_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    json = await graph_db.create_node(foo_model, "some_new_id", to_json(Foo("some_new_id", "name")), "root")
    assert to_foo(json).identifier == "some_new_id"
    assert to_foo(await graph_db.get_node("some_new_id", "reported")).identifier == "some_new_id"


@pytest.mark.asyncio
async def test_update_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    await graph_db.create_node(foo_model, "some_other", to_json(Foo("some_other", "foo")), "root")
    json = await graph_db.update_node(foo_model, "reported", "reported", "some_other", {"name": "bla"})
    assert to_foo(json).name == "bla"
    assert to_foo(await graph_db.get_node("some_other", "reported")).name == "bla"


@pytest.mark.asyncio
async def test_delete_node(graph_db: ArangoGraphDB, foo_model: Model) -> None:
    await graph_db.wipe()
    await graph_db.create_node(foo_model, "sub_root", to_json(Foo("sub_root", "foo")), "root")
    await graph_db.create_node(foo_model, "some_other_child", to_json(Foo("some_other_child", "foo")), "sub_root")
    await graph_db.create_node(foo_model, "born_to_die", to_json(Foo("born_to_die", "foo")), "sub_root")
    await graph_db.delete_node("born_to_die")
    assert await graph_db.get_node("born_to_die", "reported") is None
    with pytest.raises(AttributeError) as not_allowed:
        await graph_db.delete_node("sub_root")
    assert str(not_allowed.value) == "Can not delete node, since it has 1 child(ren)!"


@pytest.mark.asyncio
async def test_events(event_graph_db: EventGraphDB, foo_model: Model, all_events: List[Message]) -> None:
    await event_graph_db.create_node(foo_model, "some_other", to_json(Foo("some_other", "foo")), "root")
    await event_graph_db.update_node(foo_model, "reported", "reported", "some_other", {"name": "bla"})
    await event_graph_db.delete_node("some_other")
    await event_graph_db.update_sub_graph(foo_model, create_graph("yes or no"), "root")
    await event_graph_db.update_sub_graph(foo_model, create_graph("yes or no"), "root", "batch1")
    await event_graph_db.commit_batch_update("batch1")
    await event_graph_db.update_sub_graph(foo_model, create_graph("yes or no"), "root", "batch2")
    await event_graph_db.commit_batch_update("batch2")
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.message_type for a in all_events] == [
        "node-created",
        "node-updated",
        "node-deleted",
        "subgraph-updated",
        "batch-update-subgraph-added",
        "batch-update-committed",
        "batch-update-subgraph-added",
        "batch-update-committed",
    ]


def to_json(obj: BaseResource) -> Json:
    return to_js(obj) | {"kind": obj.kind()}


def to_foo(json: Json) -> Foo:
    return from_js(json, Foo)  # type: ignore
