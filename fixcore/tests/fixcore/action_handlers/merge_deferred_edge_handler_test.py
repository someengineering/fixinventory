import asyncio
from datetime import timedelta
from typing import List

import pytest

from fixcore.action_handlers.merge_deferred_edge_handler import MergeDeferredEdgesHandler, merge_deferred_edges
from fixcore.db.db_access import DbAccess
from fixcore.db.deferrededgesdb import DeferredEdges
from fixcore.db.graphdb import ArangoGraphDB
from fixcore.db.model import QueryModel
from fixcore.ids import TaskId, NodeId
from fixcore.message_bus import Action, MessageBus
from fixcore.model.graph_access import ByNodeId, BySearchCriteria, DeferredEdge, EdgeTypes
from fixcore.model.model import Model
from fixcore.model.typed_model import to_js
from fixcore.query.query_parser import parse_query
from fixcore.task.subscribers import SubscriptionHandler
from fixcore.types import Json
from fixcore.util import utc
from tests.fixcore.db.graphdb_test import Foo, Bla, BaseResource


@pytest.mark.asyncio
async def test_handler_invocation(
    merge_handler: MergeDeferredEdgesHandler,
    subscription_handler: SubscriptionHandler,
    message_bus: MessageBus,
) -> None:
    merge_called: asyncio.Future[List[TaskId]] = asyncio.get_event_loop().create_future()

    def mocked_merge(task_ids: List[TaskId]) -> None:
        merge_called.set_result(task_ids)

    # monkey patching the merge_deferred_edges method
    # use setattr here, since assignment does not work in mypy https://github.com/python/mypy/issues/2427
    setattr(merge_handler, "merge_deferred_edges", mocked_merge)

    subscribers = await subscription_handler.list_subscriber_for(merge_deferred_edges)

    assert subscribers[0].id == "fixcore"

    task_id = TaskId("test_task_1")

    await message_bus.emit(Action(merge_deferred_edges, task_id, merge_deferred_edges))

    assert await merge_called == [task_id]


@pytest.mark.asyncio
async def test_merge_deferred_edges(
    merge_handler: MergeDeferredEdgesHandler, graph_db: ArangoGraphDB, foo_model: Model, db_access: DbAccess
) -> None:
    now = utc()

    id1 = NodeId("id1")
    id2 = NodeId("id2")
    id3 = NodeId("id3")

    await graph_db.wipe()
    await graph_db.create_node(foo_model, id1, to_json(Foo("id1", "foo")), NodeId("root"))
    await graph_db.create_node(foo_model, id3, to_json(Foo("id3", "foo")), NodeId("root"))
    await graph_db.create_node(foo_model, id2, to_json(Bla("id2", "bla")), NodeId("root"))
    await db_access.deferred_outer_edge_db.create_update_schema()

    e1 = DeferredEdge(ByNodeId(id1), BySearchCriteria("is(bla)"), EdgeTypes.default)
    await db_access.deferred_outer_edge_db.update(
        DeferredEdges("t0", "c0", TaskId("task123"), now, graph_db.name, [e1])
    )
    await merge_handler.merge_deferred_edges([TaskId("task123")])

    graph = await graph_db.search_graph(QueryModel(parse_query("is(graph_root) -default[0:]->"), foo_model))
    assert graph.has_edge("id1", "id2")
    assert graph.has_edge("root", "id3")

    # deletion test

    new_now = now + timedelta(minutes=10)

    e2 = DeferredEdge(ByNodeId(id2), ByNodeId(id1), EdgeTypes.default)
    await db_access.deferred_outer_edge_db.update(
        DeferredEdges("t1", "c1", TaskId("task456"), new_now, graph_db.name, [e2])
    )
    await merge_handler.merge_deferred_edges([TaskId("task456")])

    graph = await graph_db.search_graph(QueryModel(parse_query("is(graph_root) -default[0:]->"), foo_model))
    assert not graph.has_edge("id1", "id2")
    assert graph.has_edge("id2", "id1")
    assert graph.has_edge("root", "id3")

    # it is possible to overwrite the same edge with a new value

    new_now_2 = now + timedelta(minutes=10)

    await db_access.deferred_outer_edge_db.update(
        DeferredEdges("t2", "c4", TaskId("task789"), new_now_2, graph_db.name, [e2])
    )
    r = await merge_handler.merge_deferred_edges([TaskId("task789")])
    assert r.processed == 1
    # here we also implicitly test that the timestamp was updated, because otherwise the edge
    # would have an old timestamp and would be deleted
    assert r.updated == 1
    assert r.deleted == 0
    graph = await graph_db.search_graph(QueryModel(parse_query("is(graph_root) -default[0:]->"), foo_model))
    assert not graph.has_edge("id1", "id2")
    assert graph.has_edge("id2", "id1")
    assert graph.has_edge("root", "id3")


def to_json(obj: BaseResource) -> Json:
    return {"kind": obj.kind(), **to_js(obj)}
