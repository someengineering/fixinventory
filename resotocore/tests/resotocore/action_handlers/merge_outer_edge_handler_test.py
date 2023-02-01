import asyncio
from datetime import timedelta

import pytest

from resotocore.action_handlers.merge_outer_edge_handler import MergeOuterEdgesHandler
from resotocore.db.db_access import DbAccess
from resotocore.db.deferred_edge_db import PendingDeferredEdges
from resotocore.db.graphdb import ArangoGraphDB
from resotocore.db.model import QueryModel
from resotocore.ids import TaskId, NodeId
from resotocore.message_bus import Action, MessageBus
from resotocore.model.graph_access import ByNodeId, BySearchCriteria, DeferredEdge, EdgeTypes
from resotocore.model.model import Model
from resotocore.model.typed_model import to_js
from resotocore.query.query_parser import parse_query
from resotocore.task.subscribers import SubscriptionHandler
from resotocore.types import Json
from resotocore.util import utc
from tests.resotocore.db.graphdb_test import Foo, Bla, BaseResource

merge_outer_edges = "merge_outer_edges"


@pytest.mark.asyncio
async def test_handler_invocation(
    merge_handler: MergeOuterEdgesHandler,
    subscription_handler: SubscriptionHandler,
    message_bus: MessageBus,
) -> None:
    merge_called: asyncio.Future[TaskId] = asyncio.get_event_loop().create_future()

    def mocked_merge(task_id: TaskId) -> None:
        merge_called.set_result(task_id)

    # monkey patching the merge_outer_edges method
    # use setattr here, since assignment does not work in mypy https://github.com/python/mypy/issues/2427
    setattr(merge_handler, "merge_outer_edges", mocked_merge)

    subscribers = await subscription_handler.list_subscriber_for(merge_outer_edges)

    assert subscribers[0].id == "resotocore"

    task_id = TaskId("test_task_1")

    await message_bus.emit(Action(merge_outer_edges, task_id, merge_outer_edges))

    assert await merge_called == task_id


@pytest.mark.asyncio
async def test_merge_outer_edges(
    merge_handler: MergeOuterEdgesHandler, graph_db: ArangoGraphDB, foo_model: Model, db_access: DbAccess
) -> None:
    now = utc()

    id1 = NodeId("id1")
    id2 = NodeId("id2")
    id3 = NodeId("id3")

    await graph_db.wipe()
    await graph_db.create_node(foo_model, id1, to_json(Foo("id1", "foo")), NodeId("root"))
    await graph_db.create_node(foo_model, id3, to_json(Foo("id3", "foo")), NodeId("root"))
    await graph_db.create_node(foo_model, id2, to_json(Bla("id2", "bla")), NodeId("root"))
    await db_access.pending_deferred_edge_db.create_update_schema()

    await db_access.pending_deferred_edge_db.update(
        PendingDeferredEdges(
            TaskId("task123"),
            now,
            graph_db.name,
            [
                DeferredEdge(ByNodeId(id1), BySearchCriteria("is(bla)"), EdgeTypes.default),
            ],
        )
    )
    await merge_handler.merge_outer_edges(TaskId("task123"))

    graph = await graph_db.search_graph(QueryModel(parse_query("is(graph_root) -default[0:]->"), foo_model))
    assert graph.has_edge("id1", "id2")
    assert graph.has_edge("root", "id3")

    # deletion test

    new_now = now + timedelta(minutes=10)

    await db_access.pending_deferred_edge_db.update(
        PendingDeferredEdges(
            TaskId("task456"),
            new_now,
            graph_db.name,
            [
                DeferredEdge(ByNodeId(id2), ByNodeId(id1), EdgeTypes.default),
            ],
        )
    )
    await merge_handler.merge_outer_edges(TaskId("task456"))

    graph = await graph_db.search_graph(QueryModel(parse_query("is(graph_root) -default[0:]->"), foo_model))
    assert not graph.has_edge("id1", "id2")
    assert graph.has_edge("id2", "id1")
    assert graph.has_edge("root", "id3")

    # it is possible to overwrite the same edge with a new value

    new_now_2 = now + timedelta(minutes=10)

    await db_access.pending_deferred_edge_db.update(
        PendingDeferredEdges(
            TaskId("task789"),
            new_now_2,
            graph_db.name,
            [
                DeferredEdge(ByNodeId(id2), ByNodeId(id1), EdgeTypes.default),
            ],
        )
    )
    updated, deleted = await merge_handler.merge_outer_edges(TaskId("task789"))
    # here we also implicitly test that the timestamp was updated, because otherwise the edge
    # would have an old timestamp and would be deleted
    assert updated == 1
    assert deleted == 0
    graph = await graph_db.search_graph(QueryModel(parse_query("is(graph_root) -default[0:]->"), foo_model))
    assert not graph.has_edge("id1", "id2")
    assert graph.has_edge("id2", "id1")
    assert graph.has_edge("root", "id3")


def to_json(obj: BaseResource) -> Json:
    return {"kind": obj.kind(), **to_js(obj)}
