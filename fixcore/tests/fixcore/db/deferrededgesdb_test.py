from datetime import datetime, timezone

import pytest
from pytest import fixture
from typing import List

from fixcore.db.deferrededgesdb import DeferredEdges, DeferredEdgesDb
from fixcore.ids import TaskId, GraphName, NodeId
from fixcore.model.graph_access import DeferredEdge, ByNodeId, EdgeTypes


@fixture
def instances() -> List[DeferredEdges]:
    reported = dict(foo="bla", test=[1, 2, 3])
    hash_str = "1234567890"
    return [
        DeferredEdges(
            id="1",
            change_id="c1",
            task_id=TaskId("t1"),
            created_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
            graph=GraphName("test"),
            edges=[DeferredEdge(ByNodeId(NodeId("e1")), ByNodeId(NodeId("e2")), EdgeTypes.default, reported, hash_str)],
        ),
        DeferredEdges(
            id="2",
            change_id="c1",
            task_id=TaskId("t1"),
            created_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
            graph=GraphName("test"),
            edges=[DeferredEdge(ByNodeId(NodeId("e2")), ByNodeId(NodeId("e3")), EdgeTypes.default, reported, hash_str)],
        ),
        DeferredEdges(
            id="3",
            change_id="c2",
            task_id=TaskId("t2"),
            created_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
            graph=GraphName("test"),
            edges=[DeferredEdge(ByNodeId(NodeId("e2")), ByNodeId(NodeId("e3")), EdgeTypes.default, reported, hash_str)],
        ),
    ]


@pytest.mark.asyncio
async def test_all_by_task_id(pending_deferred_edge_db: DeferredEdgesDb, instances: List[DeferredEdges]) -> None:
    await pending_deferred_edge_db.update_many(instances)
    assert len(await pending_deferred_edge_db.all_for_task(TaskId("t1"))) == 2
    t2 = await pending_deferred_edge_db.all_for_task(TaskId("t2"))
    assert len(t2) == 1
    assert t2[0] == instances[2]


@pytest.mark.asyncio
async def test_remove_by_task_id(pending_deferred_edge_db: DeferredEdgesDb, instances: List[DeferredEdges]) -> None:
    await pending_deferred_edge_db.wipe()
    # insert all
    await pending_deferred_edge_db.update_many(instances)
    # delete t1
    await pending_deferred_edge_db.delete_for_task(TaskId("t1"))
    assert len(await pending_deferred_edge_db.all_for_task(TaskId("t1"))) == 0
    assert len(await pending_deferred_edge_db.all_for_task(TaskId("t2"))) == 1
    # delete t2
    await pending_deferred_edge_db.delete_for_task(TaskId("t2"))
    assert len([n async for n in pending_deferred_edge_db.all()]) == 0
