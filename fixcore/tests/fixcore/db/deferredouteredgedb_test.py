from datetime import datetime, timezone

import pytest
from pytest import fixture
from typing import List

from fixcore.db.deferredouteredgedb import DeferredOuterEdges, DeferredOuterEdgeDb
from fixcore.ids import TaskId, GraphName, NodeId
from fixcore.model.graph_access import DeferredEdge, ByNodeId, EdgeTypes


@fixture
def instances() -> List[DeferredOuterEdges]:
    return [
        DeferredOuterEdges(
            id="1",
            change_id="c1",
            task_id=TaskId("t1"),
            created_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
            graph=GraphName("test"),
            edges=[DeferredEdge(ByNodeId(NodeId("e1")), ByNodeId(NodeId("e2")), EdgeTypes.default)],
        ),
        DeferredOuterEdges(
            id="2",
            change_id="c1",
            task_id=TaskId("t1"),
            created_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
            graph=GraphName("test"),
            edges=[DeferredEdge(ByNodeId(NodeId("e2")), ByNodeId(NodeId("e3")), EdgeTypes.default)],
        ),
        DeferredOuterEdges(
            id="3",
            change_id="c2",
            task_id=TaskId("t2"),
            created_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
            graph=GraphName("test"),
            edges=[DeferredEdge(ByNodeId(NodeId("e2")), ByNodeId(NodeId("e3")), EdgeTypes.default)],
        ),
    ]


@pytest.mark.asyncio
async def test_all_by_task_id(
    pending_deferred_edge_db: DeferredOuterEdgeDb, instances: List[DeferredOuterEdges]
) -> None:
    await pending_deferred_edge_db.update_many(instances)
    assert len(await pending_deferred_edge_db.all_for_task(TaskId("t1"))) == 2
    assert len(await pending_deferred_edge_db.all_for_task(TaskId("t2"))) == 1


@pytest.mark.asyncio
async def test_remove_by_task_id(
    pending_deferred_edge_db: DeferredOuterEdgeDb, instances: List[DeferredOuterEdges]
) -> None:
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
