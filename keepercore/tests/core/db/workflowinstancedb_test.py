from typing import List, Tuple

import pytest
from arango.database import StandardDatabase

from core.db import workflowinstancedb
from core.db.async_arangodb import AsyncArangoDB
from core.db.workflowinstancedb import WorkflowInstanceData, WorkflowInstanceDb
from core.event_bus import ActionDone
from core.util import utc
from core.workflow.model import Subscriber

from core.workflow.workflows import WorkflowInstance

# noinspection PyUnresolvedReferences
from tests.core.workflow.workflows_test import workflow_instance

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import test_db

# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus, all_events


@pytest.fixture
async def workflow_instance_db(test_db: StandardDatabase) -> WorkflowInstanceDb:
    async_db = AsyncArangoDB(test_db)
    workflow_instance_db = workflowinstancedb.workflow_instance_db(async_db, "workflow_instance")
    await workflow_instance_db.create_update_schema()
    await workflow_instance_db.wipe()
    return workflow_instance_db


@pytest.fixture
def instances() -> List[WorkflowInstanceData]:
    messages = [ActionDone(str(a), "test", "bla", "sf") for a in range(0, 10)]
    state_data = {"test": 1}
    return [
        WorkflowInstanceData(str(a), str(a), "workflow_123", messages, "start", state_data, utc()) for a in range(0, 10)
    ]


@pytest.mark.asyncio
async def test_load(workflow_instance_db: WorkflowInstanceDb, instances: List[WorkflowInstanceData]) -> None:
    await workflow_instance_db.update_many(instances)
    loaded = [sub async for sub in workflow_instance_db.all()]
    assert instances.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_update(workflow_instance_db: WorkflowInstanceDb, instances: List[WorkflowInstanceData]) -> None:
    # multiple updates should work as expected
    await workflow_instance_db.update_many(instances)
    await workflow_instance_db.update_many(instances)
    await workflow_instance_db.update_many(instances)
    loaded = [sub async for sub in workflow_instance_db.all()]
    assert instances.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_delete(workflow_instance_db: WorkflowInstanceDb, instances: List[WorkflowInstanceData]) -> None:
    await workflow_instance_db.update_many(instances)
    remaining = list(instances)
    for _ in instances:
        sub = remaining.pop()
        await workflow_instance_db.delete(sub)
        loaded = [sub async for sub in workflow_instance_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in workflow_instance_db.all()]) == 0


@pytest.mark.asyncio
async def test_update_state(
    workflow_instance_db: WorkflowInstanceDb,
    workflow_instance: Tuple[WorkflowInstance, Subscriber, Subscriber, dict[str, List[Subscriber]]],
) -> None:
    wi, _, _, _ = workflow_instance
    first = ActionDone("start_collect", "test", "bla", "sf")
    second = ActionDone("collect", "test", "bla", "sf")
    third = ActionDone("collect_done", "test", "bla", "sf")

    async def assert_state(current: str, message_count: int) -> WorkflowInstanceData:
        state = await workflow_instance_db.get(wi.id)
        assert state.current_state_name == current
        assert len(state.received_messages) == message_count
        return state

    await workflow_instance_db.insert(wi)
    await assert_state(wi.current_state.name, 6)

    wi.machine.set_state("start")
    await workflow_instance_db.update_state(wi, first)
    await assert_state("start", 7)

    wi.machine.set_state("collect")
    await workflow_instance_db.update_state(wi, second)
    await assert_state("collect", 8)

    wi.machine.set_state("done")
    await workflow_instance_db.update_state(wi, third)
    last = await assert_state("done", 9)

    assert last.received_messages[-3:] == [first, second, third]
