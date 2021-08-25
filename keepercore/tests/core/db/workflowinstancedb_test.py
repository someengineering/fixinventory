from typing import List

import pytest
from arango.database import StandardDatabase

from core.db import workflowinstancedb
from core.db.async_arangodb import AsyncArangoDB
from core.db.workflowinstancedb import WorkflowInstanceData, WorkflowInstanceDb
from core.event_bus import ActionDone
from core.util import utc

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
async def test_append_message(workflow_instance_db: WorkflowInstanceDb, instances: List[WorkflowInstanceData]) -> None:
    instance = instances[0]
    await workflow_instance_db.update(instance)
    first = ActionDone("first", "test", "bla", "sf")
    second = ActionDone("second", "test", "bla", "sf")
    third = ActionDone("third", "test", "bla", "sf")
    await workflow_instance_db.append_message(instance.id, first)
    await workflow_instance_db.append_message(instance.id, second)
    await workflow_instance_db.append_message(instance.id, third)
    updated: WorkflowInstanceData = await workflow_instance_db.get(instance.id)  # type: ignore
    assert len(updated.received_messages) == (len(instance.received_messages) + 3)
    assert updated.received_messages[-3:] == [first, second, third]
