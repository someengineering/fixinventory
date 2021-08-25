import asyncio
from typing import List

import pytest
from arango.database import StandardDatabase

from core.db import workflowinstancedb
from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EventEntityDb
from core.db.workflowinstancedb import WorkflowInstanceDb, EventWorkflowInstanceDb, WorkflowInstanceData
from core.event_bus import EventBus, Message, ActionDone
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
def event_db(workflow_instance_db: WorkflowInstanceDb, event_bus: EventBus) -> EventWorkflowInstanceDb:
    return EventEntityDb(workflow_instance_db, event_bus, "workflow-instance")


@pytest.fixture
def instances() -> List[WorkflowInstanceData]:
    messages = [ActionDone(str(a), "test", "bla", "sf") for a in range(0, 10)]
    subscriber = {str(a): ["a", "b", str(a)] for a in range(0, 10)}
    return [WorkflowInstanceData(str(a), str(a), "workflow_123", messages, subscriber, utc()) for a in range(0, 10)]


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
async def test_events(
    event_db: EventWorkflowInstanceDb, instances: List[WorkflowInstanceData], all_events: List[Message]
) -> None:
    # 2 times update
    await event_db.update_many(instances)
    await event_db.update_many(instances)
    # 6 times delete
    for sub in instances:
        await event_db.delete(sub)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.message_type for a in all_events] == ["workflow-instance-updated-many"] * 2 + [
        "workflow-instance-deleted"
    ] * 10
