import asyncio
from typing import List

import pytest
from arango.database import StandardDatabase

from resotocore.analytics import InMemoryEventSender
from resotocore.db import inspectiondb
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EventEntityDb
from resotocore.db.inspectiondb import InspectionCheckEntityDb, EventInspectionCheckEntityDb
from resotocore.inspect import InspectionCheck

# noinspection PyUnresolvedReferences
from tests.resotocore.analytics import event_sender

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import test_db, local_client, system_db


@pytest.fixture
async def inspection_db(test_db: StandardDatabase) -> InspectionCheckEntityDb:
    async_db = AsyncArangoDB(test_db)
    inspection_db = inspectiondb.inspection_check_entity_db(async_db, "inspections")
    await inspection_db.create_update_schema()
    await inspection_db.wipe()
    return inspection_db


@pytest.fixture
def event_db(inspection_db: InspectionCheckEntityDb, event_sender: InMemoryEventSender) -> EventInspectionCheckEntityDb:
    return EventEntityDb(inspection_db, event_sender, "inspection")


@pytest.fixture
def inspections() -> List[InspectionCheck]:
    return InspectionCheck.from_files()


def inspection_id(inspection: InspectionCheck) -> str:
    return inspection.id


@pytest.mark.asyncio
async def test_load(inspection_db: InspectionCheckEntityDb, inspections: List[InspectionCheck]) -> None:
    await inspection_db.update_many(inspections)
    loaded = [sub async for sub in inspection_db.all()]
    assert inspections.sort(key=inspection_id) == loaded.sort(key=inspection_id)


@pytest.mark.asyncio
async def test_update(inspection_db: InspectionCheckEntityDb, inspections: List[InspectionCheck]) -> None:
    # multiple updates should work as expected
    await inspection_db.update_many(inspections)
    await inspection_db.update_many(inspections)
    await inspection_db.update_many(inspections)
    loaded = [sub async for sub in inspection_db.all()]
    assert inspections.sort(key=inspection_id) == loaded.sort(key=inspection_id)


@pytest.mark.asyncio
async def test_delete(inspection_db: InspectionCheckEntityDb, inspections: List[InspectionCheck]) -> None:
    await inspection_db.update_many(inspections)
    remaining = list(inspections)
    for _ in inspections:
        sub = remaining.pop()
        await inspection_db.delete_value(sub)
        loaded = [sub async for sub in inspection_db.all()]
        assert remaining.sort(key=inspection_id) == loaded.sort(key=inspection_id)
    assert len([sub async for sub in inspection_db.all()]) == 0


@pytest.mark.asyncio
async def test_events(
    event_db: EventInspectionCheckEntityDb, inspections: List[InspectionCheck], event_sender: InMemoryEventSender
) -> None:
    # 2 times update
    await event_db.update_many(inspections)
    await event_db.update_many(inspections)
    # 2 times delete
    for sub in inspections:
        await event_db.delete_value(sub)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.kind for a in event_sender.events[0:10]] == ["inspection-updated-many"] * 2 + ["inspection-deleted"] * 8
