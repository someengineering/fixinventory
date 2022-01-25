import asyncio
import pytest
from arango.database import StandardDatabase
from typing import List

from core.analytics import AnalyticsEventSender, InMemoryEventSender
from core.db import templatedb
from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EventEntityDb
from core.db.templatedb import TemplateEntityDb, EventTemplateEntityDb
from core.query.model import Template

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import test_db, local_client, system_db

# noinspection PyUnresolvedReferences
from tests.core.analytics import event_sender


@pytest.fixture
async def template_db(test_db: StandardDatabase) -> TemplateEntityDb:
    async_db = AsyncArangoDB(test_db)
    template_db = templatedb.template_entity_db(async_db, "templates")
    await template_db.create_update_schema()
    await template_db.wipe()
    return template_db


@pytest.fixture
def event_db(template_db: TemplateEntityDb, event_sender: AnalyticsEventSender) -> EventTemplateEntityDb:
    return EventEntityDb(template_db, event_sender, "templates")


@pytest.fixture
def templates() -> List[Template]:
    return [Template(f"tpl_{a}", "is({{a}})") for a in range(0, 10)]


@pytest.mark.asyncio
async def test_load(template_db: TemplateEntityDb, templates: List[Template]) -> None:
    await template_db.update_many(templates)
    loaded = [sub async for sub in template_db.all()]
    assert templates.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_update(template_db: TemplateEntityDb, templates: List[Template]) -> None:
    # multiple updates should work as expected
    await template_db.update_many(templates)
    await template_db.update_many(templates)
    await template_db.update_many(templates)
    loaded = [sub async for sub in template_db.all()]
    assert templates.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_delete(template_db: TemplateEntityDb, templates: List[Template]) -> None:
    await template_db.update_many(templates)
    remaining = list(templates)
    for _ in templates:
        sub = remaining.pop()
        await template_db.delete(sub)
        loaded = [sub async for sub in template_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in template_db.all()]) == 0


@pytest.mark.asyncio
async def test_events(
    event_db: EventTemplateEntityDb, templates: List[Template], event_sender: InMemoryEventSender
) -> None:
    # 2 times update
    await event_db.update_many(templates)
    await event_db.update_many(templates)
    # 6 times delete
    for sub in templates:
        await event_db.delete(sub)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.kind for a in event_sender.events] == ["templates-updated-many"] * 2 + ["templates-deleted"] * 10
