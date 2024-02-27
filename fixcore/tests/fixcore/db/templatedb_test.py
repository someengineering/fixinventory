import asyncio
from typing import List

import pytest
from arango.database import StandardDatabase

from fixcore.analytics import AnalyticsEventSender, InMemoryEventSender
from fixcore.db import templatedb
from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.db.entitydb import EventEntityDb
from fixcore.db.templatedb import TemplateEntityDb, EventTemplateEntityDb
from fixcore.query.model import Template


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
        await template_db.delete_value(sub)
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
        await event_db.delete_value(sub)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.kind for a in event_sender.events] == ["templates-updated-many"] * 2 + ["templates-deleted"] * 10
