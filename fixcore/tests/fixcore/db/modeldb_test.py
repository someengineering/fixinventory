import asyncio
from typing import List

import pytest
from arango.database import StandardDatabase

from fixcore.analytics import AnalyticsEventSender, InMemoryEventSender
from fixcore.db import modeldb
from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.db.entitydb import EventEntityDb
from fixcore.db.modeldb import ModelDb, EventModelDb
from fixcore.model.model import ComplexKind, Property, StringKind, NumberKind, BooleanKind, Kind


@pytest.fixture
def test_kinds() -> List[Kind]:
    string_kind = StringKind("some.string", 0, 3, "\\w+")
    int_kind = NumberKind("some.int", "int32", 0, 100)
    bool_kind = BooleanKind("some.bool")
    base = ComplexKind(
        "base",
        [],
        [
            Property("id", "string", required=True),
            Property("kind", "string", required=True),
        ],
    )
    foo = ComplexKind(
        "foo",
        ["base"],
        [
            Property("name", "string"),
            Property("some_int", "some.int"),
            Property("some_string", "some.string"),
            Property("now_is", "datetime"),
        ],
    )
    bla = ComplexKind(
        "bla",
        ["base"],
        [
            Property("name", "string"),
            Property("now", "date"),
            Property("f", "int32"),
            Property("g", "int32[]"),
        ],
    )
    return [string_kind, int_kind, bool_kind, base, foo, bla]


@pytest.fixture
async def model_db(test_db: StandardDatabase) -> ModelDb:
    async_db = AsyncArangoDB(test_db)
    model_db = modeldb.model_db(async_db, "model")
    await model_db.create_update_schema()
    await model_db.wipe()
    return model_db


@pytest.fixture
def event_db(model_db: ModelDb, event_sender: AnalyticsEventSender) -> EventModelDb:
    return EventEntityDb(model_db, event_sender, "model")


@pytest.mark.asyncio
async def test_load(model_db: ModelDb, test_kinds: List[Kind]) -> None:
    await model_db.update_many(test_kinds)
    loaded = [kind async for kind in model_db.all()]
    assert test_kinds.sort(key=fqn) == loaded.sort(key=fqn)


@pytest.mark.asyncio
async def test_update(model_db: ModelDb, test_kinds: List[Kind]) -> None:
    # multiple updates should work as expected
    await model_db.update_many(test_kinds)
    await model_db.update_many(test_kinds)
    await model_db.update_many(test_kinds)
    loaded = [kind async for kind in model_db.all()]
    assert test_kinds.sort(key=fqn) == loaded.sort(key=fqn)


@pytest.mark.asyncio
async def test_delete(model_db: ModelDb, test_kinds: List[Kind]) -> None:
    await model_db.update_many(test_kinds)
    remaining = list(test_kinds)
    for _ in test_kinds:
        kind = remaining.pop()
        await model_db.delete_value(kind)
        loaded = [kind async for kind in model_db.all()]
        assert remaining.sort(key=fqn) == loaded.sort(key=fqn)
    assert len([kind async for kind in model_db.all()]) == 0


@pytest.mark.asyncio
async def test_events(event_db: EventModelDb, test_kinds: List[Kind], event_sender: InMemoryEventSender) -> None:
    # 2 times update
    await event_db.update_many(test_kinds)
    await event_db.update_many(test_kinds)
    # 6 times delete
    for kind in test_kinds:
        await event_db.delete_value(kind)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.kind for a in event_sender.events] == ["model-updated-many"] * 2 + ["model-deleted"] * 6


def fqn(kind: Kind) -> str:
    return kind.fqn
