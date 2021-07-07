import asyncio
from typing import List

import pytest
from arango.database import StandardDatabase

from core.db.async_arangodb import AsyncArangoDB
from core.db.modeldb import ModelDB, ArangoModelDB, EventModelDB
from core.event_bus import EventBus
from core.model.model import Complex, Property, StringKind, NumberKind, BooleanKind, Kind
# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus, all_events
# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import test_db
from core.types import Json


@pytest.fixture
def test_model() -> List[Kind]:
    string_kind = StringKind("some.string", 0, 3, "\\w+")
    int_kind = NumberKind("some.int", "int32", 0, 100)
    bool_kind = BooleanKind("some.bool")
    base = Complex("base", None, [
        Property("identifier", "string", required=True),
        Property("kind", "string", required=True),
    ])
    foo = Complex("foo", "base", [
        Property("name", "string"),
        Property("some_int", "some.int"),
        Property("some_string", "some.string"),
        Property("now_is", "datetime"),
    ])
    bla = Complex("bla", "base", [
        Property("name", "string"),
        Property("now", "date"),
        Property("f", "int32"),
        Property("g", "int32[]"),
    ])
    return [string_kind, int_kind, bool_kind, base, foo, bla]


@pytest.fixture
async def model_db(test_db: StandardDatabase) -> ModelDB:
    async_db = AsyncArangoDB(test_db)
    model_db = ArangoModelDB(async_db, "model")
    await model_db.create_update_schema()
    await model_db.wipe()
    return model_db


@pytest.fixture
def event_db(model_db: ModelDB, event_bus: EventBus) -> EventModelDB:
    return EventModelDB(model_db, event_bus)


@pytest.mark.asyncio
async def test_load(model_db: ModelDB, test_model: List[Kind]) -> None:
    await model_db.update_kinds(test_model)
    loaded = [kind async for kind in model_db.get_kinds()]
    assert test_model.sort(key=fqn) == loaded.sort(key=fqn)


@pytest.mark.asyncio
async def test_update(model_db: ModelDB, test_model: List[Kind]) -> None:
    # multiple updates should work as expected
    await model_db.update_kinds(test_model)
    await model_db.update_kinds(test_model)
    await model_db.update_kinds(test_model)
    loaded = [kind async for kind in model_db.get_kinds()]
    assert test_model.sort(key=fqn) == loaded.sort(key=fqn)


@pytest.mark.asyncio
async def test_delete(model_db: ModelDB, test_model: List[Kind]) -> None:
    await model_db.update_kinds(test_model)
    remaining = list(test_model)
    for _ in test_model:
        kind = remaining.pop()
        await model_db.delete_kind(kind)
        loaded = [kind async for kind in model_db.get_kinds()]
        assert remaining.sort(key=fqn) == loaded.sort(key=fqn)
    assert len([kind async for kind in model_db.get_kinds()]) == 0


@pytest.mark.asyncio
async def test_events(event_db: EventModelDB, test_model: List[Kind], all_events: List[Json]) -> None:
    # 2 times update
    await event_db.update_kinds(test_model)
    await event_db.update_kinds(test_model)
    # 6 times delete
    for kind in test_model:
        await event_db.delete_kind(kind)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a["name"] for a in all_events] == ["model-updated"] * 2 + ["model-deleted"] * 6


def fqn(kind: Kind) -> str:
    return kind.fqn
