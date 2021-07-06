import asyncio
from typing import List, AsyncGenerator

from pytest import fixture, mark
from core.event_bus import EventBus
from core.types import Json


@fixture
def event_bus() -> EventBus:
    return EventBus()


@fixture
async def all_events(event_bus: EventBus) -> AsyncGenerator[List[Json], None]:
    events: List[Json] = []

    async def gather_events() -> None:
        with event_bus.subscribe() as event_queue:
            while True:
                events.append(await event_queue.get())

    run_gather = asyncio.create_task(gather_events())
    try:
        yield events
    finally:
        run_gather.cancel()


@mark.asyncio
async def test_handler(event_bus: EventBus) -> None:
    foos: List[Json] = []
    blas: List[Json] = []

    async def emit() -> None:
        await event_bus.emit("foo", {})
        await event_bus.emit("foo", {})
        await event_bus.emit("bla", {})
        await event_bus.emit("bar", {})

    async def wait_for(name: str, list: List[Json]) -> None:
        with event_bus.subscribe([name]) as events:
            while True:
                list.append(await events.get())

    foo_t = asyncio.create_task(wait_for("foo", foos))
    bla_t = asyncio.create_task(wait_for("bla", blas))

    await asyncio.sleep(0.1)
    await emit()
    await asyncio.sleep(0.1)
    assert len(foos) == 2
    assert len(blas) == 1
    foo_t.cancel()
    await emit()
    await asyncio.sleep(0.1)
    assert len(foos) == 2
    assert len(blas) == 2
    bla_t.cancel()
