import asyncio
from typing import List, AsyncGenerator, Any, Type

from deepdiff import DeepDiff
from pytest import fixture, mark
from core.event_bus import EventBus, Message, Event, Action, ActionDone, ActionError
from core.model.typed_model import to_js, from_js


@fixture
def event_bus() -> EventBus:
    return EventBus()


@fixture
async def all_events(event_bus: EventBus) -> AsyncGenerator[List[Message], None]:
    events: List[Message] = []

    async def gather_events() -> None:
        with event_bus.subscribe("test") as event_queue:
            while True:
                events.append(await event_queue.get())

    run_gather = asyncio.create_task(gather_events())
    try:
        yield events
    finally:
        run_gather.cancel()


@mark.asyncio
async def test_handler(event_bus: EventBus) -> None:
    foos: List[Message] = []
    blas: List[Message] = []

    async def emit() -> None:
        await event_bus.emit(Event("foo"))
        await event_bus.emit(Event("foo"))
        await event_bus.emit(Event("bla"))
        await event_bus.emit(Event("bar"))

    async def wait_for(name: str, list: List[Message]) -> None:
        with event_bus.subscribe("test", [name]) as events:
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


def test_message_serialization() -> None:
    roundtrip(Event("test", {"a": "b", "c": 1, "d": "bla"}), Message)
    roundtrip(Action("test", "123", "step_name"), Message)
    roundtrip(Action("test", "123", "step_name", {"test": 1}), Message)
    roundtrip(ActionDone("test", "123", "step_name", "sub"), Message)
    roundtrip(ActionDone("test", "123", "step_name", "sub", {"test": 1}), Message)
    roundtrip(ActionError("test", "123", "step_name", "sub", "oops"), Message)
    roundtrip(ActionError("test", "123", "step_name", "sub", "oops", {"test": 23}), Message)


def roundtrip(obj: Any, clazz: Type[object]) -> None:
    js = to_js(obj)
    again = from_js(js, clazz)
    assert DeepDiff(obj, again) == {}, f"Json: {js} serialized as {again}"
