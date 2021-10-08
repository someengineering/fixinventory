import asyncio
from typing import AsyncGenerator, Any, Type, List

from datetime import timedelta
from deepdiff import DeepDiff
from pytest import fixture, mark

from core.message_bus import MessageBus, Message, Event, Action, ActionDone, ActionError
from core.model.typed_model import to_js, from_js
from core.util import AnyT, utc, first


@fixture
def message_bus() -> MessageBus:
    return MessageBus()


@fixture
async def all_events(message_bus) -> AsyncGenerator[List[Message], None]:
    events: List[Message] = []

    async def gather_events() -> None:
        async with message_bus.subscribe("test") as event_queue:
            while True:
                events.append(await event_queue.get())

    run_gather = asyncio.create_task(gather_events())
    try:
        yield events
    finally:
        run_gather.cancel()


async def wait_for_message(
    all_events: List[Message], message_type: str, t: Type[AnyT], timeout: timedelta = timedelta(seconds=1)
) -> AnyT:
    stop_at = utc() + timeout

    async def find() -> AnyT:
        result = first(lambda m: isinstance(m, t) and m.message_type == message_type, all_events)  # type: ignore
        if result:
            return result  # type: ignore
        elif utc() > stop_at:
            raise TimeoutError()
        else:
            await asyncio.sleep(0.1)
            return await find()

    return await find()


@mark.asyncio
async def test_handler(message_bus) -> None:
    foos: List[Message] = []
    blas: List[Message] = []

    async def emit() -> None:
        await message_bus.emit(Event("foo"))
        await message_bus.emit(Event("foo"))
        await message_bus.emit(Event("bla"))
        await message_bus.emit(Event("bar"))

    async def wait_for(name: str, list: List[Message]) -> None:
        async with message_bus.subscribe("test", [name]) as events:
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
    roundtrip(Event("test", {"a": "b", "c": 1, "d": "bla"}))
    roundtrip(Action("test", "123", "step_name"))
    roundtrip(Action("test", "123", "step_name", {"test": 1}))
    roundtrip(ActionDone("test", "123", "step_name", "sub"))
    roundtrip(ActionDone("test", "123", "step_name", "sub", {"test": 1}))
    roundtrip(ActionError("test", "123", "step_name", "sub", "oops"))
    roundtrip(ActionError("test", "123", "step_name", "sub", "oops", {"test": 23}))


def roundtrip(obj: Any) -> None:
    js = to_js(obj)
    again = from_js(js, type(obj))
    assert DeepDiff(obj, again) == {}, f"Json: {js} serialized as {again}"
