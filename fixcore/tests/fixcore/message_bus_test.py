import asyncio
from datetime import timedelta, datetime, timezone
from typing import Any, Type, List

from deepdiff import DeepDiff
from pytest import mark

from fixcore.ids import SubscriberId
from fixcore.ids import TaskId
from fixcore.message_bus import (
    MessageBus,
    Message,
    Event,
    Action,
    ActionDone,
    ActionError,
    ActionInfo,
    ActionProgress,
    ActionAbort,
)
from fixcore.model.typed_model import to_js, from_js
from fixcore.util import AnyT, utc, first
from fixlib.core.progress import ProgressDone, Progress
from fixlib.utils import freeze


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
async def test_handler(message_bus: MessageBus) -> None:
    foos: List[Message] = []
    blas: List[Message] = []

    async def emit() -> None:
        await message_bus.emit(Event("foo"))
        await message_bus.emit(Event("foo"))
        await message_bus.emit(Event("bla"))
        await message_bus.emit(Event("bar"))

    async def wait_for(name: str, list: List[Message]) -> None:
        async with message_bus.subscribe(SubscriberId("test"), [name]) as events:
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
    task_id = TaskId("123")
    subsctiber_id = SubscriberId("sub")
    now = datetime(2022, 10, 23, 12, 0, 0, 0, timezone.utc)
    roundtrip(Event("test", {"a": "b", "c": 1, "d": "bla"}))
    roundtrip(Event("test", freeze({"a": "b", "c": {"a": 1, "d": "bla"}})))
    roundtrip(Action("test", task_id, "step_name"))
    roundtrip(Action("test", task_id, "step_name", {"test": 1}))
    roundtrip(ActionDone("test", task_id, "step_name", subsctiber_id))
    roundtrip(ActionDone("test", task_id, "step_name", subsctiber_id, {"test": 1}))
    roundtrip(ActionError("test", task_id, "step_name", subsctiber_id, "oops"))
    roundtrip(ActionError("test", task_id, "step_name", subsctiber_id, "oops", {"test": 23}))
    roundtrip(ActionInfo("test", task_id, "step_name", subsctiber_id, "error", "Error message"))
    roundtrip(ActionProgress("test", task_id, "step_name", subsctiber_id, ProgressDone("region", 1, 2), now))
    roundtrip(ActionAbort("test", task_id, "step_name", {"test": 1}))
    nested = Progress.from_progresses("account1", [ProgressDone("region", 1, 2)])
    pg = ActionProgress("test", task_id, "step_name", subsctiber_id, nested, now)
    assert to_js(pg) == to_js(from_js(to_js(pg), ActionProgress))


def roundtrip(obj: Any) -> None:
    js = to_js(obj)
    again = from_js(js, type(obj))
    assert DeepDiff(obj, again) == {}, f"Json: {js} serialized as {again}"
