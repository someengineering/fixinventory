import asyncio
from typing import AsyncGenerator, List

import pytest
from pytest import fixture
from resotolib.log import Event, Severity

from resotoeventlog.logs.log_handler import LogHandler


@fixture
def log_handler() -> LogHandler:
    return LogHandler(100)


@fixture
async def all_events(log_handler: LogHandler) -> AsyncGenerator[List[Event], None]:
    events: List[Event] = []

    async def gather_events() -> None:
        async with log_handler.subscribe("test", ["log"]) as event_queue:
            while True:
                events.append(await event_queue.get())

    run_gather = asyncio.create_task(gather_events())
    try:
        yield events
    finally:
        run_gather.cancel()


@pytest.mark.asyncio
async def test_collect_events(log_handler: LogHandler, all_events: List[Event]) -> None:
    # send a couple of events, more than the internal buffer can hold
    for num in range(120):
        await log_handler.add_event(Event("test", num, Severity.info, "log", {"num": num}))
    await asyncio.sleep(0)

    # we expect all messages to be arrived
    assert len(all_events) == 120

    # we expect that only the max number of configured events is kept
    assert len(log_handler.events) == 100

    # Only listens for log messages, so this one gets ignored
    await log_handler.add_event(Event("test", 123, Severity.info, "unknown", {"num": 123}))
    assert len(all_events) == 120
