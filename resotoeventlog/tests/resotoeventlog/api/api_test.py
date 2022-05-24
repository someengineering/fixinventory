import multiprocessing
from asyncio import sleep
from contextlib import suppress
from multiprocessing import Process
from typing import AsyncIterator

import pytest
from aiohttp import ClientSession
from pytest import fixture
from resotolib.log import Event, Severity

from resotoeventlog.__main__ import run
from tests.resotoeventlog.api import EventLogClient


@fixture
async def client_session() -> AsyncIterator[ClientSession]:
    session = ClientSession()
    yield session
    await session.close()


@fixture
async def eventlog_client(client_session: ClientSession) -> AsyncIterator[EventLogClient]:
    """
    Note: adding this fixture to a test: a complete resotoeventlog process is started.
          The fixture ensures that the underlying process has entered the ready state.
          It also ensures to clean up the process, when the test is done.
    """
    multiprocessing.set_start_method("spawn", True)
    process = Process(
        target=run,
        args=(["--debug", "--no-tls", "--port", "8951"],),
    )
    process.start()
    ready = False
    count = 10
    while not ready:
        await sleep(0.5)
        with suppress(Exception):
            async with client_session.get("http://localhost:8951/system/ready"):
                ready = True
                count -= 1
                if count == 0:
                    raise AssertionError("Process does not came up as expected")
    yield EventLogClient("http://localhost:8951", client_session)
    # terminate the process
    process.terminate()
    process.join(5)
    # if it is still running, kill it
    if process.is_alive():
        process.kill()
        process.join()
    process.close()


@pytest.mark.asyncio
async def test_api(eventlog_client: EventLogClient) -> None:
    assert await eventlog_client.ready()
    assert await eventlog_client.ping() == "pong"

    # ingest a couple of events
    events = [Event("test", ev, Severity.info, "log", {"message": "test"}) for ev in range(10)]
    await eventlog_client.ingest(events)

    gen, done = await eventlog_client.events()
    async for count, event in gen():
        if count == len(events):
            done.set_result(True)  # signal that we are done
