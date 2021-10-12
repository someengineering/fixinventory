import asyncio
from datetime import timedelta

import pytest

from core.message_bus import MessageBus, CoreEvent
from core.task.start_workflow_on_first_subscriber import wait_and_start
from core.task.task_description import Workflow

# noinspection PyUnresolvedReferences
from tests.core.message_bus_test import message_bus
from tests.core.task.job_handler_test import InMemJobHandler

# noinspection PyUnresolvedReferences
from tests.core.task.task_handler_test import test_workflow


@pytest.mark.asyncio
async def test_wait_and_start(message_bus: MessageBus, test_workflow: Workflow) -> None:
    handler = InMemJobHandler()
    task = wait_and_start([test_workflow], handler, message_bus, timedelta(seconds=0))
    await asyncio.sleep(0.1)
    await message_bus.emit_event(CoreEvent.Connected, {"subscriber_id": "test", "channels": ["collect"]})
    await task
    assert handler.started_tasks == ["test_workflow"]
