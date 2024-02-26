import asyncio
from datetime import timedelta

import pytest

from fixcore.message_bus import MessageBus, CoreMessage
from fixcore.task.start_workflow_on_first_subscriber import wait_and_start
from fixcore.task.task_description import Workflow
from tests.fixcore.task.job_handler_test import InMemJobHandler


@pytest.mark.asyncio
async def test_wait_and_start(message_bus: MessageBus, test_workflow: Workflow) -> None:
    handler = InMemJobHandler()
    task = wait_and_start([test_workflow], handler, message_bus, timedelta(seconds=0))
    await asyncio.sleep(0.1)
    await message_bus.emit_event(CoreMessage.Connected, {"subscriber_id": "test", "channels": ["collect"]})
    await task
    assert handler.started_tasks == ["test_workflow"]
