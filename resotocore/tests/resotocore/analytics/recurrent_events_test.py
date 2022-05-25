import asyncio
from datetime import timedelta

import pytest

from resotocore.analytics import InMemoryEventSender, CoreEvent
from resotocore.analytics.recurrent_events import emit_recurrent_events
from resotocore.message_bus import MessageBus
from resotocore.task.model import Subscriber
from resotocore.worker_task_queue import WorkerTaskQueue
from tests.resotocore.db.entitydb import InMemoryDb
from resotocore.model.model import Model
from resotocore.task.subscribers import SubscriptionHandler
from tests.resotocore.model import ModelHandlerStatic


@pytest.mark.asyncio
async def test_emit_recurrent_events() -> None:
    message_bus = MessageBus()
    sender = InMemoryEventSender()
    model = ModelHandlerStatic(Model.empty())
    sub = SubscriptionHandler(InMemoryDb(Subscriber, lambda x: x.id), message_bus)
    queue = WorkerTaskQueue()
    fast = timedelta(seconds=0.001)
    periodic = emit_recurrent_events(sender, model, sub, queue, message_bus, fast, fast)
    await periodic.start()
    while len(sender.events) < 3:
        await asyncio.sleep(0.01)
    await periodic.stop()
    model_event, subscriber_event, worker_event = sender.events[0:3]
    assert model_event.kind == CoreEvent.ModelInfo
    assert model_event.counters["model_count"] == 0
    assert subscriber_event.kind == CoreEvent.SubscriberInfo
    assert subscriber_event.counters["subscriber_count"] == 0
    assert worker_event.kind == CoreEvent.WorkerQueueInfo
    assert worker_event.counters["worker_count"] == 0
