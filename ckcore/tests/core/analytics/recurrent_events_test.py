import asyncio
from datetime import timedelta

import pytest

from core.analytics import InMemoryEventSender, CoreEvent
from core.analytics.recurrent_events import emit_recurrent_events
from core.message_bus import MessageBus
from core.task.model import Subscriber
from core.worker_task_queue import WorkerTaskQueue
from tests.core.db.entitydb import InMemoryDb
from core.model.model import Model
from core.task.subscribers import SubscriptionHandler
from tests.core.model import ModelHandlerStatic


@pytest.mark.asyncio
async def test_emit_recurrent_events() -> None:
    message_bus = MessageBus()
    sender = InMemoryEventSender()
    model = ModelHandlerStatic(Model.empty())
    sub = SubscriptionHandler(InMemoryDb[Subscriber](Subscriber, lambda x: x.id), message_bus)
    queue = WorkerTaskQueue()
    periodic = emit_recurrent_events(sender, model, sub, queue, message_bus, timedelta(seconds=0.001))
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
