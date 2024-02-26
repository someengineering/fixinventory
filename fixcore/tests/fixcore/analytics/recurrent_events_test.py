import asyncio
from datetime import timedelta

import pytest

from fixcore.analytics import InMemoryEventSender, CoreEvent
from fixcore.analytics.recurrent_events import emit_recurrent_events
from fixcore.message_bus import MessageBus
from fixcore.model.model import Model
from fixcore.task.subscribers import SubscriptionHandler
from fixcore.worker_task_queue import WorkerTaskQueue
from tests.fixcore.model import ModelHandlerStatic


@pytest.mark.asyncio
async def test_emit_recurrent_events(subscription_handler: SubscriptionHandler) -> None:
    message_bus = MessageBus()
    sender = InMemoryEventSender()
    model = ModelHandlerStatic(Model.empty())
    queue = WorkerTaskQueue()
    fast = timedelta(seconds=0.001)
    periodic = emit_recurrent_events(sender, model, subscription_handler, queue, message_bus, fast, fast)
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
