from datetime import timedelta

from core.analytics import AnalyticsEventSender, CoreEvent
from core.message_bus import MessageBus
from core.model.model_handler import ModelHandler
from core.task.subscribers import SubscriptionHandler
from core.util import Periodic
from core.worker_task_queue import WorkerTaskQueue


def emit_recurrent_events(
    event_sender: AnalyticsEventSender,
    model_handler: ModelHandler,
    subscription_handler: SubscriptionHandler,
    worker_task_queue: WorkerTaskQueue,
    message_bus: MessageBus,
    frequency: timedelta,
    first_run: timedelta = timedelta(minutes=1),
) -> Periodic:
    async def emit_events() -> None:
        # information about the model
        model = await model_handler.load_model()
        await event_sender.core_event(CoreEvent.ModelInfo, model_count=len(model.kinds))
        # information about all subscribers/actors
        subscribers = await subscription_handler.all_subscribers()
        await event_sender.core_event(
            CoreEvent.SubscriberInfo,
            subscriber_count=sum(1 for _ in subscribers),
            # do not count wildcard listeners
            active=sum(1 for channels in message_bus.active_listener.values() if channels != ["*"]),
        )
        # information about all workers
        await event_sender.core_event(
            CoreEvent.WorkerQueueInfo,
            worker_count=len(worker_task_queue.work_count),
            worker_tasks_count=len(worker_task_queue.worker_by_task_name),
            outstanding_tasks=len(worker_task_queue.outstanding_tasks),
            unassigned_tasks=len(worker_task_queue.unassigned_tasks),
        )

    return Periodic("emit_recurrent_events", emit_events, frequency, first_run)
