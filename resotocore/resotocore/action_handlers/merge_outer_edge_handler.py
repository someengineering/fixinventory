from resotocore.message_bus import MessageBus, Action
import logging
import asyncio
from asyncio import Task, Future
from typing import Optional
from contextlib import suppress
from datetime import timedelta
from resotocore.task.model import Subscriber
from resotocore.model.ids import SubscriberId
from resotocore.task.task_handler import TaskHandlerService

from resotocore.task.subscribers import SubscriptionHandler

log = logging.getLogger(__name__)

subscriber_id = SubscriberId("resotocore")
merge_outer_edges = "merge_outer_edges"


class MergeOuterEdgesHandler:
    def __init__(
        self,
        message_bus: MessageBus,
        subscription_handler: SubscriptionHandler,
        task_handler_service: TaskHandlerService,
    ):
        self.message_bus = message_bus
        self.merge_outer_edges_listener: Optional[Task[None]] = None
        self.subscription_handler = subscription_handler
        self.subscriber: Optional[Subscriber] = None
        self.task_handler_service = task_handler_service

    def merge_outer_edges(self, task_id: str) -> None:
        log.info(f"MergeOuterEdgesHandler: Noop outer edge merge for task_id: {task_id}")

    async def __handle_events(self, subscription_done: Future[None]) -> None:
        async with self.message_bus.subscribe(subscriber_id, [merge_outer_edges]) as events:
            subscription_done.set_result(None)
            while True:
                event = await events.get()
                if isinstance(event, Action) and event.message_type == merge_outer_edges:
                    self.merge_outer_edges(event.task_id)
                    await self.task_handler_service.handle_action_done(event.done(subscriber_id))

    async def start(self) -> None:
        subscription_done = asyncio.get_event_loop().create_future()
        self.subscriber = await self.subscription_handler.add_subscription(
            subscriber_id, merge_outer_edges, True, timedelta(seconds=30)
        )
        self.merge_outer_edges_listener = asyncio.create_task(
            self.__handle_events(subscription_done), name=subscriber_id
        )
        await subscription_done

    async def stop(self) -> None:
        if self.merge_outer_edges_listener:
            with suppress(Exception):
                self.merge_outer_edges_listener.cancel()
        if self.subscriber:
            await self.subscription_handler.remove_subscription(subscriber_id, merge_outer_edges)
