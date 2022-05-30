from asyncio import Queue, QueueFull
from collections import deque
from contextlib import asynccontextmanager
from itertools import islice
from typing import AsyncGenerator, Optional, List, Dict

from resotolib.log import Event
from resotolib.logger import log


class LogHandler:
    def __init__(self, max_entries: int) -> None:
        self.events = deque[Event](maxlen=max_entries)
        # key is the channel name, value is the list of queues
        self.listeners: Dict[str, List[Queue[Event]]] = {}
        # key is the subscriber id, value is the list of queue names
        self.active_listener: Dict[str, List[str]] = {}

    async def add_event(self, event: Event) -> None:
        self.events.append(event)
        await self.emit(event)

    @asynccontextmanager
    async def subscribe(
        self, subscriber_id: str, channels: Optional[List[str]] = None, queue_size: int = 0, show_last: int = 100
    ) -> AsyncGenerator[Queue[Event], None]:
        queue: Queue[Event] = Queue(queue_size)

        # initially fill the list with the last x entries
        try:
            el = len(self.events)
            for element in islice(self.events, max(0, el - show_last), el):
                queue.put_nowait(element)
        except QueueFull:
            pass

        def add_listener(name: str) -> None:
            if name not in self.listeners:
                self.listeners[name] = [queue]
            else:
                self.listeners[name].append(queue)

        def remove_listener(name: str) -> None:
            self.listeners[name].remove(queue)
            if len(self.listeners[name]) == 0:
                del self.listeners[name]

        ch_list = channels if channels else ["*"]
        if len(ch_list) == 0:
            raise AttributeError("Need at least one channel to subscribe to!")
        try:
            self.active_listener[subscriber_id] = ch_list
            for channel in ch_list:
                add_listener(channel)
            log.info(f"Event listener {subscriber_id} added to following queues: {ch_list}")
            yield queue
        finally:
            log.info(f"Remove listener: {subscriber_id}")
            for channel in ch_list:
                remove_listener(channel)
            self.active_listener.pop(subscriber_id, None)

    async def emit(self, event: Event) -> None:
        async def emit_by(name: str) -> None:
            for listener in self.listeners.get(name, []):
                try:
                    await listener.put(event)
                except QueueFull:
                    log.warning(f"Queue for listener {name} is full. Dropping message.")

        await emit_by(event.kind)  # inform specific listener
        await emit_by("*")  # inform "all" event listener
