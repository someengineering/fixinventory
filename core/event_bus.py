import logging
from asyncio import Queue
from contextlib import contextmanager
from typing import Dict, List, Generator, Any, Optional

from core.model.model import Json

log = logging.getLogger(__name__)


class Event:
    NodeCreated = "node-created"
    NodeUpdated = "node-updated"
    NodeDeleted = "node-deleted"
    SubGraphUpdated = "subgraph-updated"
    BatchUpdateSubGraphAdded = "batch-update-subgraph-added"
    BatchUpdateCommitted = "batch-update-committed"
    BatchUpdateAborted = "batch-update-aborted"
    GraphDBWiped = "graphdb-wiped"
    ModelUpdated = "model-updated"
    ModelDeleted = "model-deleted"

    AllEvents = {
        NodeCreated,
        NodeUpdated,
        NodeDeleted,
        SubGraphUpdated,
        BatchUpdateSubGraphAdded,
        BatchUpdateCommitted,
        BatchUpdateAborted,
        GraphDBWiped,
        ModelUpdated,
        ModelDeleted
    }


class EventBus:
    """
    This class implements a simple event bus.
    Every subscriber is context managed and gets its own queue of events.
    """

    def __init__(self):
        self.listeners: Dict[str, List[Queue]] = {}

    @contextmanager
    def subscribe(self, channels: Optional[List[str]] = None, queue_size: int = 0) -> Generator[Queue, Any, None]:
        """
        Subscribe to a list of event channels.
        All events that match the channel will be written to this queue.
        This is an async queue - all operations are async!

        Usage Subscriber:
        with bus.subscribe(["foo", "bar", "bla"]) as q:
          elem = await q.get()

        Usage Emitter:
        await bus.emit("foo", { "my": "event" })

        :param channels: the list of channels to subscribe to. In case if empty list: all channels.
        :param queue_size: the size of elements that can be buffered in the queue.
        :return: the context managed queue.
        """
        queue: Queue = Queue(queue_size)

        def add_listener(name: str):
            if name not in self.listeners:
                self.listeners[name] = [queue]
            else:
                self.listeners[name].append(queue)

        def remove_listener(name: str):
            self.listeners[name].remove(queue)
            if len(self.listeners[name]) == 0:
                del self.listeners[name]

        ch_list = channels if channels else ["*"]
        try:
            for channel in ch_list:
                add_listener(channel)
            yield queue
        finally:
            log.info("Remove listener....")
            for channel in ch_list:
                remove_listener(channel)

    async def emit(self, event_name: str, event: Json):
        async def emit_by(name: str):
            for listener in self.listeners.get(name, []):
                await listener.put({"name": event_name, "event": event})

        await emit_by(event_name)  # inform specific listener
        await emit_by("*")  # inform "all" event listener
