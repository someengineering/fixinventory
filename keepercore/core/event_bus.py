from __future__ import annotations

import logging
from abc import ABC
from asyncio import Queue
from contextlib import contextmanager
from typing import Dict, List, Generator, Any, Optional

from jsons import set_deserializer, set_serializer

from core.types import Json
from core.util import pop_keys
from frozendict import frozendict

log = logging.getLogger(__name__)


class CoreEvent:
    NodeCreated = "node-created"
    NodeUpdated = "node-updated"
    NodesDesiredUpdated = "nodes-desired-updated"
    NodeDeleted = "node-deleted"
    GraphMerged = "graph-merged"
    BatchUpdateGraphMerged = "batch-update-graph-merged"
    BatchUpdateCommitted = "batch-update-committed"
    BatchUpdateAborted = "batch-update-aborted"
    GraphDBWiped = "graphdb-wiped"
    WorkflowFinished = "task-finished"


class Message(ABC):
    """
    Json representation of a message is always:
    { "kind": "xxx", "message_type": "yyy", "data": { ... }}

    The kind defines the purpose of this message and is one of those:
    - event: something happened in the system
    - action: some action needs to be performed
    - action_done: response for a given action to mark this action as done
    - action_error: response for a given action to mark this action as error

    The message type is an identifier that identifies the cause of a message.
    A message_type has to be unique for a specific cause.
    Subscribers subscribe solely on message_type.

    The data field can hold arbitrary data that makes sense for the specific message.
    For all action, action_done and action_error messages, the data field contains references to the task.
    """

    def __init__(self, message_type: str, data: Optional[Json]):
        self.message_type = message_type
        self.data = frozendict(data if data else {})

    def __eq__(self, other: Any) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Message) else False

    def __hash__(self) -> int:
        return hash(self.message_type) + hash(self.data)

    @staticmethod
    def from_json(json: Json, _: type = object, **__: object) -> Message:
        kind = json["kind"]
        message_type = json["message_type"]
        data: Json = json.get("data", {})
        if kind == "event":
            res_data = pop_keys(data, ["task", "step", "subscriber_id"])
            return Event(message_type, res_data)
        elif kind == "action":
            res_data = pop_keys(data, ["task", "step", "subscriber_id"])
            return Action(message_type, data["task"], data["step"], res_data)
        elif kind == "action_done":
            res_data = pop_keys(data, ["task", "step", "subscriber_id"])
            return ActionDone(message_type, data["task"], data["step"], data["subscriber_id"], res_data)
        elif kind == "action_error":
            res_data = pop_keys(data, ["task", "step", "subscriber_id", "error"])
            return ActionError(
                message_type, data["task"], data["step"], data["subscriber_id"], data.get("error", "n/a"), res_data
            )
        else:
            raise AttributeError(f"No handler to parse {kind}")

    @staticmethod
    def message_to_json(o: Message, **_: object) -> Json:
        if isinstance(o, Event):
            return {
                "kind": "event",
                "message_type": o.message_type,
                "data": o.data,
            }
        elif isinstance(o, Action):
            extra_data = {"task": o.task_id, "step": o.step_name}
            return {
                "kind": "action",
                "message_type": o.message_type,
                "data": o.data | extra_data,
            }
        elif isinstance(o, ActionDone):
            extra_data = {"task": o.task_id, "step": o.step_name, "subscriber_id": o.subscriber_id}
            return {
                "kind": "action_done",
                "message_type": o.message_type,
                "data": o.data | extra_data,
            }
        elif isinstance(o, ActionError):
            extra_data = {
                "task": o.task_id,
                "step": o.step_name,
                "subscriber_id": o.subscriber_id,
                "error": o.error,
            }
            return {
                "kind": "action_error",
                "message_type": o.message_type,
                "data": o.data | extra_data,
            }
        else:
            raise AttributeError(f"No handler to marshal {type(o).__name__}")


class Event(Message):
    def __init__(self, message_type: str, data: Optional[Json] = None):
        super().__init__(message_type, data)


class ActionMessage(Message):
    def __init__(self, message_type: str, task_id: str, step_name: str, data: Optional[Json] = None):
        super().__init__(message_type, data)
        self.task_id = task_id
        self.step_name = step_name


class Action(ActionMessage):
    pass


class ActionDone(ActionMessage):
    def __init__(
        self,
        message_type: str,
        task_id: str,
        step_name: str,
        subscriber_id: str,
        data: Optional[Json] = None,
    ):
        super().__init__(message_type, task_id, step_name, data)
        self.subscriber_id = subscriber_id


class ActionError(ActionMessage):
    def __init__(
        self,
        message_type: str,
        task_id: str,
        step_name: str,
        subscriber_id: str,
        error: str,
        data: Optional[Json] = None,
    ):
        super().__init__(message_type, task_id, step_name, data)
        self.subscriber_id = subscriber_id
        self.error = error


class EventBus:
    """
    This class implements a simple event bus.
    Every subscriber is context managed and gets its own queue of events.
    """

    def __init__(self) -> None:
        # key is the channel name, value is the list of queues
        self.listeners: Dict[str, List[Queue[Message]]] = {}
        # key is the subscriber id, value is the list of queue names
        self.active_listener: dict[str, list[str]] = {}

    @contextmanager
    def subscribe(
        self, subscriber_id: str, channels: Optional[List[str]] = None, queue_size: int = 0
    ) -> Generator[Queue[Message], Any, None]:
        """
        Subscribe to a list of event channels.
        All events that match the channel will be written to this queue.
        This is an async queue - all operations are async!

        Usage Subscriber:
        with bus.subscribe(["foo", "bar", "bla"]) as q:
          elem = await q.get()

        Usage Emitter:
        await bus.emit("foo", { "my": "event" })

        :param subscriber_id: the id of the subscriber.
        :param channels: the list of channels to subscribe to. In case if empty list: all channels.
        :param queue_size: the size of elements that can be buffered in the queue.
        :return: the context managed queue.
        """
        queue: Queue[Message] = Queue(queue_size)

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
            log.info(f"Listener {subscriber_id} added to following queues: {ch_list}")
            yield queue
        finally:
            log.info(f"Remove listener: {subscriber_id}")
            for channel in ch_list:
                remove_listener(channel)
            self.active_listener.pop(subscriber_id, None)

    async def emit_event(self, event_type: str, data: Json) -> None:
        return await self.emit(Event(event_type, data))

    async def emit(self, message: Message) -> None:
        async def emit_by(name: str) -> None:
            for listener in self.listeners.get(name, []):
                await listener.put(message)

        await emit_by(message.message_type)  # inform specific listener
        await emit_by("*")  # inform "all" event listener


set_deserializer(Message.from_json, Message)
set_serializer(Message.message_to_json, Message)
