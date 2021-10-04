import asyncio
import json
import logging
import sys
from abc import ABC
from argparse import Namespace
from asyncio import Task
from dataclasses import dataclass
from datetime import timedelta
from multiprocessing import Process, Queue
from typing import Optional, Union, AsyncGenerator

from core.async_extensions import run_async
from core.db.db_access import DbAccess
from core.db.model import GraphUpdate
from core.dependencies import db_access, setup_logging
from core.event_bus import EventBus, Message
from core.model.graph_access import GraphBuilder
from core.model.model import Model
from core.types import Json

log = logging.getLogger(__name__)


class ProcessAction(ABC):
    """
    Base class to exchange commands between processes.
    Important: all messages must be serializable in order to get pickled/unpickled.
    """


@dataclass
class ReadElement(ProcessAction):
    """
    Read an incoming element:
    - either a line of text or
    - a complete json element
    Parent -> Child: for every incoming data line.
    """

    element: Union[bytes, Json]

    def json(self) -> Json:
        return self.element if isinstance(self.element, dict) else json.loads(self.element)  # type: ignore


@dataclass
class MergeGraph(ProcessAction):
    """
    Merge the graph that has been read so far.
    Parent -> Child: once EOF of the incoming graph is reached.
    """

    graph: str
    maybe_batch: Optional[str]


@dataclass
class EmitMessage(ProcessAction):
    """
    Emit this message to the event bus.
    Child -> Parent: to have the event from the child process propagated to the parent process.
    """

    event: Message


class PoisonPill(ProcessAction):
    """
    Sentence the process to die.
    Parent -> Child: when the update process is interrupted.
    """


@dataclass
class Result(ProcessAction):
    result: Union[GraphUpdate, Exception]

    def get_value(self) -> GraphUpdate:
        if isinstance(self.result, Exception):
            raise self.result
        else:
            return self.result


class DbUpdaterProcess(Process):
    """
    This update class implements Process and is supposed to run as separate process.
    Note: default starting method is supposed to be "spawn".

    This process has 2 queues to read input from and write output to.
    All elements in either queues are of type ProcessAction.

    The parent process should stream the raw parts of graph to this process via ReadElement objects.
    Once the MergeGraph action is received, the graph gets imported.
    From here the parent expects result messages from the child.
    All events happen in the child are forwarded to the parent via EmitEvent.
    Once the graph update is done, a result is send.
    The result is either an exception in case of failure or a graph update in success case.
    """

    def __init__(self, read_queue: Queue, write_queue: Queue, args: Namespace) -> None:  # type: ignore
        super().__init__(name="merge_update")
        self.read_queue = read_queue
        self.write_queue = write_queue
        self.args = args

    def next_action(self) -> ProcessAction:
        return self.read_queue.get(True, 30)  # type: ignore

    def forward_events(self, bus: EventBus) -> Task[None]:
        async def forward_events_forever() -> None:
            with bus.subscribe("event_forwarder") as events:
                while True:
                    event = await events.get()
                    self.write_queue.put(EmitMessage(event))

        return asyncio.create_task(forward_events_forever())

    async def merge_graph(self, db: DbAccess) -> GraphUpdate:  # type: ignore
        model = Model.from_kinds([kind async for kind in db.model_db.all()])
        builder = GraphBuilder(model)
        nxt = self.next_action()
        while isinstance(nxt, ReadElement):
            builder.add_from_json(nxt.json())
            nxt = self.next_action()
        if isinstance(nxt, PoisonPill):
            log.info("Got poison pill - going to die.")
            sys.exit(1)
        elif isinstance(nxt, MergeGraph):
            builder.check_complete()
            graphdb = db.get_graph_db(nxt.graph)
            _, result = await graphdb.merge_graph(builder.graph, model, nxt.maybe_batch)
            return result

    async def setup_and_merge(self) -> GraphUpdate:
        bus = EventBus()
        db = db_access(self.args, bus)
        task = self.forward_events(bus)
        result = await self.merge_graph(db)
        await asyncio.sleep(0.1)  # yield current process to drain event bus
        task.cancel()
        return result

    def run(self) -> None:
        try:
            # Entrypoint of the new service
            setup_logging(self.args, f"merge_update_{self.pid}")
            log.info("Import process started")
            result = asyncio.run(self.setup_and_merge())
            self.write_queue.put(Result(result))
            log.info("Update process done. Exit.")
            sys.exit(0)
        except Exception as ex:
            self.write_queue.put(Result(ex))
            log.info("Update process interrupted. Preemptive Exit.", exc_info=ex)
            sys.exit(1)


async def merge_graph_process(
    bus: EventBus,
    args: Namespace,
    content: AsyncGenerator[Union[bytes, Json], None],
    graph: str,
    max_wait: timedelta,
    maybe_batch: Optional[str],
) -> GraphUpdate:
    write = Queue()  # type: ignore
    read = Queue()  # type: ignore
    updater = DbUpdaterProcess(write, read, args)  # the process reads from our write queue and vice versa
    stale = timedelta(seconds=5).total_seconds()  # consider dead communication after this amount of time

    async def send_to_child(pa: ProcessAction) -> bool:
        alive = updater.is_alive()
        if alive:
            await run_async(write.put, pa, True, stale)
        return alive

    try:
        updater.start()
        async for line in content:
            if not await send_to_child(ReadElement(line)):
                # in case the child is dead, we should stop
                break
        await send_to_child(MergeGraph(graph, maybe_batch))
        while True:
            action = await run_async(read.get, True, max_wait.total_seconds())
            if isinstance(action, EmitMessage):
                await bus.emit(action.event)
            elif isinstance(action, Result):
                return action.get_value()
    finally:
        if updater.is_alive():
            log.debug(f"Process is still active - send poison pill {updater.pid}")
            await send_to_child(PoisonPill())
        await run_async(updater.join, stale)
        if updater.is_alive():
            log.warning(f"Process is still active after poison pill. Kill process {updater.pid}")
            updater.kill()
        updater.close()
