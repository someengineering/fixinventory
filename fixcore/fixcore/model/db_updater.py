from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from abc import ABC
from asyncio import Task, CancelledError
from collections import defaultdict
from contextlib import suppress
from datetime import timedelta, datetime
from multiprocessing import Process, Queue
from pathlib import Path
from queue import Empty
from typing import Optional, Union, Any, Generator, List, AsyncIterator, Dict

import aiofiles
from aiostream import stream, pipe
from aiostream.core import Stream
from attrs import define

from fixcore.analytics import AnalyticsEventSender, InMemoryEventSender, AnalyticsEvent
from fixcore.async_extensions import run_async
from fixcore.core_config import CoreConfig
from fixcore.db.db_access import DbAccess
from fixcore.db.deferredouteredgedb import DeferredOuterEdges
from fixcore.db.graphdb import GraphDB
from fixcore.db.model import GraphUpdate
from fixcore.error import ImportAborted
from fixcore.ids import TaskId, GraphName
from fixcore.message_bus import MessageBus, CoreMessage
from fixcore.model.graph_access import GraphBuilder
from fixcore.model.model_handler import ModelHandlerDB, ModelHandler
from fixcore.service import Service
from fixcore.system_start import db_access, setup_process, reset_process_start_method
from fixcore.types import Json
from fixcore.util import utc, uuid_str, shutdown_process

log = logging.getLogger(__name__)


class ProcessAction(ABC):
    """
    Base class to exchange commands between processes.
    Important: all messages must be serializable in order to get pickled/unpickled.
    """


@define
class ReadFile(ProcessAction):
    """
    Read a file from disk.
    """

    path: Path
    task_id: Optional[str]

    def jsons(self) -> Generator[Json, Any, None]:
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)


@define
class ReadElement(ProcessAction):
    """
    Read an incoming element:
    - either a line of text or
    - a complete json element
    Parent -> Child: for every incoming data line.
    """

    elements: List[Union[bytes, Json]]
    task_id: Optional[str]

    def jsons(self) -> Generator[Json, Any, None]:
        return (e if isinstance(e, dict) else json.loads(e) for e in self.elements)


@define
class MergeGraph(ProcessAction):
    """
    Merge the graph that has been read so far.
    Parent -> Child: once EOF of the incoming graph is reached.
    """

    graph: GraphName
    change_id: str
    is_batch: bool = False
    task_id: Optional[TaskId] = None


@define
class EmitAnalyticsEvent(ProcessAction):
    """
    Emit this message to the event sender.
    Child -> Parent: to have the event from the child process propagated to the parent process.
    """

    event: AnalyticsEvent


class PoisonPill(ProcessAction):
    """
    Sentence the process to die.
    Parent -> Child: when the update process is interrupted.
    """


@define
class Result(ProcessAction):
    result: Union[GraphUpdate, str]

    def get_value(self) -> GraphUpdate:
        if isinstance(self.result, str):
            raise ImportAborted(self.result)
        else:
            return self.result


BatchSize = 100000


class DbUpdaterProcess(Process):
    """
    This update class implements Process and is supposed to run as separate process.
    Note: default starting method is supposed to be "spawn".

    This process has 2 queues to read input from and write output to.
    All elements in either queues are of type ProcessAction.

    The parent process should stream the raw commands of graph to this process via ReadElement objects.
    Once the MergeGraph action is received, the graph gets imported.
    From here the parent expects result messages from the child.
    All events happen in the child are forwarded to the parent via EmitEvent.
    Once the graph update is done, a result is send.
    The result is either an exception in case of failure or a graph update in success case.
    """

    def __init__(
        self,
        read_queue: Queue[ProcessAction],
        write_queue: Queue[ProcessAction],
        config: CoreConfig,
        graph_name: GraphName,
        change_id: str,
    ) -> None:
        super().__init__(name="merge_update")
        self.read_queue = read_queue
        self.write_queue = write_queue
        self.config = config
        self.change_id = change_id
        self.graph_name = graph_name

    def next_action(self) -> ProcessAction:
        try:
            # graph is read into memory. If the sender does not send data in a given amount of time,
            # we raise an exception and abort the update.
            return self.read_queue.get(True, 90)
        except Empty as ex:
            raise ImportAborted("Merge process did not receive any data for more than 90 seconds. Abort.") from ex

    async def merge_graph(self, db: DbAccess) -> GraphUpdate:  # type: ignore
        model_handler = ModelHandlerDB(db)
        model = await model_handler.load_model(self.graph_name)
        builder = GraphBuilder(model, self.change_id)
        nxt = self.next_action()
        if isinstance(nxt, ReadFile):
            for element in nxt.jsons():
                builder.add_from_json(element)
            nxt = self.next_action()
        elif isinstance(nxt, ReadElement):
            while isinstance(nxt, ReadElement):
                for element in nxt.jsons():
                    builder.add_from_json(element)
                log.debug(f"Read {int(BatchSize / 1000)}K elements in process")
                nxt = self.next_action()
        if isinstance(nxt, PoisonPill):
            log.debug("Got poison pill - going to die.")
            shutdown_process(0)
        elif isinstance(nxt, MergeGraph):
            log.debug("Graph read into memory")
            builder.check_complete()
            graphdb = db.get_graph_db(nxt.graph)
            outer_edge_db = db.deferred_outer_edge_db
            await graphdb.insert_usage_data(builder.usage)
            _, result = await graphdb.merge_graph(
                builder.graph,
                model,
                nxt.change_id,
                is_batch=nxt.is_batch,
                preserve_parent_structure=builder.organizational_root is not None,
            )
            # sizes of model entries have been adjusted during the merge. Update the model in the db.
            await model_handler.update_model(graphdb.name, list(model.kinds.values()), False)
            if nxt.task_id and builder.deferred_edges:
                await outer_edge_db.update(
                    DeferredOuterEdges(uuid_str(), nxt.change_id, nxt.task_id, utc(), nxt.graph, builder.deferred_edges)
                )
                log.debug(f"Updated {len(builder.deferred_edges)} pending outer edges for collect task {nxt.task_id}")
            return result

    async def setup_and_merge(self) -> GraphUpdate:
        sender = InMemoryEventSender()
        _, _, sdb = DbAccess.connect(self.config.args, timedelta(seconds=3), verify=self.config.run.verify)
        db = db_access(self.config, sdb, sender)
        result = await self.merge_graph(db)
        for event in sender.events:
            self.write_queue.put(EmitAnalyticsEvent(event))
        return result

    def run(self) -> None:
        try:
            # Entrypoint of the new service
            setup_process(self.config.args, self.config)
            log.info(f"Import process started: {self.pid}")
            result = asyncio.run(self.setup_and_merge())
            self.write_queue.put(Result(result))
            log.info(f"Update process done: {self.pid}. {result} Exit.")
            shutdown_process(0)
        except Exception as ex:
            # not all exceptions can be pickled. Use string representation.
            self.write_queue.put(Result(repr(ex)))
            log.error(f"Update process interrupted. Preemptive Exit. {ex}", exc_info=ex)
            shutdown_process(1)


@define
class GraphUpdateTask:
    """
    This class represents a graph update task that is queued for processing.
    The update is written to a temporary file.
    """

    db: GraphDB
    path: Path
    deadline: datetime
    maybe_batch: Optional[str]
    task_id: Optional[TaskId]

    def cleanup(self) -> None:
        shutil.rmtree(self.path.parent)


class GraphMerger(Service):
    def __init__(
        self,
        model_handler: ModelHandler,
        event_sender: AnalyticsEventSender,
        config: CoreConfig,
        message_bus: MessageBus,
    ) -> None:
        super().__init__()
        self.model_handler = model_handler
        self.event_sender = event_sender
        self.config = config
        self.message_bus = message_bus
        self.run_lock = asyncio.Lock()
        self.running_imports: Dict[TaskId, int] = defaultdict(int)
        self.update_queue: asyncio.Queue[GraphUpdateTask] = asyncio.Queue()
        self.concurrent_updates = asyncio.Semaphore(self.config.graph_update.parallel_imports)
        self.handler_task: Optional[Task[Any]] = None

    async def __process_item(self, item: GraphUpdateTask) -> Union[GraphUpdate, Exception]:
        log.info(f"Start processing graph merge from queue: {item}")
        try:
            return await self.__merge_graph_process(item.db, item.path, item.deadline, item.maybe_batch, item.task_id)
        except Exception as ex:
            log.error(f"Failed to process graph merge: {item}", exc_info=ex)
            return ex
        finally:
            item.cleanup()

    async def start(self) -> None:
        async def wait_for_update() -> None:
            log.info("Start waiting for graph updates")
            fl = (
                stream.call(self.update_queue.get)  # type: ignore
                | pipe.cycle()
                | pipe.map(self.__process_item, task_limit=self.config.graph_update.parallel_imports)  # type: ignore
            )
            with suppress(CancelledError):
                async with fl.stream() as streamer:
                    async for update in streamer:
                        if isinstance(update, GraphUpdate):
                            log.info(f"Finished spawned graph merge: {update}")

        self.handler_task = asyncio.create_task(wait_for_update())

    async def stop(self) -> None:
        if self.handler_task:
            self.handler_task.cancel()
            with suppress(Exception):
                await self.handler_task
        # cleanup all queued entries
        while not self.update_queue.empty():
            self.update_queue.get_nowait().cleanup()

    async def merge_graph(
        self,
        db: GraphDB,
        content: AsyncIterator[Union[bytes, Json]],
        max_wait: timedelta,
        maybe_batch: Optional[str],
        task_id: Optional[TaskId],
        wait_for_result: bool = False,
    ) -> Optional[GraphUpdate]:
        # increment count
        if task_id:
            async with self.run_lock:
                self.running_imports[task_id] += 1

        deadline = utc() + max_wait
        if wait_for_result:
            return await self.__merge_graph_process(db, content, deadline, maybe_batch, task_id)
        else:
            td = Path(tempfile.mkdtemp()) / "graph"
            log.debug(f"Do not merge directly. Write to temp file: {td}")
            async with aiofiles.open(td, "wb") as f:
                async for line in content:
                    await f.write(line if isinstance(line, bytes) else (json.dumps(line) + "\n").encode("utf-8"))
            await self.update_queue.put(GraphUpdateTask(db, td, deadline, maybe_batch, task_id))
            log.debug("GraphMerge operation queued.")
            return None

    async def __merge_graph_process(
        self,
        db: GraphDB,
        content: Union[AsyncIterator[Union[bytes, Json]], Path],
        deadline: datetime,
        maybe_batch: Optional[str],
        task_id: Optional[TaskId],
    ) -> GraphUpdate:
        async with self.concurrent_updates:
            change_id = maybe_batch if maybe_batch else uuid_str()
            write: Queue[ProcessAction] = Queue()
            read: Queue[ProcessAction] = Queue()
            updater = DbUpdaterProcess(write, read, self.config, db.name, change_id)  # the process communication queue
            stale = timedelta(seconds=5).total_seconds()  # consider dead communication after this amount of time
            dead_adjusted = False

            async def send_to_child(pa: ProcessAction) -> bool:
                alive = updater.is_alive()
                if alive:
                    await run_async(write.put, pa, True, stale)
                return alive

            def read_results() -> Task[GraphUpdate]:
                async def read_forever() -> GraphUpdate:
                    nonlocal deadline
                    nonlocal dead_adjusted
                    while utc() < deadline:
                        # After exit of updater: adjust the deadline once
                        if not updater.is_alive() and not dead_adjusted:
                            log.debug("Import process done or dead. Adjust deadline.")
                            deadline = utc() + timedelta(seconds=30)
                            dead_adjusted = True
                        try:
                            action = await run_async(read.get, True, stale)
                            if isinstance(action, EmitAnalyticsEvent):
                                await self.event_sender.capture([action.event])
                            elif isinstance(action, Result):
                                return action.get_value()
                        except Empty:
                            # empty is fine
                            pass
                    raise ImportAborted(f"Import process died or deadline exceeded. (ExitCode: {updater.exitcode})")

                return asyncio.create_task(read_forever())

            task: Optional[Task[GraphUpdate]] = None
            result: Optional[GraphUpdate] = None
            try:
                reset_process_start_method()  # other libraries might have tampered the value in the mean time
                updater.start()
                task = read_results()  # concurrently read result queue
                # Either send a file or stream the content directly
                if isinstance(content, Path):
                    await send_to_child(ReadFile(content, task_id))
                else:
                    chunked: Stream[List[Union[bytes, Json]]] = stream.chunks(content, BatchSize)  # type: ignore
                    async with chunked.stream() as streamer:
                        async for lines in streamer:
                            if not await send_to_child(ReadElement(lines, task_id)):
                                # in case the child is dead, we should stop
                                break
                await send_to_child(MergeGraph(db.name, change_id, maybe_batch is not None, task_id))
                result = await task  # wait for final result
                await self.model_handler.load_model(db.name, force=True)  # reload model to get the latest changes
                return result
            finally:
                # update running imports and send event if completed
                if task_id:
                    async with self.run_lock:
                        self.running_imports[task_id] -= 1
                        if self.running_imports[task_id] == 0:
                            del self.running_imports[task_id]
                            await self.message_bus.emit_event(CoreMessage.GraphMergeCompleted, dict(task_id=task_id))
                if task is not None and not task.done():
                    task.cancel()
                if not result:
                    # make sure the change is aborted in case of transaction
                    log.info(f"Abort update manually: {change_id}")
                    await db.abort_update(change_id)
                await send_to_child(PoisonPill())
                await run_async(updater.join, stale)
                if updater.is_alive():
                    log.warning(f"Process is still alive after poison pill. Terminate process {updater.pid}")
                    with suppress(Exception):
                        updater.terminate()
                    await asyncio.sleep(3)
                if updater.is_alive():
                    log.warning(f"Process is still alive after terminate. Kill process {updater.pid}")
                    with suppress(Exception):
                        updater.kill()
                    await run_async(updater.join)
                if not updater.is_alive():
                    with suppress(Exception):
                        updater.close()
