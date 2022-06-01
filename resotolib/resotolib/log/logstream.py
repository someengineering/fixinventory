import asyncio
import logging
from abc import ABC
from asyncio import Task, Future
from collections import deque
from datetime import timedelta
from logging import StreamHandler, LogRecord
from ssl import SSLContext
from typing import Optional, TypeVar, Mapping, Union

import jsons
from aiohttp import ClientSession, ClientWebSocketResponse, Fingerprint
from aiohttp.typedefs import LooseHeaders

from resotolib.asynchronous.periodic import Periodic
from resotolib.log import Event, Severity
from resotolib.logger import JsonFormatter

log = logging.getLogger(__name__)
T = TypeVar("T")


class EventStreamer:
    def __init__(
        self,
        url: str,
        max_outstanding: int = 10000,
        frequency: timedelta = timedelta(seconds=1),
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[LooseHeaders] = None,
        ssl: Union[SSLContext, bool, None, Fingerprint] = None,
    ) -> None:
        self.url = url
        self.connection_args = dict(params=params, headers=headers, ssl=ssl)
        self.buffer: deque[str] = deque(maxlen=max_outstanding)
        self.queue = asyncio.Queue()
        self.periodic = Periodic("flush log messages", self.__shuffle_messages, frequency)
        self.task: Optional[Task] = None

    async def start(self) -> None:
        log.info("Start log streamer")
        await self.periodic.start()
        self.task = asyncio.create_task(self.__send_log_messages())

    async def stop(self) -> None:
        log.info("Stopping log streamer")
        await self.periodic.stop()
        self.task.cancel()
        await self.task

    def send_event(self, event: Event):
        self.buffer.append(jsons.dumps(event))

    async def __shuffle_messages(self) -> None:
        while self.buffer:
            msg = self.buffer.popleft()
            await self.queue.put(msg)

    async def __send_log_messages(self) -> None:
        async with ClientSession() as session:
            while True:
                try:
                    log.debug("Try to connect to log streamer")
                    async with session.ws_connect(self.url, **self.connection_args) as ws:
                        await self.__send_with_connection(ws)
                except Exception as e:
                    await asyncio.sleep(3)
                    log.warning(f"Could not send log messages to resotoeventlog. Retry. {e}")

    async def __send_with_connection(self, ws: ClientWebSocketResponse) -> None:
        while True:
            msg = await self.queue.get()
            await ws.send_str(msg + "\n")


level_to_severity = {
    "CRITICAL": Severity.critical,
    "ERROR": Severity.error,
    "WARN": Severity.warn,
    "WARNING": Severity.warn,
    "INFO": Severity.info,
    "DEBUG": Severity.debug,
}

default_log_props = {"message": "message", "pid": "process", "thread": "threadName"}


class LogStreamHandler(StreamHandler):
    def __init__(
        self,
        process: str,
        streamer: EventStreamer,
        fmt_dict: Optional[Mapping[str, str]] = None,
        attach: bool = True,
    ) -> None:
        super().__init__(None)
        self.streamer = streamer
        self.attach() if attach else None
        self.process = process
        self.js_formatter = JsonFormatter(fmt_dict or default_log_props)

    def emit(self, record: LogRecord) -> None:
        payload = self.js_formatter.formatJsonMessage(record)
        self.streamer.send_event(
            Event(
                self.process,
                int(record.created),
                level_to_severity.get(record.levelname, Severity.info),
                "log",
                payload,
            )
        )

    def attach(self) -> None:
        already_attached: bool = False
        # safety check, that only one handler is attached
        for handler in logging.root.handlers:
            if isinstance(handler, LogStreamHandler):
                if handler is self:
                    already_attached = True
                else:
                    raise RuntimeError("Only one BufferedHandler allowed")
        if not already_attached:
            logging.root.addHandler(self)

    def detach(self) -> None:
        logging.root.removeHandler(self)


class EventStream(ABC):
    def send_event(self, event: Event) -> None:
        pass


class EventStreamSync(EventStream):
    def __enter__(self) -> None:
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


class EventStreamAsync(EventStream):
    async def __aenter__(self):
        await self.start()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class EventStreamBase(ABC):
    def __init__(self, streamer: EventStreamer, log_handler: LogStreamHandler) -> None:
        self.log_handler = log_handler
        self.streamer = streamer

    def send_event(self, event: Event) -> None:
        self.streamer.send_event(event)


class EventStreamSyncService(EventStreamBase, EventStreamSync):
    def __init__(self, streamer: EventStreamer, log_handler: LogStreamHandler) -> None:
        super().__init__(streamer, log_handler)
        # only here to get the result of the start task (will yield a warning otherwise)
        self.start_future: Optional[Future[None]] = None
        self.stop_future: Optional[Future[None]] = None

    def start(self) -> None:
        if self.start_future is None:
            loop = asyncio.get_event_loop()
            self.start_future = asyncio.run_coroutine_threadsafe(self.streamer.start(), loop)

    def stop(self) -> None:
        if self.start_future is not None:
            loop = asyncio.get_event_loop()
            self.stop_future = asyncio.run_coroutine_threadsafe(self.streamer.stop(), loop)
            self.start_future = None


class EventStreamAsyncService(EventStreamBase, EventStreamAsync):
    async def start(self) -> None:
        await self.streamer.start()

    async def stop(self) -> None:
        await self.streamer.stop()


class NoEventStreamSync(EventStreamSync):
    pass


class NoEventStreamAsync(EventStreamAsync):
    pass
