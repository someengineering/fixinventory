import asyncio
import logging
from asyncio import Task, Future
from collections import deque
from datetime import timedelta
from logging import StreamHandler, LogRecord
from ssl import SSLContext
from typing import Optional, TypeVar, Mapping, Union

from aiohttp import ClientSession, ClientWebSocketResponse, Fingerprint
from aiohttp.typedefs import LooseHeaders

from resotocore.util import Periodic
from resotolib.logger import JsonFormatter

log = logging.getLogger(__name__)
T = TypeVar("T")


class LogStreamAsync:
    def __init__(
        self,
        url: str,
        max_outstanding: int,
        frequency: timedelta,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[LooseHeaders] = None,
        ssl: Union[SSLContext, bool, None, Fingerprint] = None,
    ) -> None:
        self.url = url
        self.connection_args = dict(params=params, headers=headers, ssl=ssl)
        self.buffer: deque[str] = deque(maxlen=max_outstanding)
        self.queue = asyncio.Queue()
        self.periodic = Periodic(
            "flush log messages", self.__shuffle_messages, frequency
        )
        self.task: Optional[Task] = None
        self.do_work: Optional[Future] = None

    async def start(self) -> None:
        log.info("Start log streamer")
        # create future that can be called from non-async context
        self.do_work = asyncio.get_event_loop().create_future()
        self.do_work.add_done_callback(self.stop)
        await self.periodic.start()
        self.task = asyncio.create_task(self.__send_log_messages())

    async def stop(self) -> None:
        log.info("Stopping log streamer")
        await self.periodic.stop()
        self.task.cancel()
        await self.task

    async def __shuffle_messages(self) -> None:
        while self.buffer:
            msg = self.buffer.popleft()
            await self.queue.put(msg)

    async def __send_log_messages(self) -> None:
        async with ClientSession() as session:
            while not self.do_work.done():
                try:
                    log.info("Try to connect to log streamer")
                    async with session.ws_connect(
                        self.url, **self.connection_args
                    ) as ws:
                        await self.__send_with_connection(ws)
                except Exception as e:
                    log.warning(
                        "Could not send log messages to resotolog. Retry."
                    )

    async def __send_with_connection(self, ws: ClientWebSocketResponse) -> None:
        while True:
            msg = await self.queue.get()
            await ws.send_str(msg + "\n")


class BufferedHandler(StreamHandler):
    def __init__(self, process: str, streamer: LogStreamAsync, json_format: Optional[JsonFormatter] = None, attach: bool = True) -> None:
        super().__init__(None)
        if json_format is None:
            json_format = JsonFormatter(
                {
                    "timestamp": "asctime",
                    "level": "levelname",
                    "message": "message",
                    "pid": "process",
                    "thread": "threadName",
                },
                static_values={"process": process},
            )
        self.streamer = streamer
        self.formatter = json_format
        self.attach() if attach else None

    def emit(self, record: LogRecord) -> None:
        msg = self.format(record)
        self.streamer.buffer.append(msg)

    def attach(self) -> None:
        already_attached: bool = False
        # safety check, that only one handler is attached
        for handler in logging.root.handlers:
            if isinstance(handler, BufferedHandler):
                if handler is self:
                    already_attached = True
                else:
                    raise RuntimeError("Only one BufferedHandler allowed")
        if not already_attached:
            logging.root.addHandler(self)

    def detach(self) -> None:
        logging.root.removeHandler(self)


class ShipLogsSync(BufferedHandler):
    def __init__(self, process: str, streamer: LogStreamAsync, json_format: Optional[JsonFormatter]) -> None:
        super().__init__(process, streamer, json_format)
        # only here to get the result of the start task (will yield a warning otherwise)
        self.start_future: Optional[Future[None]] = None

    def start(self) -> None:
        if self.start_future is None:
            loop = asyncio.get_event_loop()
            self.start_future = asyncio.run_coroutine_threadsafe(
                self.streamer.start(), loop
            )

    def stop(self) -> None:
        if self.streamer.do_work and not self.streamer.do_work.done():
            self.streamer.do_work.set_result(None)
            self.start_future = None


class ShipLogsAsync(BufferedHandler):
    async def start(self) -> None:
        await self.streamer.start()

    async def stop(self) -> None:
        await self.streamer.stop()

