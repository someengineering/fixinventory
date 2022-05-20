import asyncio
import json
import logging
import uuid
from asyncio import Future
from contextlib import suppress
from typing import Any, Dict, Tuple, Callable, Awaitable

from aiohttp import web, WSMessage, WSMsgType
from aiohttp.web import Request, StreamResponse
from resotolib.asynchronous.web.auth import auth_handler

from resotolog.logs.log_handler import LogHandler
from resotolog.model import LogConfig, Message
from resotolog.web.directives import error_handler

log = logging.getLogger(__name__)

AlwaysAllowed = {"/metrics", "/api-doc.*", "/system/.*"}


class Api:
    def __init__(self, config: LogConfig, handler: LogHandler) -> None:
        self.handler = handler
        self.app = web.Application(
            # note on order: the middleware is passed in the order provided.
            middlewares=[auth_handler(config.args.psk, AlwaysAllowed), error_handler()]
        )
        self.in_shutdown = False
        self.websocket_handler: Dict[str, Tuple[Future[Any], web.WebSocketResponse]] = {}
        self.__add_routes("")  # bind to root

    def __add_routes(self, prefix: str) -> None:
        self.app.add_routes(
            [
                web.get(prefix + "/system/ping", self.ping),
                web.get(prefix + "/system/ready", self.ready),
                web.get(prefix + "/ingest", self.log_events_in),
                web.get(prefix + "/logs", self.log_events_out),
            ]
        )

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        if not self.in_shutdown:
            self.in_shutdown = True
            for ws_id in list(self.websocket_handler):
                await self.clean_ws_handler(ws_id)

    async def clean_ws_handler(self, ws_id: str) -> None:
        with suppress(Exception):
            handler = self.websocket_handler.get(ws_id)
            if handler:
                self.websocket_handler.pop(ws_id, None)
                future, ws = handler
                future.cancel()
                log.info(f"Cleanup ws handler: {ws_id} ({len(self.websocket_handler)} active)")
                if not ws.closed:
                    await ws.close()

    @staticmethod
    def forward(to: str) -> Callable[[Request], Awaitable[StreamResponse]]:
        async def forward_to(_: Request) -> StreamResponse:
            return web.HTTPFound(to)

        return forward_to

    @staticmethod
    async def ping(_: Request) -> StreamResponse:
        return web.HTTPOk(text="pong", content_type="text/plain")

    @staticmethod
    async def ready(_: Request) -> StreamResponse:
        return web.HTTPOk(text="ok")

    async def log_events_in(self, request: Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        wsid = str(uuid.uuid1())

        async def receive() -> None:
            try:
                async for msg in ws:
                    if isinstance(msg, WSMessage) and msg.type == WSMsgType.CLOSED or msg.type == WSMsgType.ERROR:
                        break  # end the session
                    elif isinstance(msg, WSMessage) and msg.type == WSMsgType.TEXT and len(msg.data.strip()) > 0:
                        log.info(f"Incoming message: type={msg.type} data={msg.data} extra={msg.extra}")
                        message = Message(json.loads(msg.data))
                        await self.handler.add_entry(message)
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Receive: message listener {wsid}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(wsid)

        to_wait = asyncio.create_task(receive())
        self.websocket_handler[wsid] = (to_wait, ws)
        await to_wait
        return ws

    async def log_events_out(self, request: Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        wsid = str(uuid.uuid1())

        async def receive() -> None:
            try:
                async for msg in ws:
                    if isinstance(msg, WSMessage) and msg.type == WSMsgType.TEXT and len(msg.data.strip()) > 0:
                        log.info(f"Incoming message: type={msg.type} data={msg.data} extra={msg.extra}")
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Receive: message listener {wsid}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(wsid)

        async def send() -> None:
            try:
                async with self.handler.subscribe(wsid) as events:
                    while True:
                        message: Message = await events.get()
                        await ws.send_str(json.dumps(message.payload) + "\n")
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Send: message listener {wsid}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(wsid)

        to_wait = asyncio.gather(asyncio.create_task(receive()), asyncio.create_task(send()))
        self.websocket_handler[wsid] = (to_wait, ws)
        await to_wait
        return ws
