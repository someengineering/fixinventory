import asyncio
import uuid
from asyncio import Future
from contextlib import suppress
from typing import Any, Dict, Tuple, Callable, Awaitable

import jsons
from aiohttp import web, WSMessage, WSMsgType
from aiohttp.web import Request, StreamResponse, WebSocketResponse
from resotolib.asynchronous.web.auth import auth_handler
from resotolib.log import Event
from resotolib.logger import log

from resotolog.logs.log_handler import LogHandler
from resotolog.model import LogConfig
from resotolog.web.directives import error_handler

AlwaysAllowed = {"/metrics", "/api-doc.*", "/system/.*"}


class Api:
    def __init__(self, config: LogConfig, handler: LogHandler) -> None:
        self.handler = handler
        self.app = web.Application(
            # note on order: the middleware is passed in the order provided.
            middlewares=[auth_handler(config.args.psk, AlwaysAllowed), error_handler()]
        )
        self.in_shutdown = False
        self.websocket_handler: Dict[str, Tuple[Future[Any], WebSocketResponse]] = {}
        self.__add_routes("")  # bind to root

    def __add_routes(self, prefix: str) -> None:
        self.app.add_routes(
            [
                web.get(prefix + "/system/ping", self.ping),
                web.get(prefix + "/system/ready", self.ready),
                web.get(prefix + "/ingest", self.events_in),
                web.get(prefix + "/events", self.events_out),
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

    async def events_in(self, request: Request) -> WebSocketResponse:
        ws = WebSocketResponse()
        await ws.prepare(request)
        wsid = str(uuid.uuid1())

        async def receive() -> None:
            try:
                async for msg in ws:
                    if isinstance(msg, WSMessage) and msg.type == WSMsgType.CLOSED or msg.type == WSMsgType.ERROR:
                        break  # end the session
                    elif isinstance(msg, WSMessage) and msg.type == WSMsgType.TEXT and len(msg.data.strip()) > 0:
                        log.debug(f"Incoming message: type={msg.type} data={msg.data} extra={msg.extra}")
                        message = jsons.loads(msg.data, Event)
                        await self.handler.add_event(message)
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Receive: message listener {wsid}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(wsid)

        to_wait = asyncio.create_task(receive())
        self.websocket_handler[wsid] = (to_wait, ws)
        await to_wait
        return ws

    async def events_out(self, request: Request) -> WebSocketResponse:
        ws = WebSocketResponse()
        await ws.prepare(request)
        wsid = str(uuid.uuid1())
        show = request.query["show"].split(",") if "show" in request.query else ["*"]
        last = int(request.query.get("last", "100"))
        buffer = int(request.query.get("buffer", "1000"))

        async def receive() -> None:
            try:
                async for msg in ws:
                    if isinstance(msg, WSMessage) and msg.type == WSMsgType.TEXT and len(msg.data.strip()) > 0:
                        log.debug(f"Incoming message: type={msg.type} data={msg.data} extra={msg.extra}")
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Receive: message listener {wsid}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(wsid)

        async def send() -> None:
            try:
                async with self.handler.subscribe(
                    wsid,
                    channels=show,
                    show_last=last,
                    queue_size=buffer,
                ) as events:
                    while True:
                        event: Event = await events.get()
                        await ws.send_str(jsons.dumps(event) + "\n")
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Send: message listener {wsid}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(wsid)

        to_wait = asyncio.gather(asyncio.create_task(receive()), asyncio.create_task(send()))
        self.websocket_handler[wsid] = (to_wait, ws)
        await to_wait
        return ws
