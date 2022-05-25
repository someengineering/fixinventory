from asyncio import Future
from functools import partial
from typing import Any, Dict, Tuple, Callable, Awaitable
from uuid import uuid1
import os

import jsons
from aiohttp import web
from aiohttp.web import Request, StreamResponse, WebSocketResponse
from resotolib.asynchronous.web.auth import auth_handler
from resotolib.asynchronous.web.ws_handler import accept_websocket, clean_ws_handler
from resotolib.log import Event
from resotolib.logger import log

from resotoeventlog.logs.log_handler import LogHandler
from resotoeventlog.model import LogConfig
from resotoeventlog.web.directives import error_handler

AlwaysAllowed = {"/metrics", "/api-doc.*", "/system/.*", "/ui.*"}


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
        ui_path = os.path.abspath(os.path.dirname(__file__) + "/../ui")

        self.app.add_routes(
            [
                web.get(prefix + "/system/ping", self.ping),
                web.get(prefix + "/system/ready", self.ready),
                web.get(prefix + "/ingest", self.events_in),
                web.get(prefix + "/events", self.events_out),
                web.static(prefix + "/ui", ui_path),
                web.get(prefix, self.forward("/ui/index.html")),
            ]
        )

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        if not self.in_shutdown:
            self.in_shutdown = True
            for ws_id in list(self.websocket_handler):
                await clean_ws_handler(ws_id, self.websocket_handler)

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
        async def handle_message(msg: str) -> None:
            try:
                event = jsons.loads(msg, Event)
                await self.handler.add_event(event)
            except Exception as e:
                log.error(f"Failed to handle event: {e}")

        return await accept_websocket(
            request,
            handle_incoming=handle_message,
            websocket_handler=self.websocket_handler,
        )

    async def events_out(self, request: Request) -> WebSocketResponse:
        show = request.query["show"].split(",") if "show" in request.query else ["*"]
        last = int(request.query.get("last", "100"))
        buffer = int(request.query.get("buffer", "1000"))
        listener_id = str(uuid1())

        async def handle_message(msg: str) -> None:
            pass

        return await accept_websocket(
            request,
            handle_incoming=handle_message,
            websocket_handler=self.websocket_handler,
            outgoing_context=partial(self.handler.subscribe, listener_id, show, last, buffer),
        )
