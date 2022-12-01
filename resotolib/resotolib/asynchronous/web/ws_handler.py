import asyncio
from asyncio import Queue, Future
from contextlib import suppress
from typing import (
    Callable,
    Awaitable,
    AsyncContextManager,
    Any,
    Optional,
    Sequence,
    Dict,
    Tuple,
    TypeVar,
)
from uuid import uuid1

import jsons
from aiohttp import WSMessage, WSMsgType
from aiohttp.web import Request, WebSocketResponse

from resotolib.logger import log

WSHandler = Dict[str, Tuple[Future[Any], WebSocketResponse]]
T = TypeVar("T")


async def clean_ws_handler(ws_id: str, websocket_handler: WSHandler) -> None:
    with suppress(Exception):
        handler = websocket_handler.get(ws_id)
        if handler:
            websocket_handler.pop(ws_id, None)
            future, ws = handler
            future.cancel()
            log.info(f"Cleanup ws handler: {ws_id} ({len(websocket_handler)} active)")
            if not ws.closed:
                await ws.close()


def js_str(a: Any) -> str:
    return jsons.dumps(a, strip_privates=True)


async def accept_websocket(
    request: Request,
    *,
    handle_incoming: Callable[[str], Awaitable[None]],
    websocket_handler: WSHandler,
    outgoing_context: Optional[Callable[[], AsyncContextManager[Queue[T]]]] = None,
    initial_messages: Optional[Sequence[Any]] = None,
    outgoing_fn: Callable[[T], str] = js_str,
) -> WebSocketResponse:
    ws = WebSocketResponse(autoping=True, heartbeat=20)
    await ws.prepare(request)
    wsid = str(uuid1())

    # in case we wait for an initial authorization message, only wait for a limited amount of tine
    async def wait_for_authorization() -> None:
        counter = 10
        while request.get("authorized", False) is not True and counter >= 0:
            await asyncio.sleep(1)
            counter -= 1
        if counter <= 0:
            log.info(f"Wait for authorization: message listener {wsid}: Timeout. Hang up.")
            await clean_ws_handler(wsid, websocket_handler)

    async def receive() -> None:
        try:
            async for msg in ws:
                if isinstance(msg, WSMessage) and msg.type in (
                    WSMsgType.ERROR,
                    WSMsgType.CLOSE,
                    WSMsgType.CLOSED,
                ):
                    break
                elif isinstance(msg, WSMessage) and msg.type == WSMsgType.TEXT and len(msg.data.strip()) > 0:
                    log.debug(f"Incoming message: type={msg.type} data={msg.data} extra={msg.extra}")
                    await handle_incoming(msg.data)
        except Exception as ex:
            # do not allow any exception - it will destroy the async fiber and cleanup
            log.info(f"Receive: message listener {wsid}: {ex}. Hang up.")
        finally:
            await clean_ws_handler(wsid, websocket_handler)

    async def send(ctx: Callable[[], AsyncContextManager[Queue[T]]]) -> None:
        try:
            # wait for the request to become authorized, before we will send any message
            while request.get("authorized", False) is not True:
                await asyncio.sleep(1)
            # send all initial messages
            if initial_messages:
                for msg in initial_messages:
                    await ws.send_str(outgoing_fn(msg) + "\n")
            # attach to the queue and wait for messages
            async with ctx() as events:
                while True:
                    event = await events.get()
                    await ws.send_str(outgoing_fn(event) + "\n")
        except Exception as ex:
            # do not allow any exception - it will destroy the async fiber and cleanup
            log.info(f"Send: message listener {wsid}: {ex}. Hang up.")
        finally:
            await clean_ws_handler(wsid, websocket_handler)

    tasks = [asyncio.create_task(receive())]
    if outgoing_context is not None:
        tasks.append(asyncio.create_task(send(outgoing_context)))
    if request.get("authorized", False) is not True:
        tasks.append(asyncio.create_task(wait_for_authorization()))

    to_wait = asyncio.gather(*tasks)
    websocket_handler[wsid] = (to_wait, ws)
    await to_wait
    return ws
