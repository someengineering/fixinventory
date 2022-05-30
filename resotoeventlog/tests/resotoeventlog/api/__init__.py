import asyncio
import json
import logging
from asyncio import Future
from typing import Dict, Optional, AsyncGenerator, List, Tuple, Any, Callable

import jsons
from aiohttp import ClientSession
from resotolib.log import Event
from resotolib.types import Json

log: logging.Logger = logging.getLogger(__name__)


class EventLogClient:
    def __init__(self, url: str, client_session: ClientSession):
        self.resotocore_url = url
        self.client_session = client_session

    async def _get(
        self,
        path: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        async with self.client_session.get(self.resotocore_url + path, params=params, headers=headers) as response:
            if response.status == 200:
                return await response.text()
            else:
                raise AttributeError(response.text)

    async def ping(self) -> str:
        return await self._get("/system/ping")

    async def ready(self) -> str:
        return await self._get("/system/ready", headers={"Accept": "text/plain"})

    async def events(self) -> Tuple[Callable[[], AsyncGenerator[Tuple[int, Json], None]], Future[Any]]:
        ft = asyncio.get_event_loop().create_future()

        async def generate() -> AsyncGenerator[Tuple[int, Json], None]:
            async with self.client_session.ws_connect(self.resotocore_url + "/events") as ws:
                count = 0
                async for msg in ws:
                    count += 1
                    # noinspection PyUnresolvedReferences
                    yield count, json.loads(msg.data)
                    if ft.done():
                        break

        return generate, ft

    async def ingest(self, events: List[Event]) -> None:
        async with self.client_session.ws_connect(self.resotocore_url + "/ingest") as ws:
            for event in events:
                await ws.send_json(jsons.dump(event))
