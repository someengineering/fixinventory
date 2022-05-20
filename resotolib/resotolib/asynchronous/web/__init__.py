from typing import Callable, Awaitable
from aiohttp.web import Request, StreamResponse


RequestHandler = Callable[[Request], Awaitable[StreamResponse]]
Middleware = Callable[[Request, RequestHandler], Awaitable[StreamResponse]]
