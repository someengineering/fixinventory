from typing import Callable, Awaitable
from aiohttp.web import Request, StreamResponse

from resotocore.dependencies import TenantDependencies

RequestHandler = Callable[[Request], Awaitable[StreamResponse]]
TenantRequestHandler = Callable[[Request, TenantDependencies], Awaitable[StreamResponse]]
Middleware = Callable[[Request, RequestHandler], Awaitable[StreamResponse]]
