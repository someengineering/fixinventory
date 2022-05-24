import logging
from typing import Optional

from aiohttp.web import Request, StreamResponse
from aiohttp.web import middleware
from aiohttp.web_exceptions import (
    HTTPRedirection,
    HTTPBadRequest,
)

from resotolib.asynchronous.web import RequestHandler, Middleware

log = logging.getLogger(__name__)


def error_handler() -> Middleware:
    is_debug = logging.root.level < logging.INFO

    def exc_info(ex: Exception) -> Optional[Exception]:
        return ex if is_debug else None

    @middleware
    async def error_handler_middleware(request: Request, handler: RequestHandler) -> StreamResponse:
        try:
            return await handler(request)
        except HTTPRedirection as e:
            # redirects are implemented as exceptions in aiohttp for whatever reason...
            raise e
        except Exception as e:
            kind = type(e).__name__
            ex_str = str(e)
            message = f"Error: {kind}\nMessage: {ex_str}"
            log.warning(
                f"Request {request} has failed with exception: {message}",
                exc_info=exc_info(e),
            )
            raise HTTPBadRequest(text=message) from e

    return error_handler_middleware
