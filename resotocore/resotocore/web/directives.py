import logging
from re import RegexFlag, fullmatch
from typing import Optional, Callable, Awaitable

from aiohttp.hdrs import METH_OPTIONS
from aiohttp.web import HTTPRedirection, HTTPNotFound, HTTPBadRequest, HTTPException, HTTPNoContent
from aiohttp.web_exceptions import HTTPServiceUnavailable
from aiohttp.web_middlewares import middleware
from aiohttp.web_request import Request
from aiohttp.web_response import StreamResponse

from resotocore import version
from resotocore.analytics import AnalyticsEventSender, CoreEvent
from resotocore.core_config import CoreConfig
from resotocore.error import NotFoundError, ClientError
from resotocore.metrics import RequestInProgress, RequestLatency, RequestCount, perf_now
from resotocore.web import RequestHandler, api  # pylint: disable=unused-import # prevent circular import

log = logging.getLogger(__name__)


def enable_compression(request: Request, response: StreamResponse) -> None:
    # The UI can not handle compressed responses. Allow compression only if requested by somebody else
    if "resotoui-via" not in request.headers:
        response.enable_compression()


async def on_response_prepare(request: Request, response: StreamResponse) -> None:
    # Headers are required for the UI to work, since it uses SharedArrayBuffer.
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer
    if fullmatch("/ui/.*", request.path, RegexFlag.IGNORECASE):
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

    # In case of a CORS request: a response header to allow the origin is required
    if request.headers.get("sec-fetch-mode") == "cors":
        response.headers["Access-Control-Allow-Origin"] = request.headers.get("origin", "*")


@middleware
async def cors_handler(request: Request, handler: RequestHandler) -> StreamResponse:
    if request.method == METH_OPTIONS:
        return HTTPNoContent(
            headers={
                # allow origin of request or all if none is defined.
                "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
                # allow the requested method or all if none is defined.
                "Access-Control-Allow-Methods": request.headers.get("access-control-request-method", "*"),
                # allow the requested header names or all if none is defined.
                "Access-Control-Allow-Headers": request.headers.get("access-control-request-headers", "*"),
                # allow the client to cache this result
                "Access-Control-Max-Age": "86400",  # allow caching for one day
            }
        )
    else:
        return await handler(request)


@middleware
async def metrics_handler(request: Request, handler: RequestHandler) -> StreamResponse:
    request["start_time"] = perf_now()
    RequestInProgress.labels(request.path, request.method).inc()  # type: ignore
    try:
        response = await handler(request)
        RequestCount.labels(request.method, request.path, response.status).inc()
        return response
    except HTTPException as ex:
        RequestCount.labels(request.method, request.path, ex.status).inc()
        raise ex
    finally:
        resp_time = perf_now() - request["start_time"]
        RequestLatency.labels(request.path).observe(resp_time)  # type: ignore
        RequestInProgress.labels(request.path, request.method).dec()  # type: ignore


def error_handler(
    config: CoreConfig, event_sender: AnalyticsEventSender
) -> Callable[[Request, RequestHandler], Awaitable[StreamResponse]]:
    is_debug = (logging.root.level < logging.INFO) or config.runtime.debug

    def exc_info(ex: Exception) -> Optional[Exception]:
        return ex if is_debug else None

    @middleware
    async def error_handler_middleware(request: Request, handler: RequestHandler) -> StreamResponse:
        try:
            return await handler(request)
        except HTTPRedirection as e:
            # redirects are implemented as exceptions in aiohttp for whatever reason...
            raise e
        except NotFoundError as e:
            kind = type(e).__name__
            message = f"Error: {kind}\nMessage: {str(e)}"
            log.info(f"Request {request} has failed with exception: {message}", exc_info=exc_info(e))
            raise HTTPNotFound(text=message) from e
        except (ClientError, AttributeError) as e:
            kind = type(e).__name__
            ex_str = str(e)
            message = f"Error: {kind}\nMessage: {ex_str}"
            log.info(f"Request {request} has failed with exception: {message}", exc_info=exc_info(e))
            await event_sender.core_event(
                CoreEvent.ClientError, {"version": version(), "kind": kind, "message": ex_str}
            )
            raise HTTPBadRequest(text=message) from e
        except Exception as e:
            kind = type(e).__name__
            ex_str = str(e)
            message = f"Error: {kind}\nMessage: {ex_str}"
            log.warning(f"Request {request} has failed with exception: {message}", exc_info=exc_info(e))
            await event_sender.core_event(
                CoreEvent.ServerError, {"version": version(), "kind": kind, "message": ex_str}
            )
            raise HTTPBadRequest(text=message) from e

    return error_handler_middleware


def default_middleware(api_handler: "api.Api") -> Callable[[Request, RequestHandler], Awaitable[StreamResponse]]:
    @middleware
    async def default_handler(request: Request, handler: RequestHandler) -> StreamResponse:
        if api_handler.in_shutdown:
            # We are currently in shutdown: inform the caller to retry later.
            return HTTPServiceUnavailable(headers={"Retry-After": "5"})
        else:
            return await handler(request)

    return default_handler
