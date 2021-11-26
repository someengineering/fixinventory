import logging
from argparse import Namespace
from typing import Optional, Callable, Awaitable

from aiohttp.web import HTTPRedirection, HTTPNotFound, HTTPBadRequest, HTTPException
from aiohttp.web_middlewares import middleware
from aiohttp.web_request import Request
from aiohttp.web_response import StreamResponse

from core import version
from core.analytics import AnalyticsEventSender, CoreEvent
from core.error import NotFoundError, ClientError
from core.metrics import RequestInProgress, RequestLatency, RequestCount, perf_now
from core.web import RequestHandler

log = logging.getLogger(__name__)


@middleware
async def metrics_handler(request: Request, handler: RequestHandler) -> StreamResponse:
    request["start_time"] = perf_now()
    RequestInProgress.labels(request.path, request.method).inc()
    try:
        response = await handler(request)
        RequestCount.labels(request.method, request.path, response.status).inc()
        return response
    except HTTPException as ex:
        RequestCount.labels(request.method, request.path, ex.status).inc()
        raise ex
    finally:
        resp_time = perf_now() - request["start_time"]
        RequestLatency.labels(request.path).observe(resp_time)
        RequestInProgress.labels(request.path, request.method).dec()


def error_handler(
    args: Namespace, event_sender: AnalyticsEventSender
) -> Callable[[Request, RequestHandler], Awaitable[StreamResponse]]:
    is_debug = (logging.root.level < logging.INFO) or args.debug

    def exc_info(ex: Exception) -> Optional[Exception]:
        return ex if is_debug else None

    @middleware
    async def error_handler_middleware(request: Request, handler: RequestHandler) -> StreamResponse:
        try:
            response = await handler(request)
            return response
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
