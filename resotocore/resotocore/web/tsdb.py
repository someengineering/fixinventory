import logging
from functools import lru_cache
from socket import gethostname
from typing import Callable, Awaitable

from aiohttp import ClientConnectionError
from aiohttp.web import HTTPNotFound, Request, StreamResponse
from aiohttp.web_exceptions import HTTPBadGateway

from resotocore.web import api  # pylint: disable=unused-import # prevent circular import
from resotocore.web.directives import enable_compression

log = logging.getLogger(__name__)


@lru_cache(1)
def hostname() -> str:
    try:
        return gethostname()
    except Exception:
        return "localhost"


# Proxy request to configured tsdb endpoint
def tsdb(api_handler: "api.Api") -> Callable[[Request], Awaitable[StreamResponse]]:
    async def proxy_request(request: Request) -> StreamResponse:
        if api_handler.config.api.tsdb_proxy_url:
            in_headers = request.headers.copy()
            # since we stream the content (chunked), we are not allowed to set the content length.
            in_headers.popall("Content-Length", "none")
            in_headers.popall("Content-Encoding", "none")
            url = f'{api_handler.config.api.tsdb_proxy_url}/{request.match_info["tail"]}'
            try:
                async with api_handler.session.request(
                    request.method,
                    url,
                    params=request.query,
                    headers=in_headers,
                    compress="deflate",
                    data=request.content,
                    ssl=api_handler.cert_handler.client_context,
                ) as cr:
                    log.info(f"Proxy tsdb request to: {url} resulted in status={cr.status}")
                    headers = cr.headers.copy()
                    # since we stream the content (chunked), we are not allowed to set the content length.
                    headers.popall("Content-Length", "none")
                    headers.popall("Content-Encoding", "none")
                    via = f"{request.version.major}.{request.version.minor} {hostname()}"
                    headers["Via"] = via
                    headers["ViaResoto"] = via  # the via header might be set by other instances ase well
                    response = StreamResponse(status=cr.status, reason=cr.reason, headers=headers)
                    enable_compression(request, response)
                    await response.prepare(request)
                    async for data in cr.content.iter_chunked(1024 * 1024):
                        await response.write(data)
                    await response.write_eof()
                    return response
            except ClientConnectionError as e:
                log.warning(f"Proxy tsdb request to: {url} resulted in error={e}")
                raise HTTPBadGateway(text="tsdb server is not reachable") from e
        else:
            raise HTTPNotFound(text="No tsdb defined. Adjust resoto.core configuration.")

    return proxy_request
