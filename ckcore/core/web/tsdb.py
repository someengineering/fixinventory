import logging
from typing import Callable, Awaitable

from aiohttp import ClientSession
from aiohttp.web import HTTPNotFound, Request, StreamResponse
from core.web import api  # pylint: disable=unused-import # prevent circular import
from core.web.directives import enable_compression

log = logging.getLogger(__name__)


# Proxy request to configured tsdb endpoint
def tsdb(api_handler: "api.Api") -> Callable[[Request], Awaitable[StreamResponse]]:
    async def proxy_request(request: Request) -> StreamResponse:
        if api_handler.args.tsdb_proxy_url:
            if api_handler.session is None:
                api_handler.session = ClientSession()

            in_headers = request.headers.copy()
            # since we stream the content (chunked), we are not allowed to set the content length.
            in_headers.popall("Content-Length", "none")
            in_headers.popall("Content-Encoding", "none")
            url = f'{api_handler.args.tsdb_proxy_url}/{request.match_info["tail"]}'
            async with api_handler.session.request(
                request.method,
                url,
                params=request.query,
                headers=in_headers,
                compress="deflate",
                data=request.content,
            ) as cr:
                log.info(f"Proxy tsdb request to: {url} resulted in status={cr.status}")
                headers = cr.headers.copy()
                # since we stream the content (chunked), we are not allowed to set the content length.
                headers.popall("Content-Length", "none")
                headers.popall("Content-Encoding", "none")
                response = StreamResponse(status=cr.status, reason=cr.reason, headers=headers)
                await response.prepare(request)
                enable_compression(request, response)
                async for data in cr.content.iter_chunked(1024 * 1024):
                    await response.write(data)
                await response.write_eof()
                return response
        else:
            raise HTTPNotFound(text="No tsdb defined. Configure with --tsdb_proxy_url start parameter.")

    return proxy_request
