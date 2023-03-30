import logging
from functools import lru_cache
from socket import gethostname
from typing import Callable, Awaitable

from aiohttp import ClientConnectionError
from aiohttp.web import HTTPNotFound, Request, StreamResponse
from aiohttp.web_exceptions import HTTPBadGateway
from multidict import CIMultiDict

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
    def drop_request_specific_headers(headers: CIMultiDict[str]) -> None:
        # since we stream the content (chunked), we are not allowed to set the content length.
        headers.popall("Content-Length", None)
        headers.popall("Content-Encoding", None)
        headers.popall("Connection", None)
        headers.popall("Transfer-Encoding", None)
        headers.popall("Accept-Encoding", None)
        headers.popall("Host", None)

    async def proxy_request(request: Request) -> StreamResponse:
        if api_handler.config.api.tsdb_proxy_url:
            in_headers = request.headers.copy()
            drop_request_specific_headers(in_headers)
            url = f'{api_handler.config.api.tsdb_proxy_url}/{request.match_info["tail"]}'

            async def do_request(attempts_left: int) -> StreamResponse:
                async with api_handler.session.request(
                    request.method,
                    url,
                    params=request.query,
                    headers=in_headers,
                    compress="deflate",
                    data=request.content,
                    ssl=api_handler.cert_handler.client_context,
                ) as cr:
                    try:
                        # we see valid requests failing in prometheus with 400, so we also retry client errors
                        # ideally we would only retry on 5xx errors
                        if (cr.status == 400 or cr.status >= 500) and attempts_left > 0:
                            req_header = ", ".join(f"{k}={v}" for k, v in in_headers.items())
                            req_params = ", ".join(f"{k}={v}" for k, v in request.query.items())
                            req_body = await request.content.read()
                            resp_header = ", ".join(f"{k}={v}" for k, v in cr.headers.items())
                            resp_body = await cr.text()
                            log.warning(
                                f"tsdb server returned an error: url:{url}. "
                                f"Request(headers:{req_header}, params:{req_params}, body:{str(req_body)}) "
                                f"Response(headers:{resp_header}, status:{cr.status}, body:{resp_body})"
                            )
                            cr.close()  # close the connection explicitly, might be pooled otherwise
                            return await do_request(attempts_left - 1)
                        else:
                            log.info(f"Proxy tsdb request to: {url} resulted in status={cr.status}")
                            headers = cr.headers.copy()
                            drop_request_specific_headers(headers)
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
                    except Exception:
                        cr.close()  # close connection on any error
                        raise

            try:
                return await do_request(attempts_left=3)  # retry the request up to 3 times
            except ClientConnectionError as e:
                log.warning(f"Proxy tsdb request to: {url} is not reachable {e}")
                raise HTTPBadGateway(text="tsdb server is not reachable") from e
        else:
            raise HTTPNotFound(text="No tsdb defined. Adjust resoto.core configuration.")

    return proxy_request
