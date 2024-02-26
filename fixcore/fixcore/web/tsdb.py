import logging
from asyncio import sleep
from functools import lru_cache
from socket import gethostname
from typing import Callable, Awaitable

from aiohttp import ClientConnectionError, ClientResponse
from aiohttp.web import HTTPNotFound, Request, StreamResponse
from aiohttp.web_exceptions import HTTPBadGateway
from multidict import CIMultiDict

from fixcore.web import api  # pylint: disable=unused-import # prevent circular import
from fixcore.web.directives import enable_compression

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

    def should_be_retried(response: ClientResponse) -> bool:
        # We see valid requests failing in k8s with 400.
        # Prometheus will send a content-length header in such a case.
        # Retry the request, if it is missing, since it is not coming from prometheus.
        if response.status == 400 and response.content_length in (None, 0):
            return True
        elif response.status >= 500:
            return True
        else:
            return False

    async def proxy_request(request: Request) -> StreamResponse:
        if api_handler.deps.config.api.tsdb_proxy_url:
            in_headers = CIMultiDict(request.headers)
            drop_request_specific_headers(in_headers)
            url = f'{api_handler.deps.config.api.tsdb_proxy_url}/{request.match_info["tail"]}'
            max_retries = 5

            async def do_request(attempts_left: int) -> StreamResponse:
                async with api_handler.session.request(
                    request.method,
                    url,
                    params=request.query,
                    headers=in_headers,
                    compress="deflate",
                    data=request.content,
                    ssl=api_handler.deps.cert_handler.client_context,
                ) as cr:
                    try:
                        # in case of error: do we need to retry?
                        if cr.status >= 400 and attempts_left > 0 and should_be_retried(cr):
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
                            await sleep(2 ** (max_retries - attempts_left) * 0.1)  # exponential backoff
                            return await do_request(attempts_left - 1)
                        else:
                            log.info(f"Proxy tsdb request to: {url} resulted in status={cr.status}")
                            headers = cr.headers.copy()
                            drop_request_specific_headers(headers)
                            via = f"{request.version.major}.{request.version.minor} {hostname()}"
                            headers["Via"] = via
                            headers["ViaFix"] = via  # the via header might be set by other instances ase well
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
                return await do_request(attempts_left=max_retries)
            except ClientConnectionError as e:
                log.warning(f"Proxy tsdb request to: {url} is not reachable {e}")
                raise HTTPBadGateway(text="tsdb server is not reachable") from e
        else:
            raise HTTPNotFound(text="No tsdb defined. Adjust fix.core configuration.")

    return proxy_request
