from aiohttp.web_log import AccessLogger
from aiohttp.web_request import BaseRequest
from aiohttp.web_response import StreamResponse

RoutesToIgnore = {"/system/ready", "/system/ping", "/metrics"}


class FixInventoryAccessLogger(AccessLogger):
    """
    Override the default aiohttp access logger to ignore certain routes.
    """

    def log(self, request: BaseRequest, response: StreamResponse, time: float) -> None:
        if request.path not in RoutesToIgnore:
            super().log(request, response, time)
