import logging

from arango import DefaultHTTPClient, Response

log = logging.getLogger(__name__)


class ArangoHTTPClient(DefaultHTTPClient):

    def __init__(self, timeout: int, verify: bool):
        log.info(f"Create ArangoHTTPClient with timeout={timeout} and verify={verify}")
        self.timeout = timeout
        self.verify = verify

    """ Override only to extend the request timeout """

    def send_request(self, session, method, url, headers=None, params=None, data=None, auth=None) -> Response:
        response = session.request(method, url, params, data, headers, auth=auth, timeout=self.timeout,
                                   verify=self.verify)
        return Response(method, response.url, response.headers, response.status_code, response.reason, response.text)
