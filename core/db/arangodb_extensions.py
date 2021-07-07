import logging
from typing import Optional, MutableMapping, Union, Tuple

from arango import DefaultHTTPClient, Response
from arango.typings import Headers
from requests import Session
from requests_toolbelt import MultipartEncoder

log = logging.getLogger(__name__)


class ArangoHTTPClient(DefaultHTTPClient):  # type: ignore
    def __init__(self, timeout: int, verify: bool):
        log.info(f"Create ArangoHTTPClient with timeout={timeout} and verify={verify}")
        self.timeout = timeout
        self.verify = verify

    # Override only to extend the request timeout
    def send_request(
        self,
        session: Session,
        method: str,
        url: str,
        headers: Optional[Headers] = None,
        params: Optional[MutableMapping[str, str]] = None,
        data: Union[str, MultipartEncoder, None] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> Response:
        response = session.request(
            method, url, params, data, headers, auth=auth, timeout=self.timeout, verify=self.verify
        )
        return Response(method, response.url, response.headers, response.status_code, response.reason, response.text)
