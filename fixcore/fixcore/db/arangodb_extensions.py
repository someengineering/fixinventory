import logging
from typing import Optional, MutableMapping, Union, Tuple

from arango import HTTPClient
from arango.response import Response
from arango.typings import Headers
from requests import Session
from requests.adapters import HTTPAdapter, Retry
from requests_toolbelt import MultipartEncoder

log = logging.getLogger(__name__)


class ArangoHTTPClient(HTTPClient):
    def __init__(
        self,
        timeout: int,
        verify: Union[str, bool, None],
        retry_attempts: int = 3,
        backoff_factor: float = 1.0,
        pool_connections: int = 10,
        pool_maxsize: int = 20,
    ):
        log.info(f"Create ArangoHTTPClient with timeout={timeout} and verify={verify}")
        self._timeout = timeout
        self._verify = verify
        self._retry_attempts = retry_attempts
        self._backoff_factor = backoff_factor
        self._pool_connections = pool_connections
        self._pool_maxsize = pool_maxsize

    def create_session(self, host: str) -> Session:
        retry_strategy = Retry(
            total=self._retry_attempts,
            backoff_factor=self._backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        http_adapter = HTTPAdapter(
            pool_connections=self._pool_connections,
            pool_maxsize=self._pool_maxsize,
            max_retries=retry_strategy,
        )
        session = Session()
        session.mount("https://", http_adapter)
        session.mount("http://", http_adapter)
        session.verify = self._verify
        return session

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
        response = session.request(method, url, params, data, headers, auth=auth, timeout=self._timeout)
        return Response(method, response.url, response.headers, response.status_code, response.reason, response.text)
