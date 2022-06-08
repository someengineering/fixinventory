import time
import requests
import warnings
from resotolib.logger import log
from resotolib.args import ArgumentParser
from urllib.parse import urlparse, ParseResult
from typing import Optional


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--resotocore-uri",
        help="resotocore URI (default: https://localhost:8900)",
        default="https://localhost:8900",
        dest="resotocore_uri",
    )


def resotocore_is_up(resotocore_uri: str, timeout: int = 5) -> bool:
    ready_uri = f"{resotocore_uri}/system/ready"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = requests.get(ready_uri, timeout=timeout, verify=False)
            if response.status_code == 200:
                return True
    except Exception:
        pass
    return False


def wait_for_resotocore(resotocore_uri: str, timeout: int = 300) -> None:
    start_time = time.time()
    core_up = False
    wait_time = -1
    remaining_wait = timeout
    waitlog = log.info
    while wait_time < timeout:
        if resotocore_is_up(resotocore_uri):
            core_up = True
            break
        else:
            waitlog(f"Waiting up to {remaining_wait:.2f}s for resotocore" f" to come online at {resotocore_uri}")
            waitlog = log.debug
        time.sleep(2)
        wait_time = time.time() - start_time
        remaining_wait = timeout - wait_time
    if not core_up:
        raise TimeoutError(f"resotocore not ready after {wait_time:.2f} seconds")


class ResotocoreURI:
    def __init__(self, resotocore_uri: Optional[str] = None) -> None:
        self.resotocore_uri = resotocore_uri

    @property
    def uri(self) -> ParseResult:
        if self.resotocore_uri is None:
            resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri", None)
            if resotocore_uri is not None:
                resotocore_uri = str(resotocore_uri).rstrip("/")
            else:
                resotocore_uri = "https://localhost:8900"
        else:
            resotocore_uri = self.resotocore_uri
        if resotocore_uri is None:
            raise AttributeError("resotocore_uri is not set")
        return urlparse(resotocore_uri)

    @property
    def http_uri(self) -> str:
        return f"{self.uri.scheme}://{self.uri.netloc}{self.uri.path}"

    @property
    def ws_uri(self) -> str:
        scheme = "ws"
        if self.uri.scheme == "https":
            scheme = "wss"
        return f"{scheme}://{self.uri.netloc}{self.uri.path}"

    @property
    def is_secure(self) -> bool:
        return self.uri.scheme == "https"


resotocore = ResotocoreURI()
