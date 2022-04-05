import time
import requests
import warnings
from resotolib.logging import log
from resotolib.args import ArgumentParser
from urllib.parse import urlparse, ParseResult


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--resotocore-uri",
        help="resotocore URI (default: https://localhost:8900)",
        default="https://localhost:8900",
        dest="resotocore_uri",
    )


def wait_for_resotocore(resotocore_uri: str, timeout: int = 300) -> None:
    ready_uri = f"{resotocore_uri}/system/ready"
    start_time = time.time()
    core_up = False
    wait_time = -1
    while wait_time < timeout:
        wait_time = time.time() - start_time
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                log.debug(f"Waiting for resotocore to come online at {resotocore_uri}")
                response = requests.get(ready_uri, timeout=5, verify=False)
                if response.status_code == 200:
                    log.debug("resotocore is ready")
                    core_up = True
                    break
        except Exception:
            pass
        time.sleep(5)
    if not core_up:
        raise TimeoutError(f"resotocore not ready after {timeout} seconds")


class ResotocoreURI:
    def __init__(self, resotocore_uri: str = None) -> None:
        self.resotocore_uri = resotocore_uri

    @property
    def uri(self) -> ParseResult:
        if self.resotocore_uri is None:
            resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri", None)
            if resotocore_uri is None:
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
