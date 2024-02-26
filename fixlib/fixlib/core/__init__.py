import time
import requests
import warnings
from fixlib.logger import log
from fixlib.args import ArgumentParser
from urllib.parse import urlparse, ParseResult
from typing import Optional, Dict


class CLIEnvelope:
    """
    Envelope fields that are used by the CLI.
    Those fields are encoded as HTTP Headers into the HTTP response.
    """

    # Defines the action that should be performed.
    # Use cases:
    # - "edit": A file that is returned from the core should be opened in an editor.
    #           The result of the edit should be sent back to the core, identified by the "command" envelope field.
    action = "Fix-Shell-Action"
    # Defines the command that should be executed after the edit was performed.
    command = "Fix-Shell-Command"
    # Do not add this command to the shell history.
    no_history = "Fix-Shell-No-History"


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--fixcore-uri",
        help="fixcore URI (default: https://localhost:8900)",
        default="https://localhost:8900",
        dest="fixcore_uri",
    )


def fixcore_is_up(fixcore_uri: str, timeout: int = 5, headers: Optional[Dict[str, str]] = None) -> bool:
    ready_uri = f"{fixcore_uri}/system/ready"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = requests.get(ready_uri, timeout=timeout, verify=False, headers=headers)
            if response.status_code == 200:
                return True
    except Exception:
        pass
    return False


def wait_for_fixcore(fixcore_uri: str, timeout: int = 300, headers: Optional[Dict[str, str]] = None) -> None:
    start_time = time.time()
    core_up = False
    wait_time: float = -1
    remaining_wait: float = timeout
    waitlog = log.info
    while wait_time < timeout:
        if fixcore_is_up(fixcore_uri, headers=headers):
            core_up = True
            break
        else:
            waitlog(f"Waiting up to {remaining_wait:.2f}s for fixcore" f" to come online at {fixcore_uri}")
            waitlog = log.debug
        time.sleep(2)
        wait_time = time.time() - start_time
        remaining_wait = timeout - wait_time
    if not core_up:
        raise TimeoutError(f"fixcore not ready after {wait_time:.2f} seconds")


class FixcoreURI:
    def __init__(self, fixcore_uri: Optional[str] = None) -> None:
        self.fixcore_uri = fixcore_uri

    @property
    def uri(self) -> ParseResult:
        if self.fixcore_uri is None:
            fixcore_uri = getattr(ArgumentParser.args, "fixcore_uri", None)
            if fixcore_uri is not None:
                fixcore_uri = str(fixcore_uri).rstrip("/")
            else:
                fixcore_uri = "https://localhost:8900"
        else:
            fixcore_uri = self.fixcore_uri
        if fixcore_uri is None:
            raise AttributeError("fixcore_uri is not set")
        return urlparse(fixcore_uri)  # type: ignore

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


fixcore = FixcoreURI()
