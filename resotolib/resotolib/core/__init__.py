from resotolib.args import ArgumentParser
from urllib.parse import urlparse, ParseResult


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--resotocore-uri",
        help="resotocore URI (default: https://localhost:8900)",
        default="https://localhost:8900",
        dest="resotocore_uri",
    )


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
        return f"{self.uri.scheme}://{self.uri.netloc}"

    @property
    def ws_uri(self) -> str:
        scheme = "ws"
        if self.uri.scheme == "https":
            scheme = "wss"
        return f"{scheme}://{self.uri.netloc}"


resotocore = ResotocoreURI()
