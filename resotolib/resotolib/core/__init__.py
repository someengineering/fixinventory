from resotolib.args import ArgumentParser
from urllib.parse import urlparse, ParseResult


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--resotocore-uri",
        help="resotocore URI (default: http://localhost:8900)",
        default="http://localhost:8900",
        dest="resotocore_uri",
    )
    arg_parser.add_argument(
        "--resotocore-graph",
        help="resotocore graph name (default: resoto)",
        default="resoto",
        dest="resotocore_graph",
    )


class ResotocoreURI:
    @property
    def uri(self) -> ParseResult:
        resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri")
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
