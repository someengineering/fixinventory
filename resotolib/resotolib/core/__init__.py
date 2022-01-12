from resotolib.args import ArgumentParser


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--resotocore-uri",
        help="resotocore URI (default: http://localhost:8900)",
        default="http://localhost:8900",
        dest="resotocore_uri",
    )
    arg_parser.add_argument(
        "--resotocore-ws-uri",
        help="resotocore Websocket URI (default: ws://localhost:8900)",
        default="ws://localhost:8900",
        dest="resotocore_ws_uri",
    )
    arg_parser.add_argument(
        "--resotocore-graph",
        help="resotocore graph name (default: ck)",
        default="ck",
        dest="resotocore_graph",
    )
