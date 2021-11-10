from cklib.args import ArgumentParser


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--ckcore-uri",
        help="ckcore URI (default: http://localhost:8900)",
        default="http://localhost:8900",
        dest="ckcore_uri",
    )
    arg_parser.add_argument(
        "--ckcore-ws-uri",
        help="ckcore Websocket URI (default: ws://localhost:8900)",
        default="ws://localhost:8900",
        dest="ckcore_ws_uri",
    )
    arg_parser.add_argument(
        "--ckcore-graph",
        help="ckcore graph name (default: ck)",
        default="ck",
        dest="ckcore_graph",
    )
