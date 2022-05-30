import sys
import traceback
from argparse import Namespace
from typing import AsyncIterator, List, Optional

from aiohttp.web_app import Application
from resotolib import jwt
from resotolib.args import ArgumentParser
from resotolib.asynchronous.web import runner
from resotolib.core import wait_for_resotocore
from resotolib.logger import setup_logger, log

from resotoeventlog import version
from resotoeventlog.logs.log_handler import LogHandler
from resotoeventlog.model import LogConfig, RestartService
from resotoeventlog.web.api import Api


def main() -> None:
    """
    Application entrypoint - no arguments are allowed.
    """
    try:
        run(sys.argv[1:])
        log.info("Process finished.")
    except (KeyboardInterrupt, SystemExit):
        log.debug("Stopping resotoeventlog.")
        sys.exit(0)
    except Exception as ex:
        if "--debug" in sys.argv:
            print(traceback.format_exc())
        print(f"resotoeventlog stopped. Reason: {ex}", file=sys.stderr)
        sys.exit(1)


def run(arguments: List[str]) -> None:
    args = parse_args(arguments)
    setup_process(args)

    # The loop is here to restart the process in case of RestartService exceptions.
    while True:
        try:
            run_process(args)
            break  # This line should never be reached. In case it does, break the loop.
        except RestartService as ex:
            message = f"Restarting Service. Reason: {ex.reason}"
            line = "-" * len(message)
            print(f"\n{line}\n{message}\n{line}\n")


def run_process(args: Namespace) -> None:
    config = LogConfig(args)
    handler = LogHandler(args.max_queued_entries)
    api = Api(config, handler)

    async def async_initializer() -> Application:
        async def on_start_stop(_: Application) -> AsyncIterator[None]:
            await api.start()
            log.info("Initialization done. Starting API.")
            yield
            log.info("Shutdown initiated. Stop all tasks.")
            await api.stop()

        api.app.cleanup_ctx.append(on_start_stop)
        return api.app

    if config.use_tls() and config.use_core_cert():
        wait_for_resotocore(config.core_uri.http_uri)

    runner.run_app(async_initializer(), api.stop, host=config.host, port=config.port, ssl_context=config.ssl_context)


def parse_args(args: Optional[List[str]] = None) -> Namespace:
    parser = ArgumentParser(
        env_args_prefix="RESOTOEVENTLOG_",
        description="Resoto Log Aggregator.",
    )
    jwt.add_args(parser)
    parser.add_argument("--no-tls", default=False, action="store_true", help="Disable TLS and use plain HTTP.")
    parser.add_argument("--cert", help="Path to custom certificate file")
    parser.add_argument("--cert-key", help="Path to custom certificate key file")
    parser.add_argument("--cert-key-pass", help="Passphrase for certificate key file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--max-queued-entries", type=int, default=1000)
    parser.add_argument("--version", action="store_true", help="Show version.")
    parser.add_argument("--host", default="0.0.0.0", help="Host to listen on.")
    parser.add_argument("--port", default=8901, type=int, help="Port to listen on.")
    parser.add_argument(
        "--resotocore-uri",
        dest="resotocore_uri",
        default="https://localhost:8900",
        help="Resoto Core URI.",
    )
    parsed: Namespace = parser.parse_args(args if args else [])
    if parsed.version:
        print(f"resotoeventlog {version()}")
        sys.exit(0)
    return parsed


def setup_process(args: Namespace) -> None:
    setup_logger("resotoeventlog", force=True, verbose=args.verbose or args.debug)


if __name__ == "__main__":
    main()
