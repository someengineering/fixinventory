import sys
import traceback
from argparse import Namespace
from typing import AsyncIterator, List, Optional

from aiohttp.web_app import Application
from resotolib import jwt
from resotolib.args import ArgumentParser
from resotolib.logger import setup_logger, log

from resotolog.logs.log_handler import LogHandler
from resotolog.model import LogConfig, RestartService
from resotolog.web import runner
from resotolog.web.api import Api


def main() -> None:
    """
    Application entrypoint - no arguments are allowed.
    """
    try:
        run(sys.argv[1:])
        log.info("Process finished.")
    except (KeyboardInterrupt, SystemExit):
        log.info("Stopping resotolog.")
        sys.exit(0)
    except Exception as ex:
        if "--debug" in sys.argv:
            print(traceback.format_exc())
        print(f"resotolog stopped. Reason: {ex}", file=sys.stderr)
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
    handler = LogHandler(123)
    api = Api(config, handler)

    async def on_start() -> None:
        await api.start()

    async def on_stop() -> None:
        await api.stop()

    async def async_initializer() -> Application:
        async def on_start_stop(_: Application) -> AsyncIterator[None]:
            await on_start()
            log.info("Initialization done. Starting API.")
            yield
            log.info("Shutdown initiated. Stop all tasks.")
            await on_stop()

        api.app.cleanup_ctx.append(on_start_stop)
        return api.app

    runner.run_app(
        async_initializer(),
        api.stop,
        # host=config.api.web_hosts,
        # port=config.api.web_port,
        # ssl_context=cert_handler.host_context,
    )


def parse_args(args: Optional[List[str]] = None) -> Namespace:
    parser = ArgumentParser(
        env_args_prefix="RESOTOLOG_",
        description="Resoto Log Aggregator.",
    )
    jwt.add_args(parser)
    parsed: Namespace = parser.parse_args(args if args else [])
    return parsed


def setup_process(args: Namespace) -> None:
    setup_logger("resotolog", force=True)


if __name__ == "__main__":
    main()
