import asyncio
import logging
import sys
from ssl import SSLContext
from typing import Optional, Union, Awaitable, Callable, Type, List, cast

from aiohttp.abc import AbstractAccessLogger
from aiohttp.log import access_logger

# noinspection PyProtectedMember
from aiohttp.web import HostSequence, _cancel_tasks
from aiohttp.web_app import Application
from aiohttp.web_log import AccessLogger
from aiohttp.web_runner import GracefulExit, BaseSite, TCPSite, AppRunner


# This method is derived from aiohttp.web.run_app with additional steps:
# - it allows a callable that is executed on shutdown.
# - it does not swallow terminal exceptions
# - it exposes a http and https port
def run_app(
    app: Union[Application, Awaitable[Application]],
    on_shutdown: Callable[[], Awaitable[None]],
    host: Union[str, HostSequence],
    https_port: Optional[int],
    http_port: Optional[int],
    default_port: int,
    *,
    shutdown_timeout: float = 60.0,
    keepalive_timeout: float = 75.0,
    ssl_context: Optional[SSLContext] = None,
    print_cmd: Callable[..., None] = print,
    backlog: int = 128,
    access_log_class: Type[AbstractAccessLogger] = AccessLogger,
    access_log_format: str = AccessLogger.LOG_FORMAT,
    access_log: Optional[logging.Logger] = access_logger,
    handle_signals: bool = True,
    reuse_address: Optional[bool] = None,
    reuse_port: Optional[bool] = None,
    loop: Optional[asyncio.AbstractEventLoop] = None,
) -> None:
    """Run an app locally"""
    if loop is None:
        loop = asyncio.new_event_loop()

    # Configure if and only if in debugging mode and using the default logger
    if loop.get_debug() and access_log and access_log.name == "aiohttp.access":
        if access_log.level == logging.NOTSET:
            access_log.setLevel(logging.DEBUG)
        if not access_log.hasHandlers():
            access_log.addHandler(logging.StreamHandler())

    main_task = loop.create_task(
        _run_app(
            app,
            host=host,
            https_port=https_port,
            http_port=http_port,
            default_port=default_port,
            shutdown_timeout=shutdown_timeout,
            keepalive_timeout=keepalive_timeout,
            ssl_context=ssl_context,
            print=print_cmd,
            backlog=backlog,
            access_log_class=access_log_class,
            access_log_format=access_log_format,
            access_log=access_log,
            handle_signals=handle_signals,
            reuse_address=reuse_address,
            reuse_port=reuse_port,
        )
    )

    try:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main_task)
    except (GracefulExit, KeyboardInterrupt) as ex:  # pragma: no cover
        raise ex
    finally:
        loop.run_until_complete(on_shutdown())
        _cancel_tasks({main_task}, loop)
        _cancel_tasks(asyncio.all_tasks(loop), loop)
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


async def _run_app(
    app: Union[Application, Awaitable[Application]],
    host: Union[str, HostSequence],
    https_port: Optional[int],
    http_port: Optional[int],
    default_port: int,
    *,
    shutdown_timeout: float = 60.0,
    keepalive_timeout: float = 75.0,
    ssl_context: Optional[SSLContext] = None,
    print: Optional[Callable[..., None]] = print,
    backlog: int = 128,
    access_log_class: Type[AbstractAccessLogger] = AccessLogger,
    access_log_format: str = AccessLogger.LOG_FORMAT,
    access_log: Optional[logging.Logger] = access_logger,
    handle_signals: bool = True,
    reuse_address: Optional[bool] = None,
    reuse_port: Optional[bool] = None,
) -> None:
    # An internal function to actually do all dirty job for application running
    if asyncio.iscoroutine(app):
        app = await app

    app = cast(Application, app)

    runner = AppRunner(
        app,
        handle_signals=handle_signals,
        access_log_class=access_log_class,
        access_log_format=access_log_format,
        access_log=access_log,
        keepalive_timeout=keepalive_timeout,
    )

    await runner.setup()

    sites: List[BaseSite] = []

    def with_port(port: int, ssl: Optional[SSLContext] = None) -> None:
        if isinstance(host, (str, bytes, bytearray, memoryview)):
            sites.append(
                TCPSite(
                    runner,
                    host,
                    port,
                    shutdown_timeout=shutdown_timeout,
                    ssl_context=ssl,
                    backlog=backlog,
                    reuse_address=reuse_address,
                    reuse_port=reuse_port,
                )
            )
        else:
            for h in host:
                sites.append(
                    TCPSite(
                        runner,
                        h,
                        port,
                        shutdown_timeout=shutdown_timeout,
                        ssl_context=ssl,
                        backlog=backlog,
                        reuse_address=reuse_address,
                        reuse_port=reuse_port,
                    )
                )

    try:
        if https_port is not None:
            with_port(https_port, ssl_context)
        if http_port is not None and http_port != https_port:
            with_port(http_port)
        if http_port is None and https_port is None:
            with_port(default_port)

        for site in sites:
            await site.start()

        if print:
            names = sorted(str(s.name) for s in runner.sites)
            print("======== Running on {} ========\n" "(Press CTRL+C to quit)".format(", ".join(names)))

        # sleep forever by 1 hour intervals,
        # on Windows before Python 3.8 wake up every 1 second to handle
        # Ctrl+C smoothly
        if sys.platform == "win32" and sys.version_info < (3, 8):
            delay = 1
        else:
            delay = 3600

        while True:
            await asyncio.sleep(delay)
    finally:
        await runner.cleanup()
