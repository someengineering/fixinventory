import asyncio
import logging
import socket
from ssl import SSLContext
from typing import Optional, Union, Awaitable, Callable, Type

from aiohttp.abc import AbstractAccessLogger

# noinspection PyProtectedMember
from aiohttp.helpers import all_tasks
from aiohttp.log import access_logger

# noinspection PyProtectedMember
from aiohttp.web import HostSequence, _run_app, _cancel_tasks
from aiohttp.web_app import Application
from aiohttp.web_log import AccessLogger
from aiohttp.web_runner import GracefulExit


# This method is copied from aiohttp.web.run_app with one 2 additional steps:
# - it allows a callable that is executed on shutdown.
# - it does not swallow terminal exceptions
def run_app(
    app: Union[Application, Awaitable[Application]],
    on_shutdown: Callable[[], Awaitable[None]],
    *,
    host: Optional[Union[str, HostSequence]] = None,
    port: Optional[int] = None,
    path: Optional[str] = None,
    sock: Optional[socket.socket] = None,
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
            port=port,
            path=path,
            sock=sock,
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
        _cancel_tasks(all_tasks(loop), loop)
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
