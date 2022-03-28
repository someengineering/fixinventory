import argparse
import logging
import multiprocessing as mp
import os.path
import sys
from argparse import Namespace
from collections import namedtuple
from typing import Optional, List, Callable, Tuple
from urllib.parse import urlparse

import psutil
from arango.database import StandardDatabase
from parsy import Parser
from resotolib.args import ArgumentParser
from resotolib.jwt import add_args as jwt_add_args
from resotolib.utils import iec_size_format

from resotocore import async_extensions, version
from resotocore.analytics import AnalyticsEventSender
from resotocore.core_config import CoreConfig, parse_config
from resotocore.db.db_access import DbAccess
from resotocore.durations import parse_duration
from resotocore.model.adjust_node import DirectAdjuster
from resotocore.parse_util import make_parser, variable_p, equals_p, json_value_p, comma_p
from resotocore.util import utc

log = logging.getLogger(__name__)

SystemInfo = namedtuple(
    "SystemInfo",
    ["version", "cpus", "mem_available", "mem_total", "inside_docker", "started_at"],
)
started_at = utc()


@make_parser
def path_value_parser() -> Parser:
    key = yield variable_p
    yield equals_p
    value = yield json_value_p
    return key, value


path_values_parser = path_value_parser.sep_by(comma_p)


def system_info() -> SystemInfo:
    mem = psutil.virtual_memory()
    return SystemInfo(
        version=version(),
        cpus=mp.cpu_count(),
        mem_available=iec_size_format(mem.available),
        mem_total=iec_size_format(mem.total),
        inside_docker=os.path.exists("/.dockerenv"),  # this file is created by the docker runtime
        started_at=started_at,
    )


def parse_args(args: Optional[List[str]] = None, namespace: Optional[str] = None) -> Namespace:
    def is_file(message: str) -> Callable[[str], str]:
        def check_file(path: str) -> str:
            if os.path.isfile(path):
                return path
            else:
                raise AttributeError(f"{message}: path {path} is not a directory!")

        return check_file

    def is_dir(message: str) -> Callable[[str], str]:
        def check_dir(path: str) -> str:
            if os.path.isdir(path):
                return path
            else:
                raise AttributeError(f"{message}: path {path} is not a directory!")

        return check_dir

    def is_url(message: str) -> Callable[[str], str]:
        def check_url(url: str) -> str:
            try:
                urlparse(url)
                return url
            except ValueError as ex:
                raise AttributeError(f"{message}: url {url} can not be parsed!") from ex

        return check_url

    def key_value(kv: str) -> Tuple[str, str]:
        try:
            return path_value_parser.parse(kv)  # type: ignore
        except Exception as ex:
            raise AttributeError(f"Can not parse config option: {kv}. Reason: {ex}") from ex

    parser = ArgumentParser(
        env_args_prefix="RESOTOCORE_",
        description="Maintains graphs of resources of any shape.",
        epilog="Keeps all the things.",
    )
    jwt_add_args(parser)
    # No default here on purpose: it can be reconfigured!
    parser.add_argument("--log-level", help="Log level (e.g.: info)")
    parser.add_argument(
        "--graphdb-server",
        default="http://localhost:8529",
        dest="graphdb_server",
        help="Graph database server (default: http://localhost:8529)",
    )
    parser.add_argument(
        "--graphdb-database",
        default="resoto",
        dest="graphdb_database",
        help="Graph database name (default: resoto)",
    )
    parser.add_argument(
        "--graphdb-username",
        default="resoto",
        dest="graphdb_username",
        help="Graph database login (default: resoto)",
    )
    parser.add_argument(
        "--graphdb-password",
        default="",
        dest="graphdb_password",
        help='Graph database password (default: "")',
    )
    parser.add_argument(
        "--graphdb-root-password",
        default="",
        dest="graphdb_root_password",
        help="Graph root database password used for creating user and database if not existent.",
    )
    parser.add_argument(
        "--graphdb-bootstrap-do-not-secure",
        default=False,
        action="store_true",
        dest="graphdb_bootstrap_do_not_secure",
        help="Leave an empty root password during system setup process.",
    )
    parser.add_argument(
        "--graphdb-type",
        default="arangodb",
        dest="graphdb_type",
        help="Graph database type (default: arangodb)",
    )
    parser.add_argument(
        "--graphdb-no-ssl-verify",
        action="store_true",
        dest="graphdb_no_ssl_verify",
        help="If the connection should not be verified (default: False)",
    )
    parser.add_argument(
        "--graphdb-request-timeout",
        type=int,
        default=900,
        dest="graphdb_request_timeout",
        help="Request timeout in seconds (default: 900)",
    )
    parser.add_argument("--no-tls", default=False, action="store_true", help="Disable TLS and use plain HTTP.")
    parser.add_argument(
        "--tls-cert",
        type=is_file("can not parse --tls-cert"),
        help="Path to a single file in PEM format containing the certificate as well as any number "
        "of CA certificates needed to establish the certificate’s authenticity.",
    )
    parser.add_argument(
        "--tls-key",
        type=is_file("can not parse --tls-key"),
        help="Path to a file containing the private key. "
        "If not defined the private key will be taken from certfile as well.",
    )
    parser.add_argument(
        "--tls-password",
        type=str,
        help="Optional password to decrypt the private key file.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the version of resotocore and exit.",
    )
    parser.add_argument(
        "--config-override",
        nargs="+",
        type=key_value,
        dest="config_override",
        default=[],
        help="Override configuration parameters. Format: path.to.property=value. "
        "Note: the value can be any json value - proper escaping from the shell is required."
        "Example: --config-override api.hosts='[localhost, some.domain]' api.port=12345",
    )

    # All suppressed properties are only here for backward compatibility.
    # TODO: remove properties once the docker setup is done.
    # No default here on purpose: it can be reconfigured!
    parser.add_argument("--plantuml-server", help=argparse.SUPPRESS)
    parser.add_argument("--host", type=str, nargs="+", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--merge_max_wait_time_seconds", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--debug", default=None, action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--analytics-opt-out", default=None, action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ui-path", type=is_dir("can not parse --ui-dir"), help=argparse.SUPPRESS)
    parser.add_argument("--tsdb-proxy-url", type=is_url("can not parse --tsdb-proxy-url"), help=argparse.SUPPRESS)
    parser.add_argument("--cli-default-graph", type=str, dest="cli_default_graph", help=argparse.SUPPRESS)
    parser.add_argument("--cli-default-section", type=str, dest="cli_default_section", help=argparse.SUPPRESS)
    parser.add_argument("--jobs", nargs="*", type=argparse.FileType("r"), help=argparse.SUPPRESS)
    parser.add_argument(
        "--start-collect-on-subscriber-connect", default=None, action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument("--graph-update-abort-after", type=parse_duration, help=argparse.SUPPRESS)

    parsed: Namespace = parser.parse_args(args if args else [], namespace)

    if parsed.version:
        # print here on purpose, since logging is not set up yet.
        print(f"resotocore {version()}")
        sys.exit(0)

    return parsed


def empty_config(args: Optional[List[str]] = None) -> CoreConfig:
    return parse_config(parse_args(args or []), {})


# Note: this method should be called from every started process as early as possible
def setup_process(args: Namespace, config: Optional[CoreConfig] = None) -> None:
    if config:
        configure_logging(config.runtime.log_level, config.runtime.debug)
    else:
        configure_logging(args.log_level or "info", args.debug or False)
    # set/reset process creation method
    reset_process_start_method()
    # reset global async thread pool (forked processes need to create a fresh pool)
    async_extensions.GlobalAsyncPool = None


def reconfigure_logging(config: CoreConfig) -> None:
    configure_logging(config.runtime.log_level, config.runtime.debug)


def configure_logging(log_level: str, debug: bool) -> None:
    # Note: if another appender than the log appender is used, proper multiprocess logging needs to be enabled.
    # See https://docs.python.org/3/howto/logging-cookbook.html#logging-to-a-single-file-from-multiple-processes
    log_format = "%(asctime)s|resotocore|%(levelname)5s|%(process)d|%(threadName)10s  %(message)s"
    level = log_level.upper()
    logging.basicConfig(
        format=log_format,
        datefmt="%y-%m-%d %H:%M:%S",
        level=logging.getLevelName(level),
        force=True,
    )
    # adjust log levels for specific loggers
    if debug:
        logging.getLogger("resotocore").setLevel(logging.DEBUG)
        # in case of restart: reset the original level
        logging.getLogger("posthog").setLevel(level)
        logging.getLogger("backoff").setLevel(level)
        logging.getLogger("transitions.core").setLevel(level)
        logging.getLogger("apscheduler.executors").setLevel(level)
    else:
        # in case of restart: reset the original level
        logging.getLogger("resotocore").setLevel(level)
        # mute analytics transmission errors unless debug is enabled
        logging.getLogger("posthog").setLevel(logging.FATAL)
        logging.getLogger("backoff").setLevel(logging.FATAL)
        # transitions (fsm) creates a lot of log noise. Only show warnings.
        logging.getLogger("transitions.core").setLevel(logging.WARNING)
        # apscheduler uses the term Job when it triggers, which confuses people.
        logging.getLogger("apscheduler.executors").setLevel(logging.WARNING)


def reset_process_start_method() -> None:
    preferred = "spawn"
    current = mp.get_start_method(True)
    if current != preferred:
        if preferred in mp.get_all_start_methods():
            log.debug(f"Set process start method to {preferred}")
            mp.set_start_method(preferred, True)
            return
        log.warning(f"{preferred} method not available. Have {mp.get_all_start_methods()}. Use {current}")


def db_access(config: CoreConfig, db: StandardDatabase, event_sender: AnalyticsEventSender) -> DbAccess:
    adjuster = DirectAdjuster()
    return DbAccess(db, event_sender, adjuster, config)
