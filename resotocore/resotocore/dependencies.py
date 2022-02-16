import argparse
import logging
import multiprocessing as mp
import os.path
import sys
from argparse import Namespace
from collections import namedtuple
from typing import Optional, List, Callable
from urllib.parse import urlparse

import psutil
from arango.database import StandardDatabase
from resotolib.args import ArgumentParser
from resotolib.jwt import add_args as jwt_add_args
from resotolib.utils import iec_size_format

from resotocore import async_extensions, version
from resotocore.analytics import AnalyticsEventSender
from resotocore.db.db_access import DbAccess
from resotocore.durations import parse_duration
from resotocore.model.adjust_node import DirectAdjuster
from resotocore.util import utc

log = logging.getLogger(__name__)

SystemInfo = namedtuple("SystemInfo", ["version", "cpus", "mem_available", "mem_total", "inside_docker", "started_at"])
started_at = utc()


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

    parser = ArgumentParser(
        env_args_prefix="RESOTOCORE_",
        description="Maintains graphs of resources of any shape.",
        epilog="Keeps all the things.",
    )
    jwt_add_args(parser)
    parser.add_argument(
        "--log-level",
        default="info",
        help="Log level (default: info)",
    )
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
    parser.add_argument(
        "--plantuml-server",
        default="http://plantuml.resoto.org:8080",
        help="PlantUML server URI for UML image rendering.",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        nargs="+",
        help="TCP host(s) to bind on (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8900,
        help="TCP port to bind on (default: 8900)",
    )
    parser.add_argument(
        "--merge_max_wait_time_seconds",
        type=int,
        default=3600,
        help="Max waiting time to complete a merge graph action.",
    )
    parser.add_argument("--debug", default=False, action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--analytics-opt-out",
        default=False,
        action="store_true",
        help="Stop collecting analytics data.",
    )
    parser.add_argument(
        "--ui-path",
        type=is_dir("can not parse --ui-dir"),
        help="The directory where the UI is installed. This directory will be served under /ui/.",
    )
    parser.add_argument(
        "--tsdb-proxy-url",
        type=is_url("can not parse --tsdb-proxy-url"),
        help="The url to the time series database. This path will be served under /tsdb/.",
    )
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
        "--cli-default-graph",
        type=str,
        default="resoto",
        dest="cli_default_graph",
        help="Use this graph for CLI actions, if no graph is specified explicitly.",
    )
    parser.add_argument(
        "--cli-default-section",
        type=str,
        default="reported",
        dest="cli_default_section",
        help="Use this graph section by default, if no section is specified."
        "Relative paths will be interpreted with respect to this section.",
    )
    parser.add_argument("--version", action="store_true", help="Print the version of resotocore and exit.")
    parser.add_argument(
        "--jobs",
        nargs="*",
        type=argparse.FileType("r"),
        help="Read job definitions from given file.",
    )
    parser.add_argument(
        "--start-collect-on-subscriber-connect",
        default=False,
        action="store_true",
        help="Start the collect workflow, when the first handling actor connects to the system.",
    )
    parser.add_argument(
        "---graph-update-abort-after",
        dest="graph_updates_abort_after",
        default="4h",
        type=parse_duration,
        help="If a graph update takes longer than this duration, the update is aborted.",
    )
    parsed: Namespace = parser.parse_args(args if args else [], namespace)

    if parsed.version:
        # print here on purpose, since logging is not set up yet.
        print(f"resotocore {version()}")
        sys.exit(0)

    return parsed


# Note: this method should be called from every started process as early as possible
def setup_process(args: Namespace, child_process: Optional[str] = None) -> None:
    # Note: if another appender than the log appender is used, proper multiprocess logging needs to be enabled.
    # See https://docs.python.org/3/howto/logging-cookbook.html#logging-to-a-single-file-from-multiple-processes
    log_format = "%(asctime)s|resotocore|%(levelname)5s|%(process)d|%(threadName)10s  %(message)s"
    logging.basicConfig(
        format=log_format,
        datefmt="%y-%m-%d %H:%M:%S",
        level=logging.getLevelName(args.log_level.upper()),
        force=True,
    )
    # adjust log levels for specific loggers
    if not args.debug:
        # mute analytics transmission errors unless debug is enabled
        logging.getLogger("posthog").setLevel(logging.FATAL)
        logging.getLogger("backoff").setLevel(logging.FATAL)
        # transitions (fsm) creates a lot of log noise. Only show warnings.
        logging.getLogger("transitions.core").setLevel(logging.WARNING)
        # apscheduler uses the term Job when it triggers, which confuses people.
        logging.getLogger("apscheduler.executors").setLevel(logging.WARNING)

    # set/reset process creation method
    reset_process_start_method()
    # reset global async thread pool (forked processes need to create a fresh pool)
    async_extensions.GlobalAsyncPool = None


def reset_process_start_method() -> None:
    preferred = "spawn"
    current = mp.get_start_method(True)
    if current != preferred:
        if preferred in mp.get_all_start_methods():
            log.debug(f"Set process start method to {preferred}")
            mp.set_start_method(preferred, True)
            return
        log.warning(f"{preferred} method not available. Have {mp.get_all_start_methods()}. Use {current}")


def db_access(config: Namespace, db: StandardDatabase, event_sender: AnalyticsEventSender) -> DbAccess:
    adjuster = DirectAdjuster()
    return DbAccess(db, event_sender, adjuster, update_outdated=config.graph_updates_abort_after)
