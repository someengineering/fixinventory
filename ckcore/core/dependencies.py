import logging
import multiprocessing as mp
import sys
from argparse import Namespace
from typing import Optional, List

from arango import ArangoClient
from cklib.args import ArgumentParser

from core import async_extensions
from core.db.arangodb_extensions import ArangoHTTPClient
from core.db.db_access import DbAccess
from core.event_bus import EventBus
from core.model.adjust_node import DirectAdjuster
from core.task.task_handler import TaskHandler

log = logging.getLogger(__name__)


def parse_args(args: Optional[List[str]] = None, namespace: Optional[str] = None) -> Namespace:
    parser = ArgumentParser(
        env_args_prefix="CKCORE_",
        description="Maintains graphs of resources of any shape.",
        epilog="Keeps all the things.",
    )
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
        default="cloudkeeper",
        dest="graphdb_database",
        help="Graph database name (default: cloudkeeper)",
    )
    parser.add_argument(
        "--graphdb-username",
        default="cloudkeeper",
        dest="graphdb_username",
        help="Graph database login (default: cloudkeeper)",
    )
    parser.add_argument(
        "--graphdb-password",
        default="",
        dest="graphdb_password",
        help='Graph database password (default: "")',
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
        help="If the connection should be verified (default: False)",
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
        default="https://www.plantuml.com/plantuml",
        help="PlantUML server URI for UML image rendering (default: https://www.plantuml.com/plantuml)",
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
        "--psk",
        help="Pre-shared key",
        default=None,
        dest="psk",
    )
    parser.add_argument(
        "--merge_max_wait_time_seconds",
        type=int,
        default=3600,
        help="Max waiting time to complete a merge graph action.",
    )

    TaskHandler.add_args(parser)
    return parser.parse_args(args, namespace)  # type: ignore


# Note: this method should be called from every started process as early as possible
def setup_process(args: Namespace, child_process: Optional[str] = None) -> None:
    # Note: if another appender than the log appender is used, proper multiprocess logging needs to be enabled.
    # See https://docs.python.org/3/howto/logging-cookbook.html#logging-to-a-single-file-from-multiple-processes
    if child_process:
        log_format = f"%(asctime)s [{child_process}][%(levelname)s] %(message)s [%(name)s]"
    else:
        log_format = "%(asctime)s [%(levelname)s] %(message)s [%(name)s]"
    logging.basicConfig(format=log_format, datefmt="%H:%M:%S", level=logging.getLevelName(args.log_level.upper()))

    # set/reset process creation method
    reset_process_start_method()
    # reset global async thread pool (forked processes need to create a fresh pool)
    async_extensions.GlobalAsyncPool = None


def reset_process_start_method() -> None:
    preferred = "spawn"
    current = mp.get_start_method(True)
    if current != preferred:
        if preferred in mp.get_all_start_methods():
            log.info(f"Set process start method to {preferred}")
            mp.set_start_method(preferred, True)
            return
        log.warning(f"{preferred} method not available. Have {mp.get_all_start_methods()}. Use {current}")


def db_access(args: Namespace, event_bus: EventBus) -> DbAccess:
    if args.graphdb_type not in "arangodb":
        log.fatal(f"Unknown Graph DB type {args.graphdb_type}")
        sys.exit(1)

    http_client = ArangoHTTPClient(args.graphdb_request_timeout, not args.graphdb_no_ssl_verify)
    client = ArangoClient(hosts=args.graphdb_server, http_client=http_client)
    database = client.db(args.graphdb_database, username=args.graphdb_username, password=args.graphdb_password)
    adjuster = DirectAdjuster()
    return DbAccess(database, event_bus, adjuster)
