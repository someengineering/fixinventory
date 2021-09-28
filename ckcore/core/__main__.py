import logging
import os
import sys
from argparse import Namespace

from aiohttp import web
from aiohttp.web_app import Application
from arango import ArangoClient
from cklib.args import ArgumentParser

from core.cli.cli import CLIDependencies, CLI
from core.cli.command import all_parts, aliases
from core.db.arangodb_extensions import ArangoHTTPClient
from core.db.db_access import DbAccess
from core.event_bus import EventBus
from core.model.adjust_node import DirectAdjuster
from core.model.model_handler import ModelHandlerDB
from core.worker_task_queue import WorkerTaskQueue
from core.web.api import Api
from core.task.scheduler import Scheduler
from core.task.subscribers import SubscriptionHandler
from core.task.task_handler import TaskHandler

log = logging.getLogger(__name__)


def parse_args() -> Namespace:
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
        # Explicitly use the ipv4 loopback address. There are scenarios where aiohttp can not bind to the ipv6 address.
        "--host",
        type=str,
        default="127.0.0.1",
        nargs="+",
        help="TCP host(s) to bind on (default: 127.0.0.1)",
    )
    parser.add_argument("--port", type=int, default=8900, help="TCP port to bind on (default: 8900)")
    parser.add_argument(
        "--plantuml-server",
        default="https://www.plantuml.com/plantuml",
        help="PlantUML server URI for UML image rendering (default: https://www.plantuml.com/plantuml)",
    )
    TaskHandler.add_args(parser)
    return parser.parse_args()  # type: ignore


def main() -> None:
    log.info("Starting up...")

    args = parse_args()
    log_format = "%(asctime)s [%(levelname)s] %(message)s [%(name)s]"
    logging.basicConfig(format=log_format, datefmt="%H:%M:%S", level=logging.getLevelName(args.log_level.upper()))

    if args.graphdb_type not in ("arangodb"):
        log.fatal(f"Unknown Graph DB type {args.graphdb_type}")
        sys.exit(1)

    scheduler = Scheduler()
    event_bus = EventBus()
    worker_task_queue = WorkerTaskQueue()
    http_client = ArangoHTTPClient(args.graphdb_request_timeout, not args.graphdb_no_ssl_verify)
    client = ArangoClient(hosts=args.graphdb_server, http_client=http_client)
    database = client.db(args.graphdb_database, username=args.graphdb_username, password=args.graphdb_password)
    adjuster = DirectAdjuster()
    db = DbAccess(database, event_bus, adjuster)
    model = ModelHandlerDB(db.get_model_db(), args.plantuml_server)
    cli_deps = CLIDependencies()
    cli = CLI(cli_deps, all_parts(cli_deps), dict(os.environ), aliases())

    subscriptions = SubscriptionHandler(db.subscribers_db, event_bus)
    task_handler = TaskHandler(db.running_task_db, db.job_db, event_bus, subscriptions, scheduler, cli, args)
    cli_deps.lookup = {
        "event_bus": event_bus,
        "db_access": db,
        "model_handler": model,
        "job_handler": task_handler,
        "worker_task_queue": worker_task_queue,
    }
    api = Api(db, model, subscriptions, task_handler, event_bus, worker_task_queue, cli)

    async def async_initializer() -> Application:
        await db.start()
        await subscriptions.start()
        # todo: how to use context managed objects with aiohttp?
        await task_handler.__aenter__()
        await scheduler.start()
        await worker_task_queue.start()
        log.info("Initialization done. Starting API.")
        return api.app

    web.run_app(async_initializer(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
