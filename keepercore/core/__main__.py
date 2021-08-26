import logging
import os
from argparse import ArgumentParser, Namespace

from aiohttp import web
from aiohttp.web_app import Application
from arango import ArangoClient

from core.cli.cli import CLIDependencies, CLI
from core.cli.command import all_parts
from core.db.arangodb_extensions import ArangoHTTPClient
from core.db.db_access import DbAccess
from core.event_bus import EventBus
from core.model.model_handler import ModelHandlerDB
from core.web.api import Api
from core.task.scheduler import Scheduler
from core.task.subscribers import SubscriptionHandler
from core.task.task_handler import TaskHandler

log = logging.getLogger(__name__)


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Maintains graphs of documents of any shape.", epilog="Keeps all the things.")
    parser.add_argument("--log-level", default="info", help="The threshold log level for the application log.")
    parser.add_argument("-s", "--arango-server", default="http://localhost:8529", help="The server to connect to.")
    parser.add_argument("-db", "--arango-database", default="cloudkeeper", help="The database to connect to.")
    parser.add_argument("-u", "--arango-username", default="cloudkeeper", help="The username of the database.")
    parser.add_argument("-p", "--arango-password", default="", help="The password the database.")
    parser.add_argument("--arango-no-ssl-verify", action="store_true", help="If the connection should be verified.")
    parser.add_argument("--arango-request-timeout", type=int, default=900, help="Request timeout in seconds.")
    parser.add_argument("--port", type=int, default=8080, help="TCP Port to bind on.")
    parser.add_argument(
        "--plantuml-server",
        default="https://www.plantuml.com/plantuml",
        help="The plantuml server to render plantuml images",
    )
    return parser.parse_args()


def main() -> None:
    log.info("Starting up...")

    args = parse_args()
    log_format = "%(asctime)s [%(levelname)s] %(message)s [%(name)s]"
    logging.basicConfig(format=log_format, datefmt="%H:%M:%S", level=logging.getLevelName(args.log_level.upper()))

    scheduler = Scheduler()
    event_bus = EventBus()
    http_client = ArangoHTTPClient(args.arango_request_timeout, not args.arango_no_ssl_verify)
    client = ArangoClient(hosts=args.arango_server, http_client=http_client)
    database = client.db(args.arango_database, username=args.arango_username, password=args.arango_password)
    db = DbAccess(database, event_bus)
    model = ModelHandlerDB(db.get_model_db(), args.plantuml_server)
    cli_deps = CLIDependencies(event_bus, db, model)
    cli = CLI(cli_deps, all_parts(cli_deps), dict(os.environ))

    subscriptions = SubscriptionHandler(db.subscribers_db, event_bus)
    workflow_handler = TaskHandler(db.running_task_db, event_bus, subscriptions, scheduler)

    api = Api(db, model, subscriptions, workflow_handler, event_bus, cli)

    async def async_initializer() -> Application:
        await db.start()
        await subscriptions.start()
        await workflow_handler.start()
        await scheduler.start()
        log.info("Initialization done. Starting API.")
        return api.app

    web.run_app(async_initializer(), port=args.port)


if __name__ == "__main__":
    main()
