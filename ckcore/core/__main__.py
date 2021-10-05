import logging
import os

from aiohttp import web
from aiohttp.web_app import Application

from core.cli.cli import CLIDependencies, CLI
from core.cli.command import all_parts, aliases
from core.dependencies import db_access, setup_process, parse_args
from core.event_bus import EventBus
from core.model.model_handler import ModelHandlerDB
from core.task.scheduler import Scheduler
from core.task.subscribers import SubscriptionHandler
from core.task.task_handler import TaskHandler
from core.web.api import Api
from core.worker_task_queue import WorkerTaskQueue

log = logging.getLogger(__name__)


def main() -> None:

    args = parse_args()
    setup_process(args)

    log.info("Starting up...")
    scheduler = Scheduler()
    event_bus = EventBus()
    worker_task_queue = WorkerTaskQueue()
    db = db_access(args, event_bus)
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
    api = Api(db, model, subscriptions, task_handler, event_bus, worker_task_queue, cli, args)

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
