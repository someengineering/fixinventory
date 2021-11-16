import logging
import multiprocessing
import os
import platform
from datetime import timedelta
from typing import AsyncIterator

import psutil
from aiohttp import web
from aiohttp.web_app import Application

from core import __version__
from core.analytics import NoEventSender, CoreEvent
from core.analytics.recurrent_events import emit_recurrent_events
from core.cli.cli import CLI
from core.cli.command import aliases, CLIDependencies, all_commands
from core.dependencies import db_access, setup_process, parse_args
from core.message_bus import MessageBus
from core.model.model_handler import ModelHandlerDB
from core.task.scheduler import Scheduler
from core.task.subscribers import SubscriptionHandler
from core.task.task_handler import TaskHandler
from core.util import shutdown_process, utc
from core.web.api import Api
from core.worker_task_queue import WorkerTaskQueue

log = logging.getLogger(__name__)


def main() -> None:
    # os information
    cpus = multiprocessing.cpu_count()
    mem = psutil.virtual_memory()
    in_docker = os.path.exists("/.dockerenv")  # this file is created by the docker runtime
    log.info(
        f"Starting up version={__version__} on system with cpus={cpus}, "
        f"available_mem={mem.available}, total_mem={mem.total}"
    )
    started_at = utc()
    args = parse_args()
    setup_process(args)

    message_bus = MessageBus()
    event_sender = NoEventSender()
    db = db_access(args, event_sender)
    # wait here for an initial connection to the database before we continue
    db.wait_for_initial_connect(timedelta(seconds=60))

    scheduler = Scheduler()
    worker_task_queue = WorkerTaskQueue()
    model = ModelHandlerDB(db.get_model_db(), args.plantuml_server)
    cli_deps = CLIDependencies(
        message_bus=message_bus,
        event_sender=event_sender,
        db_access=db,
        model_handler=model,
        worker_task_queue=worker_task_queue,
        args=args,
    )
    cli = CLI(cli_deps, all_commands(cli_deps), dict(os.environ), aliases())
    subscriptions = SubscriptionHandler(db.subscribers_db, message_bus)
    task_handler = TaskHandler(db.running_task_db, db.job_db, message_bus, subscriptions, scheduler, cli, args)
    cli_deps.extend(job_handler=task_handler)

    api = Api(db, model, subscriptions, task_handler, message_bus, event_sender, worker_task_queue, cli, args)
    event_emitter = emit_recurrent_events(
        event_sender, model, subscriptions, worker_task_queue, message_bus, timedelta(hours=1)
    )

    async def on_start() -> None:
        await event_sender.core_event(
            CoreEvent.SystemStarted,
            {
                "version": __version__,
                "system": platform.system(),
                "platform": platform.platform(),
                "inside_docker": in_docker,
            },
            cpu_count=cpus,
            mem_total=mem.total,
            mem_available=mem.available,
        )
        await db.start()
        await subscriptions.start()
        await scheduler.start()
        await worker_task_queue.start()
        await event_emitter.start()

    async def on_stop() -> None:
        duration = utc() - started_at
        await event_sender.core_event(CoreEvent.SystemStopped, total_seconds=int(duration.total_seconds()))
        await event_sender.flush()
        await event_emitter.stop()

    async def async_initializer() -> Application:
        async def on_start_stop(_: Application) -> AsyncIterator[None]:
            await on_start()
            yield
            await on_stop()

        async def manage_task_handler(_: Application) -> AsyncIterator[None]:
            async with task_handler:
                yield  # none is yielded: we only want to start/stop the task_handler reliably

        api.app.cleanup_ctx.append(on_start_stop)
        api.app.cleanup_ctx.append(manage_task_handler)
        log.info("Initialization done. Starting API.")
        return api.app

    web.run_app(async_initializer(), host=args.host, port=args.port)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        log.info("Stopping Cloudkeeper graph core.")
        shutdown_process(0)
    except Exception as ex:
        log.info(f"ckcore stopped. Reason: {ex}")
        shutdown_process(1)
