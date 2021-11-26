import logging
import multiprocessing
import os
import platform
from datetime import timedelta
from typing import AsyncIterator

import psutil
from aiohttp import web
from aiohttp.web_app import Application

from core import version
from core.analytics import CoreEvent, NoEventSender
from core.analytics.posthog import PostHogEventSender
from core.analytics.recurrent_events import emit_recurrent_events
from core.cli.cli import CLI
from core.cli.command import aliases, CLIDependencies, all_commands
from core.db.db_access import DbAccess
from core.dependencies import db_access, setup_process, parse_args
from core.message_bus import MessageBus
from core.model.model_handler import ModelHandlerDB
from core.model.typed_model import to_js
from core.query.template_expander import DBTemplateExpander
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
        f"Starting up version={version()} on system with cpus={cpus}, "
        f"available_mem={mem.available}, total_mem={mem.total}"
    )
    started_at = utc()
    args = parse_args()
    setup_process(args)

    # wait here for an initial connection to the database before we continue. blocking!
    created, system_data, sdb = DbAccess.connect(args, timedelta(seconds=60))
    event_sender = NoEventSender() if args.analytics_opt_out else PostHogEventSender(system_data)
    db = db_access(sdb, event_sender)
    message_bus = MessageBus()
    scheduler = Scheduler()
    worker_task_queue = WorkerTaskQueue()
    model = ModelHandlerDB(db.get_model_db(), args.plantuml_server)
    template_expander = DBTemplateExpander(db.template_entity_db)
    cli_deps = CLIDependencies(
        message_bus=message_bus,
        event_sender=event_sender,
        db_access=db,
        model_handler=model,
        worker_task_queue=worker_task_queue,
        args=args,
        template_expander=template_expander,
    )
    cli = CLI(cli_deps, all_commands(cli_deps), {}, aliases())
    subscriptions = SubscriptionHandler(db.subscribers_db, message_bus)
    task_handler = TaskHandler(
        db.running_task_db, db.job_db, message_bus, event_sender, subscriptions, scheduler, cli, args
    )
    cli_deps.extend(job_handler=task_handler)
    api = Api(
        db,
        model,
        subscriptions,
        task_handler,
        message_bus,
        event_sender,
        worker_task_queue,
        cli,
        template_expander,
        args,
    )
    event_emitter = emit_recurrent_events(
        event_sender, model, subscriptions, worker_task_queue, message_bus, timedelta(hours=1)
    )

    async def on_start() -> None:
        if created:
            await event_sender.core_event(CoreEvent.SystemInstalled)
        await event_sender.core_event(
            CoreEvent.SystemStarted,
            {
                "version": version(),
                "created_at": to_js(system_data.created_at),
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
        await event_emitter.stop()

    async def async_initializer() -> Application:
        async def on_start_stop(_: Application) -> AsyncIterator[None]:
            await on_start()
            yield
            await on_stop()

        async def manage_task_handler(_: Application) -> AsyncIterator[None]:
            async with task_handler:
                yield  # none is yielded: we only want to start/stop the task_handler reliably

        async def manage_event_sender(_: Application) -> AsyncIterator[None]:
            async with event_sender:
                yield  # none is yielded: we only want to start/stop the event_sender reliably

        api.app.cleanup_ctx.append(manage_event_sender)
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
