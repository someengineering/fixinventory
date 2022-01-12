import logging
import multiprocessing
import os
import platform
import ssl
from asyncio import Queue
from datetime import timedelta
from ssl import SSLContext
from typing import AsyncIterator, Optional, List

import psutil
import sys
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
from core.model.typed_model import to_json, class_fqn
from core.query.template_expander import DBTemplateExpander
from core.task.scheduler import Scheduler
from core.task.subscribers import SubscriptionHandler
from core.task.task_handler import TaskHandler
from core.util import shutdown_process, utc
from core.web import runner
from core.web.api import Api
from core.web.certificate_handler import CertificateHandler
from core.worker_task_queue import WorkerTaskQueue

log = logging.getLogger(__name__)


def main() -> None:
    """
    Application entrypoint - no arguments are allowed.
    """
    run(sys.argv[1:])


def run(args: List[str]) -> None:
    """
    Run application. When this method returns, the process is done.
    :param args: the arguments provided to this process.
                 Note: this method is used in tests to specify arbitrary arguments.
    """

    # os information
    cpus = multiprocessing.cpu_count()
    mem = psutil.virtual_memory()
    inside_docker = os.path.exists("/.dockerenv")  # this file is created by the docker runtime
    started_at = utc()
    conf = parse_args(args)
    setup_process(conf)

    # after setup, logging is possible
    log.info(
        f"Starting up version={version()} on system with cpus={cpus}, "
        f"available_mem={mem.available}, total_mem={mem.total}"
    )

    # wait here for an initial connection to the database before we continue. blocking!
    created, system_data, sdb = DbAccess.connect(conf, timedelta(seconds=60))
    event_sender = NoEventSender() if conf.analytics_opt_out else PostHogEventSender(system_data)
    db = db_access(sdb, event_sender)
    cert_handler = CertificateHandler.lookup(conf, sdb)
    message_bus = MessageBus()
    scheduler = Scheduler()
    worker_task_queue = WorkerTaskQueue()
    model = ModelHandlerDB(db.get_model_db(), conf.plantuml_server)
    template_expander = DBTemplateExpander(db.template_entity_db)
    cli_deps = CLIDependencies(
        message_bus=message_bus,
        event_sender=event_sender,
        db_access=db,
        model_handler=model,
        worker_task_queue=worker_task_queue,
        args=conf,
        template_expander=template_expander,
    )
    cli = CLI(cli_deps, all_commands(cli_deps), {}, aliases())
    subscriptions = SubscriptionHandler(db.subscribers_db, message_bus)
    task_handler = TaskHandler(
        db.running_task_db, db.job_db, message_bus, event_sender, subscriptions, scheduler, cli, conf
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
        cert_handler,
        cli,
        template_expander,
        conf,
    )
    event_emitter = emit_recurrent_events(
        event_sender, model, subscriptions, worker_task_queue, message_bus, timedelta(hours=1)
    )

    async def on_start() -> None:
        # queue must be created inside an async function!
        cli_deps.extend(forked_tasks=Queue())
        await db.start()
        await event_sender.start()
        await subscriptions.start()
        await scheduler.start()
        await worker_task_queue.start()
        await event_emitter.start()
        await cli.start()
        await task_handler.start()
        await api.start()
        if created:
            await event_sender.core_event(CoreEvent.SystemInstalled)
        await event_sender.core_event(
            CoreEvent.SystemStarted,
            {
                "version": version(),
                "created_at": to_json(system_data.created_at),
                "system": platform.system(),
                "platform": platform.platform(),
                "inside_docker": inside_docker,
            },
            cpu_count=cpus,
            mem_total=mem.total,
            mem_available=mem.available,
        )

    async def on_stop() -> None:
        duration = utc() - started_at
        await api.stop()
        await task_handler.stop()
        await cli.stop()
        await event_sender.core_event(CoreEvent.SystemStopped, total_seconds=int(duration.total_seconds()))
        await event_emitter.stop()
        await worker_task_queue.stop()
        await scheduler.stop()
        await subscriptions.stop()
        await db.stop()
        await event_sender.stop()

    async def async_initializer() -> Application:
        async def on_start_stop(_: Application) -> AsyncIterator[None]:
            await on_start()
            log.info("Initialization done. Starting API.")
            yield
            log.info("Shutdown initiated. Stop all tasks.")
            await on_stop()

        api.app.cleanup_ctx.append(on_start_stop)
        return api.app

    tls_context: Optional[SSLContext] = None
    if conf.tls_cert:
        tls_context = SSLContext(ssl.PROTOCOL_TLS)
        tls_context.load_cert_chain(conf.tls_cert, conf.tls_key, conf.tls_password)

    runner.run_app(async_initializer(), api.stop, host=conf.host, port=conf.port, ssl_context=tls_context)


if __name__ == "__main__":
    try:
        main()
        log.info("Process finished.")
    except (KeyboardInterrupt, SystemExit):
        log.info("Stopping Cloudkeeper graph core.")
        shutdown_process(0)
    except Exception as ex:
        print(f"ckcore stopped. Reason {class_fqn(ex)}: {ex}", file=sys.stderr)
        shutdown_process(1)
