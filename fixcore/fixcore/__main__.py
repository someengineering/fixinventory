import asyncio
import logging
import platform
import sys
import traceback
import warnings
from argparse import Namespace
from asyncio import Queue
from contextlib import suppress
from datetime import timedelta
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import AsyncIterator, List, Union, cast

from aiohttp.web_app import Application
from attrs import evolve
from urllib3.exceptions import HTTPWarning

from fixcore import version
from fixcore.action_handlers.merge_outer_edge_handler import MergeOuterEdgesHandler
from fixcore.analytics import CoreEvent, NoEventSender
from fixcore.analytics.posthog import PostHogEventSender
from fixcore.analytics.recurrent_events import emit_recurrent_events
from fixcore.cli.cli import CLIService
from fixcore.cli.command import alias_names, all_commands
from fixcore.config.config_handler_service import ConfigHandlerService
from fixcore.config.config_override_service import ConfigOverrideService, model_from_db, override_config_for_startup
from fixcore.config.core_config_handler import CoreConfigHandler
from fixcore.core_config import (
    config_from_db,
    RunConfig,
    inside_docker,
    inside_kubernetes,
    helm_installation,
    FixCoreConfigId,
    parse_config,
    CoreConfig,
)
from fixcore.db import SystemData
from fixcore.db.db_access import DbAccess, CurrentDatabaseVersion
from fixcore.db.system_data_db import EphemeralJwtSigningKey
from fixcore.dependencies import Dependencies, ServiceNames, TenantDependencies
from fixcore.dependencies import (
    TenantDependencyProvider,
    FromRequestTenantDependencyProvider,
    DirectTenantDependencyProvider,
)
from fixcore.error import RestartService
from fixcore.graph_manager.graph_manager import GraphManager
from fixcore.infra_apps.local_runtime import LocalfixcoreAppRuntime
from fixcore.infra_apps.package_manager import PackageManager
from fixcore.message_bus import MessageBus
from fixcore.model.db_updater import GraphMerger
from fixcore.model.model_handler import ModelHandlerDB, ModelHandlerFromCodeAndDB
from fixcore.model.typed_model import to_json, class_fqn
from fixcore.query.template_expander_service import TemplateExpanderService
from fixcore.report.inspector_service import InspectorService
from fixcore.system_start import db_access, setup_process, parse_args, system_info, reconfigure_logging
from fixcore.task.scheduler import APScheduler, NoScheduler
from fixcore.task.subscribers import SubscriptionHandlerService
from fixcore.task.task_handler import TaskHandlerService
from fixcore.user.user_management import UserManagementService
from fixcore.util import shutdown_process, utc
from fixcore.web.accesslog import FixInventoryAccessLogger
from fixcore.web.api import Api
from fixcore.web.certificate_handler import CertificateHandlerWithCA, CertificateHandlerNoCA
from fixcore.worker_task_queue import WorkerTaskQueue
from fixlib.asynchronous.web import runner
from fixlib.utils import ensure_bw_compat

log = logging.getLogger("fixcore")


def main() -> None:
    """
    Application entrypoint - no arguments are allowed.
    """
    ensure_bw_compat()
    try:
        run(sys.argv[1:])
        log.info("Process finished.")
    except (KeyboardInterrupt, SystemExit):
        log.info("Stopping fix graph core.")
        shutdown_process(0)
    except Exception as ex:
        if "--debug" in sys.argv:
            print(traceback.format_exc())
        print(f"fixcore stopped. Reason {class_fqn(ex)}: {ex}", file=sys.stderr)
        shutdown_process(1)


def run(arguments: List[str]) -> None:
    """
    Run application. When this method returns, the process is done.
    :param arguments: the arguments provided to this process.
                 Note: this method is used in tests to specify arbitrary arguments.
    """
    args = parse_args(arguments)
    setup_process(args)

    # after setup, logging is possible
    info = system_info()
    log.info(
        f"Starting up version={info.version} on system with cpus={info.cpus}, "
        f"available_mem={info.mem_available}, total_mem={info.mem_total}"
    )

    # The loop is here to restart the process in case of RestartService exceptions.
    while True:
        try:
            run_process(args)
            break  # This line should never be reached. In case it does, break the loop.
        except RestartService as ex:
            message = f"Restarting Service. Reason: {ex.reason}"
            line = "-" * len(message)
            print(f"\n{line}\n{message}\n{line}\n")


def run_process(args: Namespace) -> None:
    with TemporaryDirectory() as temp_name:
        temp = Path(temp_name)
        if args.multi_tenant_setup:
            deps = Dependencies(system_info=system_info())
            deps.add(ServiceNames.temp_dir, temp)
            config = deps.add(ServiceNames.config, parse_config(args, {}, lambda: None))
            # jwt_signing_keys are not required for multi-tenant setup.
            deps.add(ServiceNames.jwt_signing_key_holder, EphemeralJwtSigningKey())
            cert_handler_no_ca = deps.add(ServiceNames.cert_handler, CertificateHandlerNoCA.lookup(config, temp))
            verify: Union[bool, str] = False if args.graphdb_no_ssl_verify else str(cert_handler_no_ca.ca_bundle)
            deps.add(ServiceNames.config, evolve(config, run=RunConfig(temp, verify)))
            deps.add(ServiceNames.system_data, SystemData("multi-tenant", utc(), CurrentDatabaseVersion))
            deps.add(
                ServiceNames.event_sender,
                PostHogEventSender(deps.system_data) if config.runtime.usage_metrics else NoEventSender(),
            )

            provider: TenantDependencyProvider = deps.add(
                ServiceNames.tenant_dependency_provider, FromRequestTenantDependencyProvider(deps)
            )
            created = False
        else:
            with warnings.catch_warnings():  # ignore ssl errors during setup
                deps = TenantDependencies(system_info=system_info())
                deps.add(ServiceNames.temp_dir, temp)
                warnings.simplefilter("ignore", HTTPWarning)
                # wait here for an initial connection to the database before we continue. blocking!
                created, system_data, sdb = DbAccess.connect(args, timedelta(seconds=120), verify=False)
                deps.add(ServiceNames.system_data, system_data)
                # only to be used for CoreConfig creation
                core_config_override_service = asyncio.run(override_config_for_startup(args.config_override_path))
                config = config_from_db(args, sdb, lambda: core_config_override_service.get_override(FixCoreConfigId))
                cert_handler = deps.add(ServiceNames.cert_handler, CertificateHandlerWithCA.lookup(config, sdb, temp))
                verify = False if args.graphdb_no_ssl_verify else str(cert_handler.ca_bundle)
                deps.add(ServiceNames.config, evolve(config, run=RunConfig(temp, verify)))
                # in case of tls: connect again with the correct certificate settings
                use_tls = args.graphdb_server.startswith("https://")
                sdb = DbAccess.connect(args, timedelta(seconds=30), verify=verify)[2] if use_tls else sdb
                deps.add(ServiceNames.system_database, sdb)
                event_sender = deps.add(
                    ServiceNames.event_sender,
                    PostHogEventSender(deps.system_data) if config.runtime.usage_metrics else NoEventSender(),
                )
                dba = deps.add(ServiceNames.db_access, db_access(config, sdb, event_sender))
                deps.add(ServiceNames.jwt_signing_key_holder, dba.system_data_db)
                provider = deps.add(ServiceNames.tenant_dependency_provider, DirectTenantDependencyProvider(deps))

        with_config(config, deps, provider, created)


async def direct_tenant(deps: TenantDependencies) -> None:
    config = deps.config
    event_sender = deps.event_sender
    db = deps.service(ServiceNames.db_access, DbAccess)
    message_bus = deps.add(ServiceNames.message_bus, MessageBus())
    scheduler = deps.add(ServiceNames.scheduler, APScheduler() if not config.args.no_scheduling else NoScheduler())
    model = deps.add(ServiceNames.model_handler, ModelHandlerDB(db, config.runtime.plantuml_server))
    worker_task_queue = deps.add(ServiceNames.worker_task_queue, WorkerTaskQueue())
    # a "real" config override deps.add, unlike the one used for core config
    config_override_service = deps.add(
        ServiceNames.config_override,
        ConfigOverrideService(config.args.config_override_path, partial(model_from_db, db.configs_model_db)),
    )
    config_handler = deps.add(
        ServiceNames.config_handler,
        ConfigHandlerService(
            db.config_entity_db,
            db.config_validation_entity_db,
            db.configs_model_db,
            worker_task_queue,
            message_bus,
            event_sender,
            config,
            config_override_service,
        ),
    )
    deps.add(ServiceNames.user_management, UserManagementService(db, config_handler, event_sender))
    default_env = {"graph": config.cli.default_graph, "section": config.cli.default_section}
    cli = deps.add(ServiceNames.cli, CLIService(deps, all_commands(deps), default_env, alias_names()))
    deps.add(ServiceNames.template_expander, TemplateExpanderService(db.template_entity_db, cli))
    inspector = deps.add(ServiceNames.inspector, InspectorService(cli))
    subscriptions = deps.add(ServiceNames.subscription_handler, SubscriptionHandlerService(message_bus))
    core_config_handler = deps.add(
        ServiceNames.core_config_handler,
        CoreConfigHandler(config, message_bus, worker_task_queue, config_handler, event_sender, inspector),
    )
    deps.add(ServiceNames.infra_apps_runtime, LocalfixcoreAppRuntime(cli))
    deps.add(
        ServiceNames.infra_apps_package_manager,
        PackageManager(
            db.package_entity_db, config_handler, cli.register_infra_app_alias, cli.unregister_infra_app_alias
        ),
    )
    graph_merger = deps.add(ServiceNames.graph_merger, GraphMerger(model, event_sender, config, message_bus))
    task_handler = deps.add(
        ServiceNames.task_handler,
        TaskHandlerService(
            db.running_task_db,
            db.job_db,
            message_bus,
            event_sender,
            subscriptions,
            graph_merger,
            scheduler,
            cli,
            config,
        ),
    )
    deps.add(ServiceNames.graph_manager, GraphManager(db, config, core_config_handler, task_handler))
    deps.add(
        ServiceNames.merge_outer_edges_handler,
        MergeOuterEdgesHandler(message_bus, subscriptions, task_handler, db, model),
    )
    deps.add(
        ServiceNames.event_emitter_periodic,
        emit_recurrent_events(
            event_sender,
            model,
            subscriptions,
            worker_task_queue,
            message_bus,
            timedelta(hours=1),
            timedelta(hours=1),
        ),
    )
    # queue must be created inside an async function!
    deps.add(ServiceNames.forked_tasks, Queue())


async def multi_tenancy(deps: Dependencies) -> None:
    deps.add(ServiceNames.message_bus, MessageBus())
    deps.add(ServiceNames.forked_tasks, Queue())
    InspectorService.on_startup()
    ModelHandlerFromCodeAndDB.on_startup()


def with_config(
    config: CoreConfig, deps: Dependencies, tenant_dep_provider: TenantDependencyProvider, created: bool
) -> None:
    reconfigure_logging(config)  # based on the config, logging might have changed
    # only lg the editable config - to not log any passwords
    log.debug(f"Starting with config: {config.editable}")
    api = deps.add("api", Api(deps, tenant_dep_provider))

    async def on_start() -> None:
        # fill all dependencies
        if config.multi_tenant_setup:
            await multi_tenancy(deps)
        else:
            await direct_tenant(cast(TenantDependencies, deps))
        # start all dependencies
        await deps.start()
        # Send initial creation event
        if created:
            docker = inside_docker()
            kubernetes = inside_kubernetes()
            helm = helm_installation()
            await deps.event_sender.core_event(
                CoreEvent.SystemInstalled,
                {
                    "docker_install": docker,
                    "k8s_install": kubernetes,
                    "helm_install": helm,
                    "pip_install": not (docker or kubernetes or helm),
                },
            )

        await deps.event_sender.core_event(
            CoreEvent.SystemStarted,
            {
                "version": version(),
                "created_at": to_json(deps.system_data.created_at),
                "system": platform.system(),
                "platform": platform.platform(),
                "inside_docker": deps.system_info.inside_docker,
            },
            cpu_count=deps.system_info.cpus,
            mem_total=deps.system_info.mem_total,
            mem_available=deps.system_info.mem_available,
        )

    async def on_stop() -> None:
        duration = utc() - deps.system_info.started_at
        await deps.event_sender.core_event(CoreEvent.SystemStopped, total_seconds=int(duration.total_seconds()))
        await deps.stop()

    async def async_initializer() -> Application:
        async def clean_all_tasks() -> None:
            log.info("Clean up all running tasks.")
            for task in asyncio.all_tasks():
                with suppress(asyncio.CancelledError):
                    if not task.done() or not task.cancelled():
                        task.cancel()
                    log.debug(f"Wait for task: {task}")
                    await task

        async def on_start_stop(_: Application) -> AsyncIterator[None]:
            await on_start()
            log.info("Initialization done. Starting API.")
            yield
            log.info("Shutdown initiated. Stop all tasks.")
            await on_stop()
            await clean_all_tasks()

        api.app.cleanup_ctx.append(on_start_stop)
        return api.app

    runner.run_app(
        async_initializer(),
        api.stop,
        host=config.api.web_hosts,
        https_port=config.api.https_port,
        http_port=config.api.http_port,
        default_port=8900,
        ssl_context=deps.cert_handler.host_context,
        access_log_class=FixInventoryAccessLogger,
    )


if __name__ == "__main__":
    main()
