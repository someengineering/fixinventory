from __future__ import annotations

import asyncio
import hashlib
import logging
from abc import abstractmethod, ABC
from asyncio import Queue, Task
from datetime import timedelta
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, TypeVar, Type, cast
from typing import Callable, Awaitable

from aiohttp import ClientSession, TCPConnector
from aiohttp.web import Request
from arango import ArangoServerError
from arango.client import ArangoClient
from arango.database import StandardDatabase
from attr import define

from fixcore.analytics import AnalyticsEventSender
from fixcore.async_extensions import run_async
from fixcore.cli.cli import CLIService
from fixcore.cli.command import all_commands, alias_names
from fixcore.cli.model import CLI
from fixcore.config import ConfigHandler, ConfigOverride, NoConfigOverride
from fixcore.config.config_handler_service import ConfigHandlerService
from fixcore.config.core_config_handler import CoreConfigHandler
from fixcore.core_config import CoreConfig
from fixcore.db import SystemData
from fixcore.db.arangodb_extensions import ArangoHTTPClient
from fixcore.db.db_access import DbAccess
from fixcore.db.system_data_db import JwtSigningKeyHolder
from fixcore.graph_manager.graph_manager import GraphManager
from fixcore.infra_apps.package_manager import PackageManager
from fixcore.infra_apps.runtime import Runtime
from fixcore.message_bus import MessageBus
from fixcore.metrics import timed
from fixcore.model.adjust_node import NoAdjust
from fixcore.model.db_updater import GraphMerger
from fixcore.model.model_handler import ModelHandler, ModelHandlerFromCodeAndDB
from fixcore.query.template_expander import TemplateExpander
from fixcore.query.template_expander_service import TemplateExpanderService
from fixcore.report import Inspector
from fixcore.report.inspector_service import InspectorService
from fixcore.service import Service
from fixcore.system_start import SystemInfo
from fixcore.task.scheduler import NoScheduler
from fixcore.task.subscribers import SubscriptionHandler, NoSubscriptionHandler
from fixcore.task.task_handler import TaskHandlerService
from fixcore.types import JsonElement
from fixcore.user import UserManagement
from fixcore.user.user_management import UserManagementService
from fixcore.util import Periodic
from fixcore.web.certificate_handler import CertificateHandler
from fixcore.worker_task_queue import WorkerTaskQueue

T = TypeVar("T")
log = logging.getLogger(__name__)


class ServiceNames:
    temp_dir = "temp_dir"
    cert_handler = "cert_handler"
    cli = "cli"
    config = "config"
    config_handler = "config_handler"
    config_override = "config_override"
    core_config_handler = "core_config_handler"
    db_access = "db_access"
    event_emitter_periodic = "event_emitter_periodic"
    event_sender = "event_sender"
    forked_tasks = "forked_tasks"
    graph_manager = "graph_manager"
    graph_merger = "graph_merger"
    http_session = "http_session"
    infra_apps_package_manager = "infra_apps_package_manager"
    infra_apps_runtime = "infra_apps_runtime"
    inspector = "inspector"
    jwt_signing_key_holder = "jwt_signing_key_holder"
    merge_outer_edges_handler = "merge_outer_edges_handler"
    message_bus = "message_bus"
    model_handler = "model_handler"
    scheduler = "scheduler"
    subscription_handler = "subscription_handler"
    system_data = "system_data"
    system_database = "system_database"
    system_info = "system_info"
    task_handler = "task_handler"
    template_expander = "template_expander"
    user_management = "user_management"
    worker_task_queue = "worker_task_queue"
    tenant_dependency_provider = "tenant_dependency_provider"


class Dependencies(Service):
    def __init__(self, **deps: Any) -> None:
        super().__init__()
        self.lookup: Dict[str, Any] = deps
        self.on_stop_callbacks: List[Callable[[], None]] = []

    def add(self, name: str, service: T) -> "T":
        self.lookup[name] = service
        return service

    def extend(self, **deps: Any) -> "Dependencies":
        self.lookup = {**self.lookup, **deps}
        return self

    def get(self, name: str) -> Optional[Any]:
        return self.lookup.get(name)

    def all(self) -> Dict[str, Any]:
        return self.lookup

    def register_on_stop_callback(self, callback: Callable[[], None]) -> None:
        self.on_stop_callbacks.append(callback)

    @property
    def services(self) -> List[Service]:
        return [v for _, v in self.all().items() if isinstance(v, Service)]

    @property
    def tenant_dependency_provider(self) -> TenantDependencyProvider:
        return self.service(ServiceNames.tenant_dependency_provider, TenantDependencyProvider)  # type: ignore

    @property
    def config(self) -> CoreConfig:
        return self.service(ServiceNames.config, CoreConfig)

    @property
    def temp_dir(self) -> Path:
        return self.service(ServiceNames.temp_dir, Path)

    @property
    def message_bus(self) -> MessageBus:
        return self.service(ServiceNames.message_bus, MessageBus)

    @property
    def event_sender(self) -> AnalyticsEventSender:
        return self.service(ServiceNames.event_sender, AnalyticsEventSender)  # type: ignore

    @property
    def worker_task_queue(self) -> WorkerTaskQueue:
        return self.service(ServiceNames.worker_task_queue, WorkerTaskQueue)

    @property
    def jwt_signing_key_holder(self) -> JwtSigningKeyHolder:
        return self.service(ServiceNames.jwt_signing_key_holder, JwtSigningKeyHolder)  # type: ignore

    @property
    def system_info(self) -> SystemInfo:
        return self.service(ServiceNames.system_info, SystemInfo)

    @property
    def system_data(self) -> SystemData:
        return self.service(ServiceNames.system_data, SystemData)

    @property
    def forked_tasks(self) -> Queue[Tuple[Task[JsonElement], str]]:
        return self.service(ServiceNames.forked_tasks, Any)  # type:ignore

    @property
    def cert_handler(self) -> CertificateHandler:
        return self.service(ServiceNames.cert_handler, CertificateHandler)

    @property
    def http_session(self) -> ClientSession:
        session: Optional[ClientSession] = self.get(ServiceNames.http_session)
        if not session:
            connector = TCPConnector(limit=0, ssl=False, ttl_dns_cache=300)
            session = ClientSession(connector=connector)
            self.lookup[ServiceNames.http_session] = session
        return session

    def service(self, name: str, clazz: Type[T]) -> T:
        existing = self.get(name)
        if existing is None:
            raise KeyError(f"Service {name} not found")
        elif clazz is Any or isinstance(existing, clazz):
            return existing  # type: ignore
        else:
            raise ValueError(f"Service {name} is not of type {clazz}")

    def tenant_dependencies(self, **deps: Any) -> TenantDependencies:
        return TenantDependencies(nested=self, **deps)

    async def start(self) -> None:
        for service in self.services:
            await service.start()

    async def stop(self) -> None:
        if session := cast(Optional[ClientSession], self.get(ServiceNames.http_session)):
            log.debug("Closing http session")
            await session.close()
        for service in reversed(self.services):
            log.debug(f"Stopping service {service.__class__.__name__}")
            await service.stop()
        for callback in self.on_stop_callbacks:
            log.debug("Running on stop callback")
            callback()


class TenantDependencies(Dependencies):
    def __init__(self, nested: Optional[Dependencies] = None, **deps: Any) -> None:
        super().__init__(**deps)
        self.nested = nested or Dependencies()

    def get(self, name: str) -> Optional[Any]:
        if (defined := self.lookup.get(name)) is not None:
            return defined
        else:
            return self.nested.get(name)

    @property
    def subscription_handler(self) -> SubscriptionHandler:
        return self.service(ServiceNames.subscription_handler, SubscriptionHandler)  # type: ignore

    @property
    def config_handler(self) -> ConfigHandler:
        return self.service(ServiceNames.config_handler, ConfigHandler)  # type: ignore

    @property
    def db_access(self) -> DbAccess:
        return self.service(ServiceNames.db_access, DbAccess)

    @property
    def model_handler(self) -> ModelHandler:
        return self.service(ServiceNames.model_handler, ModelHandler)  # type: ignore

    @property
    def inspector(self) -> Inspector:
        return self.service(ServiceNames.inspector, Inspector)  # type: ignore

    @property
    def infra_apps_runtime(self) -> Runtime:
        return self.service(ServiceNames.infra_apps_runtime, Runtime)  # type: ignore

    @property
    def infra_apps_package_manager(self) -> PackageManager:
        return self.service(ServiceNames.infra_apps_package_manager, PackageManager)

    @property
    def user_management(self) -> UserManagement:
        return self.service(ServiceNames.user_management, UserManagement)  # type: ignore

    @property
    def graph_manager(self) -> GraphManager:
        return self.service(ServiceNames.graph_manager, GraphManager)

    @property
    def graph_merger(self) -> GraphMerger:
        return self.service(ServiceNames.graph_merger, GraphMerger)

    @property
    def config_override(self) -> ConfigOverride:
        return self.service(ServiceNames.config_override, ConfigOverride)  # type: ignore

    @property
    def template_expander(self) -> TemplateExpander:
        return self.service(ServiceNames.template_expander, TemplateExpander)  # type: ignore

    @property
    def task_handler(self) -> TaskHandlerService:
        return self.service(ServiceNames.task_handler, TaskHandlerService)

    @property
    def cli(self) -> CLI:
        return self.service(ServiceNames.cli, CLI)  # type: ignore


class TenantDependencyProvider(Service, ABC):
    @abstractmethod
    async def dependencies(self, request: Request) -> TenantDependencies:
        pass


class DirectTenantDependencyProvider(TenantDependencyProvider):
    def __init__(self, dependencies: TenantDependencies) -> None:
        super().__init__()
        self._dependencies = dependencies

    async def dependencies(self, _: Request) -> TenantDependencies:
        return self._dependencies


class TenantDependencyCache(Service):
    def __init__(
        self, ttl: timedelta, check_frequency: timedelta, time_fn: Optional[Callable[[], float]] = None
    ) -> None:
        super().__init__()
        self._ttl = ttl.total_seconds()
        self._cache: Dict[str, Tuple[float, TenantDependencies]] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._locks_lock: Optional[asyncio.Lock] = None
        self.periodic = Periodic("tenant_dependency_cache", self._expire, check_frequency)
        self.time_fn = time_fn

    async def start(self) -> Any:
        self._locks_lock = asyncio.Lock()
        await self.periodic.start()

    async def stop(self) -> None:
        await self.periodic.stop()
        for _, value in self._cache.values():
            await value.stop()

    def _time(self) -> float:
        return (self.time_fn or asyncio.get_event_loop().time)()

    async def _lock_for(self, key: str) -> asyncio.Lock:
        assert self._locks_lock is not None, "TenantDependencyCache not started"
        async with self._locks_lock:
            if lock := self._locks.get(key):
                return lock
            else:
                lock = asyncio.Lock()
                self._locks[key] = lock
                return lock

    async def _expire(self) -> None:
        now = self._time()
        to_delete: List[Tuple[str, TenantDependencies]] = []
        for key, (timestamp, value) in list(self._cache.items()):
            if now - timestamp > self._ttl:
                lock = await self._lock_for(key)
                async with lock:
                    # test again with lock
                    if (item := self._cache.get(key)) and now - item[0] > self._ttl and item[1] is not None:
                        self._cache.pop(key, None)
                        to_delete.append((key, item[1]))
        for key, value in to_delete:
            log.info(f"Stop tenant dependencies for {key}")
            try:
                await asyncio.wait_for(value.stop(), timeout=60)  # should not take longer than 60 seconds
                log.info(f"Tenant dependencies for {key} stopped.")
            except Exception as e:
                log.error(f"Failed to stop tenant dependencies for {key}: {e}", exc_info=True)

    async def get(self, key: str, if_empty: Callable[[], Awaitable[TenantDependencies]]) -> TenantDependencies:
        now = self._time()
        lck = await self._lock_for(key)
        try:
            async with lck:
                if result := self._cache.get(key):
                    _, value = result
                else:
                    log.info(f"Create and start new tenant dependencies for {key}")
                    value = await if_empty()
                    await value.start()
                    log.info(f"Tenant dependencies for {key} created.")
                self._cache[key] = (now, value)
                return value
        except Exception as e:
            log.exception(f"Failed to create tenant dependencies for {key}: {e}", exc_info=True)
            raise


@define
class GraphDbAccess:
    server: str
    database: str
    username: str
    password: str
    create_database: bool = False

    def is_valid(self) -> bool:
        return bool(self.server and self.database and self.username)

    def hash(self) -> str:
        sha256 = hashlib.sha256()
        for key in ["server", "database", "username", "password"]:
            value = getattr(self, key)
            sha256.update(value.encode("utf-8"))
        return sha256.hexdigest()


class FromRequestTenantDependencyProvider(TenantDependencyProvider):
    def __init__(self, dependencies: Dependencies) -> None:
        super().__init__()
        self._dependencies = dependencies
        self._cache = TenantDependencyCache(ttl=timedelta(minutes=5), check_frequency=timedelta(seconds=30))

    async def start(self) -> None:
        await self._cache.start()

    async def stop(self) -> None:
        await self._cache.stop()

    @timed("tenant_dependency_provider", "dependencies")
    async def dependencies(self, request: Request) -> TenantDependencies:
        db_access = GraphDbAccess(
            request.headers.get("FixGraphDbServer", ""),
            request.headers.get("FixGraphDbDatabase", ""),
            request.headers.get("FixGraphDbUsername", ""),
            request.headers.get("FixGraphDbPassword", ""),
            request.headers.get("FixGraphDbCreateDatabase", "false").lower() == "true",
        )
        if not db_access.is_valid():
            raise ValueError("Invalid graph db access data provided for multi tenant requests!")
        key = db_access.hash()
        return await self._cache.get(key, partial(self.create_tenant_dependencies, key, db_access))

    async def create_tenant_dependencies(self, tenant_hash: str, access: GraphDbAccess) -> TenantDependencies:
        dp = self._dependencies
        config = dp.config
        args = dp.config.args
        message_bus = dp.message_bus
        event_sender = dp.event_sender
        deps = dp.tenant_dependencies(tenant_hash=tenant_hash, access=access)

        def standard_database() -> StandardDatabase:
            http_client = ArangoHTTPClient(args.graphdb_request_timeout, verify=dp.config.run.verify)
            client = ArangoClient(hosts=access.server, http_client=http_client)
            deps.register_on_stop_callback(client.close)
            tdb = client.db(name=access.database, username=access.username, password=access.password)
            # create database if requested
            if access.create_database:
                try:
                    tdb.echo()
                    log.warning(f"Tenant: {tenant_hash}: Create database requested but it already exists!")
                except ArangoServerError as ex:
                    if ex.error_code in (11, 1228, 1703):
                        DbAccess.create_database(
                            server=access.server,
                            database=access.database,
                            username=access.username,
                            password=access.password,
                            root_password=args.graphdb_root_password,
                            request_timeout=args.graphdb_request_timeout,
                            secure_root=False,
                        )
                    else:
                        raise
            return tdb

        # direct db access
        sdb = deps.add(ServiceNames.system_database, await run_async(standard_database))
        db = deps.add(ServiceNames.db_access, DbAccess(sdb, dp.event_sender, NoAdjust(), config))
        # no scheduler required in multi-tenant mode
        scheduler = deps.add(ServiceNames.scheduler, NoScheduler())
        # all tenants use the same model (derived from code)
        model = deps.add(ServiceNames.model_handler, ModelHandlerFromCodeAndDB(db, config.runtime.plantuml_server))
        worker_task_queue = deps.add(ServiceNames.worker_task_queue, WorkerTaskQueue())
        config_override_service = deps.add(ServiceNames.config_override, NoConfigOverride())
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
        subscriptions = deps.add(ServiceNames.subscription_handler, NoSubscriptionHandler())
        core_config_handler = deps.add(
            ServiceNames.core_config_handler,
            CoreConfigHandler(config, message_bus, worker_task_queue, config_handler, event_sender, inspector),
        )
        # Enable package manager and runtime for infra apps when required
        # deps.add(ServiceNames.infra_apps_runtime, LocalfixcoreAppRuntime(cli))
        # deps.add(ServiceNames.infra_apps_package_manager, PackageManager(db.package_entity_db, config_handler, cli.register_infra_app_alias, cli.unregister_infra_app_alias)) # noqa
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
        return deps
