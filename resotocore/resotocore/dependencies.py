from asyncio import Queue, Task
from typing import Any, Dict, List, Tuple, Optional, TypeVar, Type

from aiohttp import ClientSession, TCPConnector

from resotocore.analytics import AnalyticsEventSender
from resotocore.cli.model import CLI
from resotocore.config import ConfigHandler, ConfigOverride
from resotocore.core_config import CoreConfig
from resotocore.db.db_access import DbAccess
from resotocore.graph_manager.graph_manager import GraphManager
from resotocore.infra_apps.package_manager import PackageManager
from resotocore.infra_apps.runtime import Runtime
from resotocore.message_bus import MessageBus
from resotocore.model.db_updater import GraphMerger
from resotocore.model.model_handler import ModelHandler
from resotocore.query.template_expander import TemplateExpander
from resotocore.report import Inspector
from resotocore.service import Service
from resotocore.task.subscribers import SubscriptionHandler
from resotocore.task.task_handler import TaskHandlerService
from resotocore.types import JsonElement
from resotocore.user import UserManagement
from resotocore.web.certificate_handler import CertificateHandler
from resotocore.worker_task_queue import WorkerTaskQueue

T = TypeVar("T")


class ServiceNames:
    config = "config"
    message_bus = "message_bus"
    event_sender = "event_sender"
    db_access = "db_access"
    model_handler = "model_handler"
    task_handler = "task_handler"
    worker_task_queue = "worker_task_queue"
    template_expander = "template_expander"
    forked_tasks = "forked_tasks"
    cli = "cli"
    config_handler = "config_handler"
    cert_handler = "cert_handler"
    inspector = "inspector"
    infra_apps_runtime = "infra_apps_runtime"
    infra_apps_package_manager = "infra_apps_package_manager"
    user_management = "user_management"
    graph_manager = "graph_manager"
    subscription_handler = "subscription_handler"
    graph_merger = "graph_merger"
    config_override = "config_override"
    http_session = "http_session"
    scheduler = "scheduler"
    core_config_handler = "core_config_handler"
    merge_outer_edges_handler = "merge_outer_edges_handler"
    event_emitter_periodic = "event_emitter_periodic"


class Dependencies(Service):
    def __init__(self, **deps: Any) -> None:
        self.lookup: Dict[str, Any] = deps

    def add(self, name: str, service: T) -> "T":
        self.lookup[name] = service
        return service

    def extend(self, **deps: Any) -> "Dependencies":
        self.lookup = {**self.lookup, **deps}
        return self

    @property
    def services(self) -> List[Service]:
        return [v for _, v in self.lookup.items() if isinstance(v, Service)]

    @property
    def config(self) -> CoreConfig:
        return self.service(ServiceNames.config, CoreConfig)

    @property
    def message_bus(self) -> MessageBus:
        return self.service(ServiceNames.message_bus, MessageBus)

    @property
    def event_sender(self) -> AnalyticsEventSender:
        return self.service(ServiceNames.event_sender, AnalyticsEventSender)  # type: ignore

    @property
    def db_access(self) -> DbAccess:
        return self.service(ServiceNames.db_access, DbAccess)

    @property
    def model_handler(self) -> ModelHandler:
        return self.service(ServiceNames.model_handler, ModelHandler)  # type: ignore

    @property
    def task_handler(self) -> TaskHandlerService:
        return self.service(ServiceNames.task_handler, TaskHandlerService)

    @property
    def worker_task_queue(self) -> WorkerTaskQueue:
        return self.service(ServiceNames.worker_task_queue, WorkerTaskQueue)

    @property
    def template_expander(self) -> TemplateExpander:
        return self.service(ServiceNames.template_expander, TemplateExpander)  # type: ignore

    @property
    def forked_tasks(self) -> Queue[Tuple[Task[JsonElement], str]]:
        return self.lookup[ServiceNames.forked_tasks]  # type:ignore

    @property
    def cli(self) -> CLI:
        return self.service(ServiceNames.cli, CLI)  # type: ignore

    @property
    def config_handler(self) -> ConfigHandler:
        return self.service(ServiceNames.config_handler, ConfigHandler)  # type: ignore

    @property
    def cert_handler(self) -> CertificateHandler:
        return self.service(ServiceNames.cert_handler, CertificateHandler)

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
    def subscription_handler(self) -> SubscriptionHandler:
        return self.service(ServiceNames.subscription_handler, SubscriptionHandler)

    @property
    def graph_merger(self) -> GraphMerger:
        return self.service(ServiceNames.graph_merger, GraphMerger)

    @property
    def config_override(self) -> ConfigOverride:
        return self.service(ServiceNames.config_override, ConfigOverride)  # type: ignore

    @property
    def http_session(self) -> ClientSession:
        session: Optional[ClientSession] = self.lookup.get(ServiceNames.http_session)
        if not session:
            connector = TCPConnector(limit=0, ssl=False, ttl_dns_cache=300)
            session = ClientSession(connector=connector)
            self.lookup[ServiceNames.http_session] = session
        return session

    def service(self, name: str, clazz: Type[T]) -> T:
        if isinstance(existing := self.lookup.get(name), clazz):
            return existing
        else:
            raise KeyError(f"Service {name} not found")

    async def start(self) -> None:
        for service in self.services:
            await service.start()

    async def stop(self) -> None:
        if ServiceNames.http_session in self.lookup:
            await self.http_session.close()
        for service in reversed(self.services):
            await service.stop()
