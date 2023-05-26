from asyncio import Queue, Task
from typing import Optional, Any, Dict, Tuple

from aiohttp import ClientSession, TCPConnector

from resotocore.analytics import AnalyticsEventSender
from resotocore.config import ConfigHandler
from resotocore.core_config import CoreConfig
from resotocore.db.db_access import DbAccess
from resotocore.message_bus import MessageBus
from resotocore.model.model_handler import ModelHandler
from resotocore.query.template_expander import TemplateExpander
from resotocore.report import Inspector
from resotocore.task import TaskHandler
from resotocore.types import JsonElement
from resotocore.user import UserManagement
from resotocore.web.certificate_handler import CertificateHandler
from resotocore.worker_task_queue import WorkerTaskQueue
from resotocore.infra_apps.runtime import Runtime
from resotocore.infra_apps.package_manager import PackageManager
from resotocore.graph_manager.graph_manager import GraphManager
from resotocore.cli.model import CLIEngine


class CLIDependencies:
    def __init__(self, **deps: Any) -> None:
        self.lookup: Dict[str, Any] = deps

    def extend(self, **deps: Any) -> "CLIDependencies":
        self.lookup = {**self.lookup, **deps}
        return self

    @property
    def config(self) -> CoreConfig:
        return self.lookup["config"]  # type: ignore

    @property
    def message_bus(self) -> MessageBus:
        return self.lookup["message_bus"]  # type:ignore

    @property
    def event_sender(self) -> AnalyticsEventSender:
        return self.lookup["event_sender"]  # type:ignore

    @property
    def db_access(self) -> DbAccess:
        return self.lookup["db_access"]  # type:ignore

    @property
    def model_handler(self) -> ModelHandler:
        return self.lookup["model_handler"]  # type:ignore

    @property
    def task_handler(self) -> TaskHandler:
        return self.lookup["task_handler"]  # type:ignore

    @property
    def worker_task_queue(self) -> WorkerTaskQueue:
        return self.lookup["worker_task_queue"]  # type:ignore

    @property
    def template_expander(self) -> TemplateExpander:
        return self.lookup["template_expander"]  # type:ignore

    @property
    def forked_tasks(self) -> Queue[Tuple[Task[JsonElement], str]]:
        return self.lookup["forked_tasks"]  # type:ignore

    @property
    def cli(self) -> CLIEngine:
        return self.lookup["cli"]  # type:ignore

    @property
    def config_handler(self) -> ConfigHandler:
        return self.lookup["config_handler"]  # type:ignore

    @property
    def cert_handler(self) -> CertificateHandler:
        return self.lookup["cert_handler"]  # type:ignore

    @property
    def inspector(self) -> Inspector:
        return self.lookup["inspector"]  # type:ignore

    @property
    def infra_apps_runtime(self) -> Runtime:
        return self.lookup["infra_apps_runtime"]  # type:ignore

    @property
    def infra_apps_package_manager(self) -> PackageManager:
        return self.lookup["infra_apps_package_manager"]  # type:ignore

    @property
    def user_management(self) -> UserManagement:
        return self.lookup["user_management"]  # type:ignore

    @property
    def graph_manager(self) -> GraphManager:
        return self.lookup["graph_manager"]  # type:ignore

    @property
    def http_session(self) -> ClientSession:
        session: Optional[ClientSession] = self.lookup.get("http_session")
        if not session:
            connector = TCPConnector(limit=0, ssl=False, ttl_dns_cache=300)
            session = ClientSession(connector=connector)
            self.lookup["http_session"] = session
        return session

    async def stop(self) -> None:
        if "http_session" in self.lookup:
            await self.http_session.close()
