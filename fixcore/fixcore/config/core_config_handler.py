import asyncio
import logging
from asyncio import Task
from contextlib import suppress
from functools import partial
from typing import Optional, List, Callable, Awaitable
from apscheduler.triggers.cron import CronTrigger

import yaml

from fixcore.analytics import AnalyticsEventSender, CoreEvent
from fixcore.config import ConfigHandler, ConfigEntity, ConfigValidation
from fixcore.core_config import (
    CoreConfig,
    FixCoreConfigId,
    EditableConfig,
    FixCoreRoot,
    FixCoreCommandsConfigId,
    FixCoreCommandsRoot,
    FixCoreSnapshotsConfigId,
    FixCoreSnapshotsRoot,
    SnapshotsScheduleConfig,
    CustomCommandsConfig,
    migrate_core_config,
    config_model as core_config_model,
    migrate_command_config,
)
from fixcore.system_start import empty_config
from fixcore.ids import SubscriberId, WorkerId, ConfigId
from fixcore.message_bus import MessageBus, CoreMessage
from fixcore.model.model import Kind
from fixcore.model.typed_model import from_js
from fixcore.report import FixReportBenchmark, FixReportCheck, Inspector, BenchmarkConfigRoot, CheckConfigRoot
from fixcore.report.report_config import config_model as report_config_model
from fixcore.service import Service
from fixcore.types import Json
from fixcore.user import config_model as user_config_model, UsersConfigId, FixInventoryUsersConfig
from fixcore.util import deep_merge, restart_service, value_in_path, value_in_path_get
from fixcore.worker_task_queue import WorkerTaskQueue, WorkerTaskDescription, WorkerTaskName, WorkerTask

log = logging.getLogger(__name__)


class CoreConfigHandler(Service):
    def __init__(
        self,
        config: CoreConfig,
        message_bus: MessageBus,
        worker_task_queue: WorkerTaskQueue,
        config_handler: ConfigHandler,
        event_sender: AnalyticsEventSender,
        inspector: Inspector,
        exit_fn: Callable[[], None] = partial(restart_service, "fixcore config changed."),
    ):
        super().__init__()
        self.message_bus = message_bus
        self.worker_task_queue = worker_task_queue
        self.config_updated_listener: Optional[Task[None]] = None
        self.config_validator: Optional[Task[None]] = None
        self.config = config
        self.config_handler = config_handler
        self.event_sender = event_sender
        self.inspector = inspector
        self.exit_fn = exit_fn
        self.config_updated_callbacks: List[Callable[[ConfigId], Awaitable[None]]] = []

    async def validate_config_entry(self, task_data: Json) -> Optional[Json]:
        def validate_core_config() -> Optional[Json]:
            config = value_in_path(task_data, ["config", FixCoreRoot])
            if isinstance(config, dict):
                # try to read editable config, throws if there are errors
                read = from_js(config, EditableConfig)
                return read.validate()
            else:
                return {"error": "Expected a json object"}

        def validate_commands_config() -> Optional[Json]:
            config = value_in_path(task_data, ["config", FixCoreCommandsRoot])
            if isinstance(config, dict):
                # try to read editable config, throws if there are errors
                read = from_js(config, CustomCommandsConfig)
                return read.validate()
            else:
                return {"error": "Expected a json object"}

        def validate_snapshot_schedule() -> Optional[Json]:
            config = value_in_path(task_data, ["config", FixCoreSnapshotsRoot])
            if isinstance(config, dict):
                config = {"snapshots": config}  # wrap in snapshots objects to match the dataclass
                read = from_js(config, SnapshotsScheduleConfig)
                # validate cron expressions
                try:
                    for schedule in read.snapshots.values():
                        CronTrigger.from_crontab(schedule.schedule)
                    return None
                except Exception as ex:
                    return {"error": f"Invalid cron expression: {ex}"}
            else:
                return {"error": "Expected a json object"}

        holder = value_in_path(task_data, ["config"])
        if not isinstance(holder, dict):
            return {"error": "Expected a json object in config"}
        elif FixCoreRoot in holder:
            return validate_core_config()
        elif FixCoreCommandsRoot in holder:
            return validate_commands_config()
        elif CheckConfigRoot in holder:
            return await self.inspector.validate_check_collection_config(task_data["config"])
        elif BenchmarkConfigRoot in holder:
            return await self.inspector.validate_benchmark_config(task_data["config_id"], task_data["config"])
        elif FixCoreSnapshotsRoot in holder:
            return validate_snapshot_schedule()
        else:
            return {"error": "No known configuration found"}

    def add_callback(self, callback: Callable[[ConfigId], Awaitable[None]]) -> None:
        self.config_updated_callbacks.append(callback)

    async def __validate_config(self) -> None:
        worker_id = WorkerId("fixcore.config.validate")
        description = WorkerTaskDescription(
            WorkerTaskName.validate_config,
            {
                "config_id": [
                    FixCoreConfigId,
                    FixCoreCommandsConfigId,
                    FixReportBenchmark,
                    FixReportCheck,
                    FixCoreSnapshotsConfigId,
                ]
            },
        )
        async with self.worker_task_queue.attach(worker_id, [description]) as tasks:
            while True:
                task: WorkerTask = await tasks.get()
                try:
                    errors = await self.validate_config_entry(task.data)
                    if errors:
                        message = "Validation Errors:\n" + yaml.safe_dump(errors)
                        await self.worker_task_queue.error_task(worker_id, task.id, message)
                    else:
                        await self.worker_task_queue.acknowledge_task(worker_id, task.id)
                except Exception as ex:
                    log.warning("Error processing validate configuration task", exc_info=ex)
                    await self.worker_task_queue.error_task(worker_id, task.id, str(ex))

    async def __detect_usage_metrics_turned_off(self) -> None:
        loaded = await self.config_handler.get_config(FixCoreConfigId)
        if loaded:
            enabled = value_in_path_get(loaded.config, [FixCoreRoot, "runtime", "usage_metrics"], True)
            if self.config.runtime.usage_metrics and not enabled:
                await self.event_sender.core_event(CoreEvent.UsageMetricsTurnedOff)

    async def __handle_events(self) -> None:
        subscriber_id = SubscriberId("fixcore.config.update")
        async with self.message_bus.subscribe(subscriber_id, [CoreMessage.ConfigUpdated]) as events:
            while True:
                event = await events.get()
                event_id = event.data.get("id")
                if event_id:
                    for callback in self.config_updated_callbacks:
                        try:
                            await callback(event_id)
                        except Exception as ex:
                            log.warning("Error in config update callback", exc_info=ex)

                if event_id in (FixCoreConfigId, FixCoreCommandsConfigId):
                    log.info(f"Core config was updated: {event_id} Restart to take effect.")
                    await self.__detect_usage_metrics_turned_off()
                    # stop the process and rely on os to restart the service
                    self.exit_fn()

    async def __update_config(self) -> None:
        # in case the internal configuration holds new properties, we update the existing config always.
        try:
            existing = await self.config_handler.get_config(FixCoreConfigId)
            empty = empty_config().json()
            updated = deep_merge(empty, existing.config) if existing else empty
            updated = migrate_core_config(updated)
            if existing is None or updated != existing.config:
                await self.config_handler.put_config(ConfigEntity(FixCoreConfigId, updated), validate=False)
                log.info("Default fix config updated.")
        except Exception as ex:
            log.error(f"Could not update fix default configuration: {ex}", exc_info=ex)

        # make sure there is a default command configuration
        # note: this configuration is only created one time and never updated
        try:
            existing_commands = await self.config_handler.get_config(FixCoreCommandsConfigId)
            to_update: Optional[Json] = None
            if existing_commands is None:
                to_update = CustomCommandsConfig().json()
            else:
                to_update = migrate_command_config(existing_commands.config)
            if to_update is not None:
                await self.config_handler.put_config(ConfigEntity(FixCoreCommandsConfigId, to_update), validate=False)
                log.info("Default fix commands config updated.")
        except Exception as ex:
            log.error(f"Could not update fix command configuration: {ex}", exc_info=ex)

        # make sure there is a default user configuration
        try:
            existing_users = await self.config_handler.get_config(UsersConfigId)
            user_update: Optional[Json] = None
            if existing_users is None:
                user_update = FixInventoryUsersConfig().json()
            if user_update is not None:
                await self.config_handler.put_config(ConfigEntity(UsersConfigId, user_update), validate=False)
                log.info("Default fix users config updated.")
        except Exception as ex:
            log.error(f"Could not update fix users configuration: {ex}", exc_info=ex)

        # make sure there is a default snapshots configuration
        try:
            existing_snapshots = await self.config_handler.get_config(FixCoreSnapshotsConfigId)
            snapshot_update: Optional[Json] = None
            if existing_snapshots is None:
                snapshot_update = SnapshotsScheduleConfig().json()
            if snapshot_update is not None:
                await self.config_handler.put_config(
                    ConfigEntity(FixCoreSnapshotsConfigId, snapshot_update), validate=False
                )
                log.info("Default fix snapshots config updated.")
        except Exception as ex:
            log.error(f"Could not update fix snapshots configuration: {ex}", exc_info=ex)

    async def __update_model(self) -> None:
        try:
            models = core_config_model() + report_config_model() + user_config_model()
            kinds = from_js(models, List[Kind])
            await self.config_handler.update_configs_model(kinds)
            await self.config_handler.put_config_validation(ConfigValidation(FixCoreConfigId, external_validation=True))
            await self.config_handler.put_config_validation(
                ConfigValidation(FixCoreCommandsConfigId, external_validation=True)
            )
            await self.config_handler.put_config_validation(
                ConfigValidation(FixCoreCommandsConfigId, external_validation=True)
            )
            await self.config_handler.put_config_validation(
                ConfigValidation(FixCoreSnapshotsConfigId, external_validation=True)
            )
            await self.config_handler.put_config_validation(
                ConfigValidation(FixReportBenchmark, external_validation=True)
            )
            await self.config_handler.put_config_validation(ConfigValidation(FixReportCheck, external_validation=True))

            log.debug("Fix Inventory core config model updated.")
        except Exception as ex:
            log.error(f"Could not update fix core config model: {ex}", exc_info=ex)

    async def start(self) -> None:
        if not self.config.multi_tenant_setup:
            await self.__update_model()
            await self.__update_config()
        self.config_updated_listener = asyncio.create_task(self.__handle_events())
        self.config_validator = asyncio.create_task(self.__validate_config())

    async def stop(self) -> None:
        # wait for the spawned task to complete
        if self.config_updated_listener:
            with suppress(Exception):
                self.config_updated_listener.cancel()
        if self.config_validator:
            with suppress(Exception):
                self.config_validator.cancel()
