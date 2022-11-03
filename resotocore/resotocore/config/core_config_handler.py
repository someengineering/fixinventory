import asyncio
import logging
from asyncio import Task
from contextlib import suppress
from functools import partial
from typing import Optional, List, Callable

import yaml

from resotocore.analytics import AnalyticsEventSender, CoreEvent
from resotocore.config import ConfigHandler, ConfigEntity, ConfigValidation
from resotocore.core_config import (
    CoreConfig,
    ResotoCoreConfigId,
    config_model,
    EditableConfig,
    ResotoCoreRoot,
    ResotoCoreCommandsConfigId,
    ResotoCoreCommandsRoot,
    CustomCommandsConfig,
    migrate_config,
)
from resotocore.ids import SubscriberId, WorkerId
from resotocore.dependencies import empty_config
from resotocore.message_bus import MessageBus, CoreMessage
from resotocore.model.model import Kind
from resotocore.model.typed_model import from_js
from resotocore.types import Json
from resotocore.util import deep_merge, restart_service, value_in_path, value_in_path_get
from resotocore.worker_task_queue import WorkerTaskQueue, WorkerTaskDescription, WorkerTaskName, WorkerTask

log = logging.getLogger(__name__)


class CoreConfigHandler:
    def __init__(
        self,
        config: CoreConfig,
        message_bus: MessageBus,
        worker_task_queue: WorkerTaskQueue,
        config_handler: ConfigHandler,
        event_sender: AnalyticsEventSender,
        exit_fn: Callable[[], None] = partial(restart_service, "resotocore config changed."),
    ):
        self.message_bus = message_bus
        self.worker_task_queue = worker_task_queue
        self.config_updated_listener: Optional[Task[None]] = None
        self.config_validator: Optional[Task[None]] = None
        self.config = config
        self.config_handler = config_handler
        self.event_sender = event_sender
        self.exit_fn = exit_fn

    @staticmethod
    def validate_config_entry(task_data: Json) -> Optional[Json]:
        def validate_core_config() -> Optional[Json]:
            config = value_in_path(task_data, ["config", ResotoCoreRoot])
            if isinstance(config, dict):
                # try to read editable config, throws if there are errors
                read = from_js(config, EditableConfig)
                return read.validate()
            else:
                return {"error": "Expected a json object"}

        def validate_commands_config() -> Optional[Json]:
            config = value_in_path(task_data, ["config", ResotoCoreCommandsRoot])
            if isinstance(config, dict):
                # try to read editable config, throws if there are errors
                read = from_js(config, CustomCommandsConfig)
                return read.validate()
            else:
                return {"error": "Expected a json object"}

        holder = value_in_path(task_data, ["config"])
        if not isinstance(holder, dict):
            return {"error": "Expected a json object in config"}
        elif ResotoCoreRoot in holder:
            return validate_core_config()
        elif ResotoCoreCommandsRoot in holder:
            return validate_commands_config()
        else:
            return {"error": "No known configuration found"}

    async def __validate_config(self) -> None:
        worker_id = WorkerId("resotocore.config.validate")
        description = WorkerTaskDescription(
            WorkerTaskName.validate_config, {"config_id": [ResotoCoreConfigId, ResotoCoreCommandsConfigId]}
        )
        async with self.worker_task_queue.attach(worker_id, [description]) as tasks:
            while True:
                task: WorkerTask = await tasks.get()
                try:
                    errors = self.validate_config_entry(task.data)
                    if errors:
                        message = "Validation Errors:\n" + yaml.safe_dump(errors)
                        await self.worker_task_queue.error_task(worker_id, task.id, message)
                    else:
                        await self.worker_task_queue.acknowledge_task(worker_id, task.id)
                except Exception as ex:
                    log.warning("Error processing validate configuration task", exc_info=ex)
                    await self.worker_task_queue.error_task(worker_id, task.id, str(ex))

    async def __detect_usage_metrics_turned_off(self) -> None:
        loaded = await self.config_handler.get_config(ResotoCoreConfigId)
        if loaded:
            enabled = value_in_path_get(loaded.config, [ResotoCoreRoot, "runtime", "usage_metrics"], True)
            if self.config.runtime.usage_metrics and not enabled:
                await self.event_sender.core_event(CoreEvent.UsageMetricsTurnedOff)

    async def __handle_events(self) -> None:
        subscriber_id = SubscriberId("resotocore.config.update")
        async with self.message_bus.subscribe(subscriber_id, [CoreMessage.ConfigUpdated]) as events:
            while True:
                event = await events.get()
                event_id = event.data.get("id")
                if event_id in (ResotoCoreConfigId, ResotoCoreCommandsConfigId):
                    log.info(f"Core config was updated: {event_id} Restart to take effect.")
                    await self.__detect_usage_metrics_turned_off()
                    # stop the process and rely on os to restart the service
                    self.exit_fn()

    async def __update_config(self) -> None:
        # in case the internal configuration holds new properties, we update the existing config always.
        try:
            existing = await self.config_handler.get_config(ResotoCoreConfigId)
            empty = empty_config().json()
            updated = deep_merge(empty, existing.config) if existing else empty
            updated = migrate_config(updated)
            if existing is None or updated != existing.config:
                await self.config_handler.put_config(ConfigEntity(ResotoCoreConfigId, updated), validate=False)
                log.info("Default resoto config updated.")
        except Exception as ex:
            log.error(f"Could not update resoto default configuration: {ex}", exc_info=ex)

        # make sure there is a default command configuration
        # note: this configuration is only created one time and never updated
        try:
            existing_commands = await self.config_handler.get_config(ResotoCoreCommandsConfigId)
            if existing_commands is None:
                await self.config_handler.put_config(
                    ConfigEntity(ResotoCoreCommandsConfigId, CustomCommandsConfig().json()), validate=False
                )
                log.info("Default resoto commands config updated.")
        except Exception as ex:
            log.error(f"Could not update resoto command configuration: {ex}", exc_info=ex)

    async def __update_model(self) -> None:
        try:
            kinds = from_js(config_model(), List[Kind])
            await self.config_handler.update_configs_model(kinds)
            await self.config_handler.put_config_validation(
                ConfigValidation(ResotoCoreConfigId, external_validation=True)
            )
            await self.config_handler.put_config_validation(
                ConfigValidation(ResotoCoreCommandsConfigId, external_validation=True)
            )
            log.debug("Resoto core config model updated.")
        except Exception as ex:
            log.error(f"Could not update resoto core config model: {ex}", exc_info=ex)

    async def start(self) -> None:
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
