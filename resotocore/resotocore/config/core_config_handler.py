import asyncio
import logging
import sys
from asyncio import Task
from functools import partial
from typing import Optional, List, Callable

from resotocore.config import ConfigHandler, ConfigEntity
from resotocore.core_config import CoreConfig, ResotoCoreConfigId, config_model
from resotocore.dependencies import empty_config
from resotocore.message_bus import MessageBus, CoreMessage
from resotocore.model.model import Kind
from resotocore.model.typed_model import from_js
from resotocore.util import deep_merge

log = logging.getLogger(__name__)


class CoreConfigHandler:
    def __init__(
        self,
        config: CoreConfig,
        message_bus: MessageBus,
        config_handler: ConfigHandler,
        exit_fn: Callable[[], None] = partial(sys.exit, 1),
    ):
        self.message_bus = message_bus
        self.config_updated_listener: Optional[Task[None]] = None
        self.config = config
        self.config_handler = config_handler
        self.exit_fn = exit_fn

    async def __handle_events(self) -> None:
        async with self.message_bus.subscribe("resotocore_config_update", [CoreMessage.ConfigUpdated]) as events:
            while True:
                event = await events.get()
                if event.data.get("id") == ResotoCoreConfigId:
                    log.info("Core config was updated. Restart to take effect.")
                    # stop the process and rely on os to restart the service
                    self.exit_fn()

    async def __update_config(self) -> None:
        try:
            # in case the internal configuration holds new properties, we update the existing config always.
            existing = await self.config_handler.get_config(ResotoCoreConfigId)
            empty = empty_config().json()
            updated = deep_merge(empty, existing.config) if existing else empty
            if existing is None or updated != existing.config:
                await self.config_handler.put_config(ConfigEntity(ResotoCoreConfigId, updated), False)
                log.info("Default resoto config updated.")
        except Exception as ex:
            log.error(f"Could not update resoto default configuration: {ex}", exc_info=ex)

    async def __update_model(self) -> None:
        try:
            kinds = from_js(config_model(), List[Kind])
            await self.config_handler.update_configs_model(kinds)
            log.debug("Resoto core config model updated.")
        except Exception as ex:
            log.error(f"Could not update resoto core config model: {ex}", exc_info=ex)

    async def start(self) -> None:
        await self.__update_model()
        await self.__update_config()
        self.config_updated_listener = asyncio.create_task(self.__handle_events())

    async def stop(self) -> None:
        # wait for the spawned task to complete
        if self.config_updated_listener:
            self.config_updated_listener.cancel()
