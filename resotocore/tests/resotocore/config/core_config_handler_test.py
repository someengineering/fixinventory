import asyncio

import pytest
from pytest import fixture

from resotocore.config import ConfigHandler
from resotocore.config.core_config_handler import CoreConfigHandler
from resotocore.core_config import ResotoCoreConfigId
from resotocore.dependencies import empty_config
from resotocore.message_bus import MessageBus, CoreMessage

# noinspection PyUnresolvedReferences
from tests.resotocore.message_bus_test import message_bus

# noinspection PyUnresolvedReferences
from tests.resotocore.config.config_handler_service_test import config_handler

# noinspection PyUnresolvedReferences
from tests.resotocore.worker_task_queue_test import worker, task_queue, performed_by, incoming_tasks

config_handler_exits = []


@fixture
def core_config_handler(message_bus: MessageBus, config_handler: ConfigHandler) -> CoreConfigHandler:
    def on_exit() -> None:
        config_handler_exits.append(True)

    config = empty_config()
    return CoreConfigHandler(config, message_bus, config_handler, on_exit)


@pytest.mark.asyncio
async def test_model_updated_on_start(core_config_handler: CoreConfigHandler, config_handler: ConfigHandler) -> None:
    try:
        default_model = await config_handler.get_configs_model()
        await core_config_handler.start()
        assert len(await config_handler.get_configs_model()) > len(default_model)
    finally:
        await core_config_handler.stop()


@pytest.mark.asyncio
async def test_config_ingested_on_start(core_config_handler: CoreConfigHandler, config_handler: ConfigHandler) -> None:
    try:
        assert await config_handler.get_config(ResotoCoreConfigId) is None
        await core_config_handler.start()
        assert await config_handler.get_config(ResotoCoreConfigId) is not None
    finally:
        await core_config_handler.stop()


@pytest.mark.asyncio
async def test_exit_on_updated_config(core_config_handler: CoreConfigHandler, message_bus: MessageBus) -> None:
    try:
        await core_config_handler.start()
        await asyncio.sleep(0)
        await message_bus.emit_event(CoreMessage.ConfigUpdated, {"id": ResotoCoreConfigId})
        await asyncio.sleep(0)
        assert len(config_handler_exits) == 1
    finally:
        await core_config_handler.stop()
