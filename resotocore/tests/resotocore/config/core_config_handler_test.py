import asyncio

import pytest
from jsons import DeserializationError
from pytest import fixture

from resotocore.config import ConfigHandler
from resotocore.config.core_config_handler import CoreConfigHandler
from resotocore.core_config import (
    ResotoCoreConfigId,
    ResotoCoreRoot,
    ResotoCoreCommandsRoot,
    CustomCommandsConfig,
)
from resotocore.dependencies import empty_config
from resotocore.message_bus import MessageBus, CoreMessage
from resotocore.worker_task_queue import WorkerTaskQueue

# noinspection PyUnresolvedReferences
from tests.resotocore.config.config_handler_service_test import config_handler

# noinspection PyUnresolvedReferences
from tests.resotocore.message_bus_test import message_bus

# noinspection PyUnresolvedReferences
from tests.resotocore.worker_task_queue_test import worker, task_queue, performed_by, incoming_tasks

config_handler_exits = []


@fixture
def core_config_handler(
    message_bus: MessageBus, task_queue: WorkerTaskQueue, config_handler: ConfigHandler
) -> CoreConfigHandler:
    def on_exit() -> None:
        config_handler_exits.append(True)

    config = empty_config()
    return CoreConfigHandler(config, message_bus, task_queue, config_handler, on_exit)


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


@pytest.mark.asyncio
async def test_validation() -> None:
    validate = CoreConfigHandler.validate_config_entry

    # empty config is valid
    assert validate({"config": {ResotoCoreRoot: {}}}) is None
    # expected json object but got 23
    assert validate({"config": {ResotoCoreRoot: 23}}) is not None
    # validation fails, since ui-path does not exist
    assert validate({"config": {ResotoCoreRoot: {"api": {"ui_path": "n/a"}}}}) is not None
    # default configuration is valid
    assert validate({"config": {ResotoCoreRoot: empty_config().json()}}) is None

    # empty command config is fine
    assert validate({"config": {ResotoCoreCommandsRoot: {}}}) is None
    # 23 can not be parsed as command list
    pytest.raises(DeserializationError, validate, {"config": {ResotoCoreCommandsRoot: {"commands": 23}}})
    # valid entry can be read
    assert validate({"config": {ResotoCoreCommandsRoot: CustomCommandsConfig().json()}}) is None
