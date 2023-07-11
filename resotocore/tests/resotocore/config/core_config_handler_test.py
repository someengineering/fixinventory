import asyncio
from typing import List

from jsons import DeserializationError
from pytest import mark, raises

from resotocore.analytics import AnalyticsEvent, CoreEvent
from resotocore.config import ConfigHandler, ConfigEntity
from resotocore.config.core_config_handler import CoreConfigHandler
from resotocore.core_config import (
    ResotoCoreConfigId,
    ResotoCoreRoot,
    ResotoCoreCommandsRoot,
    CustomCommandsConfig,
    ResotoCoreSnapshotsRoot,
)
from resotocore.system_start import empty_config
from resotocore.message_bus import MessageBus, CoreMessage
from resotocore.ids import ConfigId


@mark.asyncio
async def test_model_updated_on_start(core_config_handler: CoreConfigHandler, config_handler: ConfigHandler) -> None:
    try:
        default_model = await config_handler.get_configs_model()
        await core_config_handler.start()
        assert len(await config_handler.get_configs_model()) > len(default_model)
    finally:
        await core_config_handler.stop()


@mark.asyncio
async def test_config_ingested_on_start(core_config_handler: CoreConfigHandler, config_handler: ConfigHandler) -> None:
    try:
        assert await config_handler.get_config(ResotoCoreConfigId) is None
        await core_config_handler.start()
        assert await config_handler.get_config(ResotoCoreConfigId) is not None
    finally:
        await core_config_handler.stop()


@mark.asyncio
async def test_exit_on_updated_config(
    core_config_handler: CoreConfigHandler, message_bus: MessageBus, core_config_handler_exits: List[bool]
) -> None:
    callback_result = []

    async def callback(config_id: ConfigId) -> None:
        callback_result.append(config_id)

    try:
        await core_config_handler.start()
        core_config_handler.add_callback(callback)
        await asyncio.sleep(0.1)
        await message_bus.emit_event(CoreMessage.ConfigUpdated, {"id": ResotoCoreConfigId})
        await asyncio.sleep(0.1)
        assert len(core_config_handler_exits) == 1
        assert len(callback_result) == 1
        assert callback_result[0] == ResotoCoreConfigId
    finally:
        await core_config_handler.stop()


@mark.asyncio
async def test_validation(core_config_handler: CoreConfigHandler) -> None:
    validate = core_config_handler.validate_config_entry

    # empty config is valid
    assert await validate({"config": {ResotoCoreRoot: {}}}) is None
    # expected json object but got 23
    assert await validate({"config": {ResotoCoreRoot: 23}}) is not None
    # validation fails, since ui-path does not exist
    assert await validate({"config": {ResotoCoreRoot: {"api": {"tsdb_proxy_url": "wrong"}}}}) is not None
    # default configuration is valid
    assert await validate({"config": {ResotoCoreRoot: empty_config().json()}}) is None

    # empty command config is fine
    assert await validate({"config": {ResotoCoreCommandsRoot: {}}}) is None
    # 23 can not be parsed as command list
    with raises(DeserializationError):
        await validate({"config": {ResotoCoreCommandsRoot: {"commands": 23}}})
    # valid entry can be read
    assert await validate({"config": {ResotoCoreCommandsRoot: CustomCommandsConfig().json()}}) is None

    # cron expression is valid
    assert (
        await validate({"config": {ResotoCoreSnapshotsRoot: {"foo-label": {"schedule": "0 0 * * *", "retain": 42}}}})
        is None
    )

    # cron expression is invalid
    assert (
        await validate({"config": {ResotoCoreSnapshotsRoot: {"foo-label": {"schedule": "foo bar", "retain": 42}}}})
        is not None
    )


@mark.asyncio
async def test_detect_usage_metrics_turned_off(
    config_handler: ConfigHandler, core_config_handler_started: CoreConfigHandler
) -> None:
    # make sure usage metrics are enabled
    core_config_handler_started.config.runtime.usage_metrics = True
    await config_handler.patch_config(
        ConfigEntity(ResotoCoreConfigId, {ResotoCoreRoot: {"runtime": {"usage_metrics": True}}})
    )
    # disable usage metrics
    await config_handler.patch_config(
        ConfigEntity(ResotoCoreConfigId, {ResotoCoreRoot: {"runtime": {"usage_metrics": False}}})
    )
    await asyncio.sleep(0.1)
    events: List[AnalyticsEvent] = core_config_handler_started.event_sender.events  # type: ignore # in-memory sender
    assert len(events) == 1
    assert events[0].kind == CoreEvent.UsageMetricsTurnedOff
