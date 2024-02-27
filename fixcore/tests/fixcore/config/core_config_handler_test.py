import asyncio
from typing import List

from jsons import DeserializationError
from pytest import mark, raises
from fixcore.analytics import AnalyticsEvent, CoreEvent
from fixcore.config import ConfigHandler, ConfigEntity
from fixcore.config.core_config_handler import CoreConfigHandler
from fixcore.core_config import (
    FixCoreConfigId,
    FixCoreRoot,
    FixCoreCommandsRoot,
    CustomCommandsConfig,
    FixCoreSnapshotsRoot,
)
from fixcore.ids import ConfigId
from fixcore.message_bus import MessageBus, CoreMessage
from fixcore.model.typed_model import to_js
from fixcore.report import BenchmarkConfigRoot, Benchmark
from fixcore.system_start import empty_config


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
        assert await config_handler.get_config(FixCoreConfigId) is None
        await core_config_handler.start()
        assert await config_handler.get_config(FixCoreConfigId) is not None
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
        await message_bus.emit_event(CoreMessage.ConfigUpdated, {"id": FixCoreConfigId})
        await asyncio.sleep(0.1)
        assert len(core_config_handler_exits) == 1
        assert len(callback_result) == 1
        assert callback_result[0] == FixCoreConfigId
    finally:
        await core_config_handler.stop()


@mark.asyncio
async def test_validation(core_config_handler: CoreConfigHandler, benchmark: Benchmark) -> None:
    validate = core_config_handler.validate_config_entry

    # empty config is valid
    assert await validate({"config": {FixCoreRoot: {}}}) is None
    # expected json object but got 23
    assert await validate({"config": {FixCoreRoot: 23}}) is not None
    # validation fails, since ui-path does not exist
    assert await validate({"config": {FixCoreRoot: {"api": {"tsdb_proxy_url": "wrong"}}}}) is not None
    # default configuration is valid
    assert await validate({"config": {FixCoreRoot: empty_config().json()}}) is None

    # empty command config is fine
    assert await validate({"config": {FixCoreCommandsRoot: {}}}) is None
    # 23 can not be parsed as command list
    with raises(DeserializationError):
        await validate({"config": {FixCoreCommandsRoot: {"commands": 23}}})
    # valid entry can be read
    assert await validate({"config": {FixCoreCommandsRoot: CustomCommandsConfig().json()}}) is None

    # cron expression is valid
    assert (
        await validate({"config": {FixCoreSnapshotsRoot: {"foo-label": {"schedule": "0 0 * * *", "retain": 42}}}})
        is None
    )

    # cron expression is invalid
    assert (
        await validate({"config": {FixCoreSnapshotsRoot: {"foo-label": {"schedule": "foo bar", "retain": 42}}}})
        is not None
    )
    # make sure that the benchmark id and config_id are the same
    assert await validate({"config": {BenchmarkConfigRoot: {"id": "some"}}, "config_id": "some_other"}) is not None
    # a valid benchmark config passes the check
    test_benchmark = to_js(benchmark)
    assert await validate({"config": {BenchmarkConfigRoot: to_js(test_benchmark)}, "config_id": "test"}) is None


@mark.asyncio
async def test_detect_usage_metrics_turned_off(
    config_handler: ConfigHandler, core_config_handler_started: CoreConfigHandler
) -> None:
    # make sure usage metrics are enabled
    core_config_handler_started.config.runtime.usage_metrics = True
    await config_handler.patch_config(
        ConfigEntity(FixCoreConfigId, {FixCoreRoot: {"runtime": {"usage_metrics": True}}})
    )
    # disable usage metrics
    await config_handler.patch_config(
        ConfigEntity(FixCoreConfigId, {FixCoreRoot: {"runtime": {"usage_metrics": False}}})
    )
    await asyncio.sleep(0.1)
    events: List[AnalyticsEvent] = core_config_handler_started.event_sender.events  # type: ignore # in-memory sender
    assert len(events) == 1
    assert events[0].kind == CoreEvent.UsageMetricsTurnedOff
