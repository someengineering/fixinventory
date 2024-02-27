from textwrap import dedent
from typing import List, cast, Dict
import os

import pytest
from pytest import fixture

from fixcore.analytics import InMemoryEventSender
from fixcore.config import ConfigHandler, ConfigEntity, ConfigValidation, ConfigOverride
from fixcore.config.config_handler_service import ConfigHandlerService
from fixcore.ids import ConfigId
from fixcore.message_bus import CoreMessage, Event, Message
from tests.fixcore.message_bus_test import wait_for_message
from fixcore.model.model import Kind, ComplexKind, Property
from fixcore.model.typed_model import to_js, from_js
from fixcore.types import Json
from types import SimpleNamespace


@fixture
def config_model() -> List[Kind]:
    return [
        ComplexKind(
            "sub_section",
            [],
            [
                Property("num", "int32", description="Some arbitrary number."),
                Property("str", "string", description="Some arbitrary string."),
            ],
        ),
        ComplexKind(
            "section",
            [],
            [
                Property("some_number", "int32", required=True, description="Some number.\nAnd some description."),
                Property(
                    "some_number_env_var",
                    "int32",
                    required=False,
                    description="Some env var substitution.\nAnd some description.",
                ),
                Property("some_string", "string", required=True, description="Some string.\nAnd some description."),
                Property("some_sub", "sub_section", required=True, description="Some sub.\nAnd some description."),
            ],
        ),
    ]


@pytest.mark.asyncio
async def test_config(config_handler: ConfigHandler) -> None:
    # list is empty on start
    assert [a async for a in config_handler.list_config_ids()] == []

    config_id = ConfigId("test")
    # add one entry
    entity = ConfigEntity(config_id, {"test": True})
    assert await config_handler.put_config(entity) == entity

    # get one entry
    assert await config_handler.get_config(config_id) == entity

    # patch the config
    assert await config_handler.patch_config(ConfigEntity(config_id, {"rest": False})) == ConfigEntity(
        config_id, {"test": True, "rest": False}
    )

    # list all configs
    assert [a async for a in config_handler.list_config_ids()] == ["test"]

    # copy the config
    copied = await config_handler.copy_config(config_id, ConfigId("test2"))
    # non-existing config is not copied
    assert await config_handler.copy_config(ConfigId("test3"), ConfigId("test4")) is None
    # copying to existing config is not allowed and raises an exception
    with pytest.raises(Exception):
        await config_handler.copy_config(ConfigId("test"), ConfigId("test"))
    assert copied == ConfigEntity(ConfigId("test2"), {"test": True, "rest": False})
    assert {a async for a in config_handler.list_config_ids()} == set(["test", "test2"])

    # delete the config
    await config_handler.delete_config(config_id)
    await config_handler.delete_config(ConfigId("test2"))

    # list all configs
    assert [a async for a in config_handler.list_config_ids()] == []


@pytest.mark.asyncio
async def test_config_change_event(config_handler: ConfigHandlerService) -> None:
    sender: InMemoryEventSender = config_handler.event_sender  # type: ignore # in-memory sender
    # list of events is empty on start
    assert sender.events == []

    config_id = ConfigId("test")
    # add one entry
    entity = ConfigEntity(config_id, {"test": True})
    assert await config_handler.put_config(entity) == entity
    assert len(sender.events) == 1

    # patch the config
    assert await config_handler.patch_config(ConfigEntity(config_id, {"rest": False})) == ConfigEntity(
        config_id, {"test": True, "rest": False}
    )
    assert len(sender.events) == 2

    # delete the config
    await config_handler.delete_config(config_id)
    assert len(sender.events) == 3


@pytest.mark.asyncio
async def test_dry_run(config_handler: ConfigHandlerService) -> None:
    config_id = ConfigId("test_dry_run")
    entity = ConfigEntity(config_id, {"test": True})

    # put dry run -> config is not stored
    assert await config_handler.put_config(entity, dry_run=True) == entity
    assert await config_handler.get_config(config_id) is None

    # patch dry run -> config is not stored
    assert await config_handler.patch_config(entity, dry_run=True) == entity
    assert await config_handler.get_config(config_id) is None


@pytest.mark.asyncio
async def test_config_change_analytics(config_handler: ConfigHandler) -> None:
    config_id = ConfigId("test")
    worker_config_1 = {
        "fixworker": {
            "collector": ["aws", "k8s", "example", "digitalocean", "gcp"],
            "aws": {"access_key_id": None, "secret_access_key": None, "profiles": ["list", "of", "profiles"]},
            "digitalocean": {"api_tokens": ["123abc"]},
            "gcp": {"service_account": [""]},
            "k8s": {"config_files": ["/path/to/some/file"]},
        }
    }
    entity = ConfigEntity(config_id, worker_config_1)
    analytics = entity.analytics()

    assert analytics["how_many_providers"] == 4
    assert analytics["aws"]
    assert analytics["k8s"]
    assert analytics["gcp"]
    assert analytics["digitalocean"]
    assert analytics["aws_use_profiles"]
    assert not analytics["aws_use_role"]
    assert analytics["do_use_config"]
    assert analytics["gcp_use_auto_discovery"]
    assert analytics["k8s_use_kubeconfig"]

    worker_config_2 = {
        "fixworker": {
            "collector": ["aws", "k8s", "example", "digitalocean", "gcp"],
            "aws": {
                "access_key_id": "abc",
                "secret_access_key": "123",
            },
            "gcp": {"service_account": ["some service account json file"]},
            "k8s": {
                "configs": [
                    {
                        "name": "dev",
                        "certificate_authority_data": "xyz",
                        "server": "https://k8s-cluster-server.example.com",
                        "token": "some token",
                    }
                ]
            },
        }
    }
    entity = ConfigEntity(config_id, worker_config_2)
    analytics = entity.analytics()
    assert not analytics["aws_use_profiles"]
    assert analytics["aws_use_access_secret_key"]
    assert not analytics["do_use_config"]
    assert analytics["gcp_use_file"]
    assert analytics["k8s_use_manual"]


@pytest.mark.asyncio
async def test_config_validation(config_handler: ConfigHandler, config_model: List[Kind]) -> None:
    await config_handler.update_configs_model(config_model)
    valid_config = {"section": {"some_number": 32, "some_string": "test", "some_sub": {"num": 32}}}

    # define the model
    await config_handler.put_config_validation(ConfigValidation("test", True))

    # list all available models
    assert [a async for a in config_handler.list_config_validation_ids()] == ["test"]

    # get the model
    model: ConfigValidation = await config_handler.get_config_validation("test")  # type: ignore
    assert model.external_validation is True

    # check the config against the model
    invalid_config = {"section": {"some_number": "no number"}}
    invalid_config_id = ConfigId("invalid_config")
    with pytest.raises(AttributeError) as reason:
        await config_handler.put_config(ConfigEntity(invalid_config_id, invalid_config))
    assert "some_number is not valid: Expected type int32 but got str" in str(reason.value)

    # External validation turned on: config with name "invalid_config" is rejected by the configured worker
    await config_handler.put_config_validation(ConfigValidation(invalid_config_id, True))
    with pytest.raises(AttributeError) as reason:
        # The config is actually valid, but the external validation will fail
        await config_handler.put_config(ConfigEntity(invalid_config_id, valid_config))
    assert "Error executing task: Invalid Config ;)" in str(reason)

    # If external validation is turned off, the configuration can be updated
    await config_handler.put_config_validation(ConfigValidation(invalid_config_id, False))
    await config_handler.put_config(ConfigEntity(invalid_config_id, valid_config))


@pytest.mark.asyncio
async def test_config_yaml(config_handler: ConfigHandler, config_model: List[Kind]) -> None:
    await config_handler.update_configs_model(config_model)
    config = {
        "some_number": 32,
        "some_number_env_var": "$(SOME_NUMBER)",
        "some_string": "test",
        "some_sub": {"num": 32},
    }
    os.environ["SOME_NUMBER"] = "42"
    expect_comment = dedent(
        """
        section:
          # Some number.
          # And some description.
          some_number: 32
          # Some env var substitution.
          # And some description.
          some_number_env_var: $(SOME_NUMBER)
          # Some string.
          # And some description.
          some_string: 'test'
          # Some sub.
          # And some description.
          some_sub:
            # Some arbitrary number.
            num: 32
        """
    ).strip()
    # no attached model -> '32' is not coerced into 32
    expect_no_comment = dedent(
        """
        another_section:
          some_number: 32
          some_number_env_var: $(SOME_NUMBER)
          some_string: test
          some_sub:
            num: 32
        """
    ).strip()
    # config has section with attached model
    test_config_id = ConfigId("test")
    await config_handler.put_config(ConfigEntity(test_config_id, {"section": config}))
    config_yaml = await config_handler.config_yaml(test_config_id) or ""
    assert expect_comment in config_yaml
    # different section with no attached model
    nomodel_config_id = ConfigId("no_model")
    await config_handler.put_config(ConfigEntity(nomodel_config_id, {"another_section": config}))
    nomodel_config_yaml = await config_handler.config_yaml(nomodel_config_id) or ""
    assert expect_no_comment in nomodel_config_yaml

    expect_json = {
        "some_number": 32,
        "some_number_env_var": 42,
        "some_string": "test",
        "some_sub": {"num": 32},
    }
    # get config returns the latest version
    stored_ce = await config_handler.get_config(test_config_id)
    stored_config = stored_ce.config.get("section") if stored_ce else None
    assert expect_json == stored_config

    override = {"section": {"some_number": 1337}}
    expect_override_comment = dedent(
        """
        section:
          # Some number.
          # And some description.
          # Warning: the current value is being ignored because there is an active override in place. The override value is: 1337
          some_number: 32
          # Some env var substitution.
          # And some description.
          some_number_env_var: $(SOME_NUMBER)
          # Some string.
          # And some description.
          some_string: 'test'
          # Some sub.
          # And some description.
          some_sub:
            # Some arbitrary number.
            num: 32
        """
    ).strip()
    cast(ConfigHandlerService, config_handler).override_service = cast(
        ConfigOverride, SimpleNamespace(get_override=lambda id: override)
    )
    config_with_override_yaml = await config_handler.config_yaml(test_config_id) or ""
    assert expect_override_comment in config_with_override_yaml


@pytest.mark.asyncio
async def test_config_change_emits_event(config_handler: ConfigHandler, all_events: List[Message]) -> None:
    # Put a config
    all_events.clear()
    config_id = ConfigId("foo")
    cfg = await config_handler.put_config(ConfigEntity(config_id, dict(test=1)))
    message = await wait_for_message(all_events, CoreMessage.ConfigUpdated, Event)
    assert message.data["id"] == cfg.id
    assert message.data["revision"] == cfg.revision

    # Patch a config
    all_events.clear()
    cfg = await config_handler.patch_config(ConfigEntity(config_id, dict(foo=2)))
    message = await wait_for_message(all_events, CoreMessage.ConfigUpdated, Event)
    assert message.data["id"] == cfg.id
    assert message.data["revision"] == cfg.revision

    # Delete a config
    all_events.clear()
    await config_handler.delete_config(config_id)
    message = await wait_for_message(all_events, CoreMessage.ConfigDeleted, Event)
    assert message.data["id"] == config_id
    assert "revision" not in message.data


def test_config_entity_roundtrip() -> None:
    entity = ConfigEntity(ConfigId("test"), {"test": 1}, "test")
    again = from_js(to_js(entity), ConfigEntity)
    assert entity == again
