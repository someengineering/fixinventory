from textwrap import dedent
from typing import List

import pytest
from pytest import fixture

from resotocore.config import ConfigHandler, ConfigEntity, ConfigModel
from resotocore.config.config_handler_service import ConfigHandlerService
from resotocore.model.model import Kind, ComplexKind, Property
from tests.resotocore.db.entitydb import InMemoryDb


@fixture
def config_handler() -> ConfigHandler:
    cfg_db = InMemoryDb(ConfigEntity, lambda c: c.id)
    model_db = InMemoryDb(ConfigModel, lambda c: c.id)
    return ConfigHandlerService(cfg_db, model_db)


@fixture
def config_model() -> List[Kind]:
    return [
        ComplexKind(
            "sub_config",
            [],
            [
                Property("num", "int32", description="Some arbitrary number."),
                Property("str", "string", description="Some arbitrary string."),
            ],
        ),
        ComplexKind(
            "config",
            [],
            [
                Property("some_number", "int32", required=True, description="Some number.\nAnd some description."),
                Property("some_string", "string", required=True, description="Some string.\nAnd some description."),
                Property("some_sub", "sub_config", required=True, description="Some sub.\nAnd some description."),
            ],
        ),
    ]


@pytest.mark.asyncio
async def test_config(config_handler: ConfigHandler) -> None:
    # list is empty on start
    assert [a async for a in config_handler.list_config_ids()] == []

    # add one entry
    assert await config_handler.put_config("test", {"test": True}) == ConfigEntity("test", {"test": True})

    # get one entry
    assert await config_handler.get_config("test") == ConfigEntity("test", {"test": True})

    # patch the config
    assert await config_handler.patch_config("test", {"rest": False}) == ConfigEntity(
        "test", {"test": True, "rest": False}
    )

    # list all configs
    assert [a async for a in config_handler.list_config_ids()] == ["test"]

    # delete the config
    assert await config_handler.delete_config("test") is None

    # list all configs
    assert [a async for a in config_handler.list_config_ids()] == []


@pytest.mark.asyncio
async def test_config_model(config_handler: ConfigHandler, config_model: List[Kind]) -> None:
    # define the model
    await config_handler.put_config_model("test", config_model)

    # list all available models
    assert [a async for a in config_handler.list_config_model_ids()] == ["test"]

    # get the model
    model = await config_handler.get_config_model("test")
    assert model.kinds == config_model  # type: ignore

    # valid
    await config_handler.put_config("test", {"some_number": 32, "some_string": "test", "some_sub": {"num": 32}})

    # invalid
    with pytest.raises(AttributeError) as reason:
        await config_handler.put_config("test", {"some_number": 32, "some_string": 32})
    assert "Property:some_string is not valid: Expected type string but got int" in str(reason)


@pytest.mark.asyncio
async def test_config_yaml(config_handler: ConfigHandler, config_model: List[Kind]) -> None:
    await config_handler.put_config_model("test", config_model)
    await config_handler.put_config("test", {"some_number": 32, "some_string": "test", "some_sub": {"num": 32}})
    assert await config_handler.config_yaml("test") == dedent(
        """
        # Some number.
        # And some description.
        some_number: 32
        # Some string.
        # And some description.
        some_string: "test"
        # Some sub.
        # And some description.
        some_sub:\u0020
          # Some arbitrary number.
          num: 32"""
    )
