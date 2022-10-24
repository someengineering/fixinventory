from typing import List, Dict

import pytest

from resotolib.config import Config, current_config
from resotolib.core.custom_command import (
    execute_command,
    execute_command_on_resource,
    command_definitions,
    CommandDefinition,
)
from resotolib.types import Json, JsonElement


class SomeExamplePlugin:
    @execute_command(
        name="some_name",
        info="some info",
        description="some description",
        args_description={"arg1": "some description", "arg2": "some description"},
        expect_node_result=True,
        filter={"cloud": ["aws", "azure"], "region": ["eu-west-1", "eu-west-2"]},
    )
    def some_name(self, config: Config, js: Json, args: List[str]) -> JsonElement:
        return {"js": js, "args": args}

    @execute_command_on_resource(
        name="some_other",
        info="some info",
        description="some description",
        args_description={"foo": "some description", "bar": "some description"},
    )
    def some_other(self, config: Config, js: Json, args: List[str]) -> JsonElement:
        raise AttributeError("some error")


def test_command_definitions() -> None:
    # The str class does not define any custom commands
    no_definitions = command_definitions(str)
    assert len(no_definitions) == 0

    # The SomeExamplePlugin class defines two custom commands
    definitions = command_definitions(SomeExamplePlugin)
    assert len(definitions) == 2
    def_by_name: Dict[str, CommandDefinition] = {d.name: d for d in definitions}
    some_name = def_by_name["some_name"]
    assert some_name.info == "some info"
    assert some_name.description == "some description"
    assert some_name.args_description == {"arg1": "some description", "arg2": "some description"}
    assert some_name.filter == {"cloud": ["aws", "azure"], "region": ["eu-west-1", "eu-west-2"]}
    assert some_name.expect_node_result is True
    assert some_name.expect_resource is False
    assert some_name.allowed_on_kind is None
    result = some_name.fn(SomeExamplePlugin(), current_config(), {"foo": "bar"}, ["arg1", "arg2"])
    assert result == {"js": {"foo": "bar"}, "args": ["arg1", "arg2"]}

    some_other = def_by_name["some_other"]
    with pytest.raises(AttributeError) as ex:
        some_other.fn(SomeExamplePlugin(), current_config(), {"foo": "bar"}, ["arg1", "arg2"])
    assert str(ex.value) == "some error"
