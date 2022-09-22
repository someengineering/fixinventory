from resotolib.core.tasks import CoreTaskHandler, CoreTaskResult
from .custom_command_test import SomeExamplePlugin
from resotolib.core.custom_command import command_definitions, CommandDefinition


def test_conversion() -> None:
    definitions = {a.name: a for a in command_definitions(SomeExamplePlugin)}
    some_name: CommandDefinition = definitions["some_name"]
    handler = CoreTaskHandler.from_definition(SomeExamplePlugin(), some_name)
    assert handler.core_json() == {
        "name": some_name.name,
        "info": some_name.info,
        "args_description": some_name.args_description,
        "description": some_name.description,
        "expect_node_result": some_name.expect_node_result,
        "allowed_on_kind": some_name.allowed_on_kind,
        "filter": some_name.filter,
    }


def test_matches() -> None:
    handler = CoreTaskHandler(
        name="test", info="", description="", handler=lambda x: None, filter={"a": ["b"], "b": ["c"]}
    )
    assert handler.matches({"task_name": "test", "attrs": {"a": "b", "b": "c", "some": "other"}})
    assert not handler.matches({"task_name": "test", "attrs": {"a": "b"}})
    assert not handler.matches({"task_name": "test", "attrs": {}})


def test_call() -> None:
    definitions = {a.name: a for a in command_definitions(SomeExamplePlugin)}
    handler = CoreTaskHandler.from_definition(SomeExamplePlugin, definitions["some_name"])
    res = handler.execute({"task_id": "test", "data": {"args": ["a", "b"], "node": {"a": "b"}}})
    assert res == CoreTaskResult(task_id="test", data={"js": {"a": "b"}, "args": ["a", "b"]})


def test_exception() -> None:
    definitions = {a.name: a for a in command_definitions(SomeExamplePlugin)}
    handler = CoreTaskHandler.from_definition(SomeExamplePlugin, definitions["some_other"])
    res = handler.execute({"task_id": "test", "data": {"args": ["a", "b"], "node": None}})
    assert res == CoreTaskResult(task_id="test", error="some error")
