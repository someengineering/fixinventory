from typing import Optional

from resotolib.types import Json
from resotoshell.interactionrunner import (
    ActionResult,
    JsonAction,
    PatchValueAction,
    value_in_path,
    converter,
    OnlyIf,
    OnlyIfValue,
    OnlyIfLen,
    OnlyIfDefined,
    OnlyIfUndefined,
    ExecuteCommand,
    ExecuteCLICommand,
    PutConfiguration,
    InteractionStep,
    InteractionInfo,
    InteractionProgress,
    InteractionInput,
    InteractionDecision,
    InteractionSequence,
    SubInteraction,
)


def test_value_in_path() -> None:
    assert value_in_path({"a": {"b": 2}}, "a") == {"b": 2}
    assert value_in_path({"a": {"b": 2}}, "a.b") == 2
    assert value_in_path({"a": {"b": 2}}, "a.b.c") is None


def test_action() -> None:
    def render(action: PatchValueAction, json: Json, value: Optional[str]) -> Json:
        for res in action.render(value):
            json = res.render(json)
        return json

    assert render(PatchValueAction("foo", '"@value@"', JsonAction.replace), {}, None) == {"foo": None}
    assert render(PatchValueAction("foo", "@value@", JsonAction.replace), {}, "123") == {"foo": 123}
    assert render(PatchValueAction("foo", '"@value@"', JsonAction.replace), {}, "123") == {"foo": "123"}
    assert render(PatchValueAction("foo", '{"a":"@value@"}', JsonAction.replace), {}, "123") == {"foo": {"a": "123"}}


def test_result() -> None:
    assert ActionResult("foo", JsonAction.replace, {"bla": "baz"}).render({}) == {"foo": {"bla": "baz"}}
    assert ActionResult("foo.bar", JsonAction.replace, {"bla": "baz"}).render({}) == {"foo": {"bar": {"bla": "baz"}}}
    assert ActionResult("foo.bla", JsonAction.replace, "baz").render({}) == {"foo": {"bla": "baz"}}
    assert ActionResult("foo.bla", JsonAction.replace, "baz").render({"foo": 2}) == {"foo": {"bla": "baz"}}


def test_only_if() -> None:
    oif_val = converter.structure({"kind": "value", "path": "aws.scrape_org", "value": False}, OnlyIf)  # type: ignore
    assert isinstance(oif_val, OnlyIfValue)
    assert oif_val.path == "aws.scrape_org"
    assert oif_val.value is False
    assert oif_val.is_true({"aws": {"scrape_org": False}})
    assert not oif_val.is_true({"aws": {"scrape_org": True}})
    assert not oif_val.is_true({"aws": 123})

    oif_len = converter.structure({"kind": "len", "path": "aws.scrape_org", "op": ">", "value": 2}, OnlyIf)  # type: ignore
    assert isinstance(oif_len, OnlyIfLen)
    assert oif_len.path == "aws.scrape_org"
    assert oif_len.op == ">"
    assert oif_len.value == 2
    assert oif_len.is_true({"aws": {"scrape_org": [1, 2, 3, 4]}})
    assert not oif_len.is_true({"aws": {"scrape_org": [1, 2]}})
    assert oif_len.is_true({"aws": {"scrape_org": "string is longer than 2"}})

    oif_defined = converter.structure({"kind": "defined", "path": "aws.scrape_org"}, OnlyIf)  # type: ignore
    assert isinstance(oif_defined, OnlyIfDefined)
    assert oif_defined.path == "aws.scrape_org"
    assert oif_defined.is_true({"aws": {"scrape_org": 1}})
    assert not oif_defined.is_true({"aws": {"scrape_org": None}})
    assert not oif_defined.is_true({"aws": {"foo": None}})

    oif_undefined = converter.structure({"kind": "undefined", "path": "aws.scrape_org"}, OnlyIf)  # type: ignore
    assert isinstance(oif_undefined, OnlyIfUndefined)
    assert oif_undefined.path == "aws.scrape_org"
    assert oif_undefined.is_true({"aws": {"foo": 1}})
    assert oif_undefined.is_true({"aws": {"scrape_org": None}})
    assert not oif_undefined.is_true({"aws": {"scrape_org": 12}})


def test_execute_command() -> None:
    execute = converter.structure({"kind": "execute", "command": "echo 'hello world'"}, ExecuteCommand)  # type: ignore
    assert isinstance(execute, ExecuteCLICommand)
    assert execute.command == "echo 'hello world'"

    put_config = converter.structure({"kind": "put_config"}, ExecuteCommand)  # type: ignore
    assert isinstance(put_config, PutConfiguration)


def test_interaction_step_json() -> None:
    info_js = {"kind": "info", "name": "name", "help": "help"}
    progress_js = {"kind": "progress", "name": "name", "help": "help"}
    input_js = {
        "kind": "input",
        "name": "name",
        "help": "help",
        "action": {"path": "a", "value_template": "b"},
        "split_result_by": "c",
        "password": True,
        "expected_type": "ipv4",
    }
    sub_js = {
        "kind": "sub_interaction",
        "name": "name",
        "help": "help",
        "path": "a.b",
        "steps": [info_js, input_js, progress_js],
    }
    seq_js = {"kind": "seq", "name": "name", "help": "help", "steps": [info_js, progress_js, input_js, sub_js]}
    decision_js = {
        "kind": "decision",
        "name": "name",
        "help": "help",
        "select_multiple": True,
        "step_options": {"a": info_js, "b": sub_js, "c": seq_js},
    }

    info = converter.structure(info_js, InteractionStep)  # type: ignore
    assert isinstance(info, InteractionInfo)
    assert info.name == "name"
    assert info.help == "help"

    progress = converter.structure(progress_js, InteractionStep)  # type: ignore
    assert isinstance(progress, InteractionProgress)
    assert progress.name == "name"
    assert progress.help == "help"

    iinput = converter.structure(input_js, InteractionStep)  # type: ignore
    assert isinstance(iinput, InteractionInput)
    assert iinput.password is True
    assert iinput.split_result_by == "c"
    assert iinput.action == PatchValueAction("a", "b", JsonAction.replace)
    assert iinput.expected_type == "ipv4"

    sub = converter.structure(sub_js, InteractionStep)  # type: ignore
    assert isinstance(sub, SubInteraction)
    assert sub.path == "a.b"
    assert len(sub.steps) == 3

    seq = converter.structure(seq_js, InteractionStep)  # type: ignore
    assert isinstance(seq, InteractionSequence)
    assert len(seq.steps) == 4

    decision = converter.structure(decision_js, InteractionStep)  # type: ignore
    assert isinstance(decision, InteractionDecision)
    assert decision.select_multiple is True
    assert len(decision.step_options) == 3
    assert isinstance(decision.step_options["a"], InteractionInfo)
