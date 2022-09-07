from typing import Optional

from resotolib.types import Json
from resotoshell.interactionrunner import ActionResult, JsonAction, PatchValueAction


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
