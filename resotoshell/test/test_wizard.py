from resotoshell.interactionrunner import ActionResult, JsonAction


def test_result() -> None:
    assert ActionResult("foo", JsonAction.replace, {"bla": "baz"}).render({}) == {"foo": {"bla": "baz"}}
    assert ActionResult("foo.bar", JsonAction.replace, {"bla": "baz"}).render({}) == {"foo": {"bar": {"bla": "baz"}}}
    assert ActionResult("foo.bla", JsonAction.replace, "baz").render({}) == {"foo": {"bla": "baz"}}
    assert ActionResult("foo.bla", JsonAction.replace, "baz").render({"foo": 2}) == {"foo": {"bla": "baz"}}
