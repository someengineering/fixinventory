from typing import ClassVar
from attrs import define
from resotolib.baseresources import BaseResource


@define(eq=False, slots=False)
class SomeTestResource(BaseResource):
    kind: ClassVar[str] = "some_test_resource"

    def delete(self, graph) -> bool:
        return False


def test_resource():
    r = SomeTestResource(id="foo", tags={"foo": "bar"})
    log_msg = "some log"
    r.log(log_msg)
    assert r.id == "foo"
    assert r.name == "foo"
    assert r.kind == "some_test_resource"
    assert r.tags["foo"] == "bar"
    assert r.event_log[0]["msg"] == log_msg
