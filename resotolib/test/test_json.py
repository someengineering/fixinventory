from attrs import define
from typing import Optional, ClassVar, Union

from resotolib.json import to_json, from_json, to_json_str


@define
class Foo:
    static: ClassVar[str] = "static"
    a: str
    b: int
    c: Optional[str] = None
    d: Union[str, int] = "test"
    inner: Optional["Foo"] = None
    _private: str = "private"


def test_roundtrip() -> None:
    foo = Foo("foo", 42, "bar")
    assert to_json(foo) == {"a": "foo", "b": 42, "c": "bar", "d": "test"}
    json = to_json(foo)
    assert json == {"a": "foo", "b": 42, "c": "bar", "d": "test"}
    again = from_json(json, Foo)
    assert isinstance(again, Foo)
    assert again == foo


def test_json_str() -> None:
    foo = Foo("foo", 42, "bar")
    assert to_json_str(foo) == '{"a": "foo", "b": 42, "c": "bar", "d": "test"}'
    assert to_json_str(foo, json_kwargs={"indent": 2}, strip_attr=("static", "a", "b", "c")) == '{\n  "d": "test"\n}'
