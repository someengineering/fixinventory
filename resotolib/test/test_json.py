from attrs import define
from typing import Optional, ClassVar, Union, Literal

from resotolib.json import to_json, from_json, is_primitive_or_primitive_union


@define
class Foo:
    static: ClassVar[str] = "static"
    a: str
    b: int
    c: Optional[str] = None
    d: Union[str, int] = "test"
    inner: Optional["Foo"] = None
    _private: str = "private"

    @property
    def foo(self) -> str:
        return "foo"


def test_roundtrip() -> None:
    foo = Foo("foo", 42, "bar")
    assert to_json(foo) == {"a": "foo", "b": 42, "c": "bar", "d": "test", "inner": None}
    json = to_json(foo)
    assert json == {"a": "foo", "b": 42, "c": "bar", "d": "test", "inner": None}
    again = from_json(json, Foo)
    assert isinstance(again, Foo)
    assert again == foo
    # strip attrs based on string or list of strings
    assert to_json(foo, strip_attr="a") == {"b": 42, "c": "bar", "d": "test", "inner": None}
    assert to_json(foo, strip_attr=["a", "b", "c"]) == {"d": "test", "inner": None}
    # do not strip nulls
    assert to_json(foo, strip_nulls=True) == {"a": "foo", "b": 42, "c": "bar", "d": "test"}


def test_primitive_union() -> None:
    # simple types
    assert is_primitive_or_primitive_union(str) is True
    assert is_primitive_or_primitive_union(int) is True
    assert is_primitive_or_primitive_union(bool) is True
    assert is_primitive_or_primitive_union(int) is True
    assert is_primitive_or_primitive_union(float) is True
    assert is_primitive_or_primitive_union(type(None)) is True
    assert is_primitive_or_primitive_union(Foo) is False
    # literal types
    assert is_primitive_or_primitive_union(Literal["test"]) is True
    # union types
    assert is_primitive_or_primitive_union(Union[str, int, None]) is True
    assert is_primitive_or_primitive_union(Union[str, int, Foo]) is False
    assert is_primitive_or_primitive_union(Union[float]) is True
    assert is_primitive_or_primitive_union(Optional[str]) is True
    assert is_primitive_or_primitive_union(Optional[int]) is True
    assert is_primitive_or_primitive_union(Optional[Foo]) is False
