from datetime import timedelta
from typing import Optional, ClassVar, Union, Literal, Any

from attrs import define

from fixlib.json import to_json, from_json, is_primitive_or_primitive_union, sort_json
from fixlib.utils import utc


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


def test_complex() -> None:
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


def test_predefined() -> None:
    def roundtrip(value: Any) -> Any:
        again = from_json(to_json(value), type(value))
        assert to_json(again) == to_json(value)

    roundtrip(utc())
    roundtrip(utc().date())
    roundtrip(timedelta(seconds=42))
    roundtrip(Foo("foo", 42, "bar"))


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


def test_json_sort() -> None:
    simple = {"c": [3, 2, 1], "b": 2, "a": 1}
    simple2 = {"c": [3, 2, 4], "b": 3, "a": 2}
    simple3 = {"c": [5, 2, 3], "b": 4, "a": 3}
    assert sort_json(simple) == {"a": 1, "b": 2, "c": [3, 2, 1]}
    assert sort_json(simple, sort_list=True) == {"a": 1, "b": 2, "c": [1, 2, 3]}
    complex = {"d": [simple2, simple3, simple], "a": {"c": simple3, "b": simple2, "a": simple}}
    assert sort_json(complex, sort_list=True) == {
        "a": {
            "a": {"a": 1, "b": 2, "c": [1, 2, 3]},
            "b": {"a": 2, "b": 3, "c": [2, 3, 4]},
            "c": {"a": 3, "b": 4, "c": [2, 3, 5]},
        },
        "d": [{"a": 2, "b": 3, "c": [2, 3, 4]}, {"a": 3, "b": 4, "c": [2, 3, 5]}, {"a": 1, "b": 2, "c": [1, 2, 3]}],
    }
