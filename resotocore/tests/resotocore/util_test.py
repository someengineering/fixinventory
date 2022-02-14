import json
import shutil

import pytest
from aiostream import stream
from copy import deepcopy

from resotocore.util import (
    AccessJson,
    force_gen,
    uuid_str,
    value_in_path,
    value_in_path_get,
    set_value_in_path,
    rnd_str,
    del_value_in_path,
)


def not_in_path(name: str, *other: str) -> bool:
    for n in [name, *other]:
        if shutil.which(n) is None:
            return True
    return False


def test_access_json() -> None:
    js = {"a": "a", "b": {"c": "c", "d": {"e": "e", "f": [0, 1, 2, 3, 4]}}}
    access = AccessJson(js, "null")

    assert access.a == "a"
    assert access.b.d.f[2] == 2
    assert str(access.foo.bla.bar[23].now) is "null"
    assert json.dumps(access.b.d, sort_keys=True) == '{"e": "e", "f": [0, 1, 2, 3, 4]}'

    assert access["a"] == "a"
    assert access["b"]["d"]["f"][2] == 2
    assert str(access["foo"]["bla"]["bar"][23]["now"]) is "null"
    assert json.dumps(access["b"]["d"], sort_keys=True) == '{"e": "e", "f": [0, 1, 2, 3, 4]}'

    assert [a for a in access] == ["a", "b"]
    assert [a for a in access.doesnt.exist] == []
    assert [a for a in access.b.d.items()] == [("e", "e"), ("f", [0, 1, 2, 3, 4])]


def test_uuid() -> None:
    assert uuid_str("foo") == uuid_str("foo")
    assert uuid_str("foo") != uuid_str("bla")
    assert uuid_str() != uuid_str()


def test_random_str() -> None:
    assert rnd_str() != rnd_str()


def test_value_in_path() -> None:
    js = {"foo": {"bla": {"test": 123}}}
    assert value_in_path(js, ["foo", "bla", "test"]) == 123
    assert value_in_path_get(js, ["foo", "bla", "test"], "foo") == "foo"  # expected string got int -> default value
    assert value_in_path(js, ["foo", "bla", "test", "bar"]) is None
    assert value_in_path_get(js, ["foo", "bla", "test", "bar"], 123) == 123
    assert value_in_path(js, ["foo", "bla", "bar"]) is None
    assert value_in_path_get(js, ["foo", "bla", "bar"], "foo") == "foo"


def test_set_value_in_path() -> None:
    js = {"foo": {"bla": {"test": 123}}}
    res = set_value_in_path(124, ["foo", "bla", "test"], deepcopy(js))
    assert res == {"foo": {"bla": {"test": 124}}}
    res = set_value_in_path(124, ["foo", "bla", "blubber"], deepcopy(js))
    assert res == {"foo": {"bla": {"test": 123, "blubber": 124}}}
    res = set_value_in_path(js, ["foo", "bla", "test"])
    assert res == {"foo": {"bla": {"test": js}}}
    res = {"a": 1}
    set_value_in_path(23, ["reported"], res)
    assert res == {"a": 1, "reported": 23}


def test_del_value_in_path() -> None:
    js = {"foo": {"bla": {"test": 123}}}
    res = del_value_in_path(deepcopy(js), ["foo", "bla", "test"])
    assert res == {"foo": {"bla": None}}
    js = {"foo": {"bla": {"test": 123}}}
    res = del_value_in_path(deepcopy(js), ["foo", "bla", "bar"])
    assert res == {"foo": {"bla": {"test": 123}}}
    js = {"foo": {"bla": {"test": 123}}}
    res = del_value_in_path(deepcopy(js), ["foo", "bla"])
    assert res == {"foo": None}
    res = del_value_in_path(deepcopy(js), ["foo"])
    assert res == {}


@pytest.mark.asyncio
async def test_async_gen() -> None:

    async with stream.empty().stream() as empty:
        async for _ in await force_gen(empty):
            pass

    with pytest.raises(Exception):
        async with stream.throw(Exception(";)")).stream() as err:
            async for _ in await force_gen(err):
                pass

    async with stream.iterate(range(0, 100)).stream() as elems:
        assert [x async for x in await force_gen(elems)] == list(range(0, 100))
