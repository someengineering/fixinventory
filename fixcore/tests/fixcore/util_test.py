import json
import shutil
from copy import deepcopy
from datetime import datetime, timezone

import pytest
import pytz
from aiostream import stream

from fixcore.util import (
    AccessJson,
    force_gen,
    uuid_str,
    value_in_path,
    value_in_path_get,
    set_value_in_path,
    rnd_str,
    del_value_in_path,
    deep_merge,
    partition_by,
    utc_str,
    parse_utc,
)


def not_in_path(name: str, *other: str) -> bool:
    for n in [name, *other]:
        if shutil.which(n) is None:
            return True
    return False


def test_partition_by() -> None:
    even, odd = partition_by(lambda x: x % 2 == 0, range(10))
    assert even == [0, 2, 4, 6, 8]
    assert odd == [1, 3, 5, 7, 9]


def test_access_json() -> None:
    js = {"a": "a", "b": {"c": "c", "d": {"e": "e", "f": [0, 1, 2, 3, 4]}}}
    access = AccessJson(js, "null", self_name="this")

    assert access.a == "a"
    assert access.b.d.f[2] == 2
    assert access.this == js
    assert str(access.b.d.f[99]) is "null"
    assert str(access.b.d.f["test"]) is "null"
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
    js = {"foo": {"bla": {"test": 123}}, "b": [{"a": 1, "b": [1, 2, 3]}, {"a": 2, "b": [1, 2, 3]}]}
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


def test_deep_merge() -> None:
    l = {"a": {"b": 1, "d": 2}, "d": 2, "e": 4}
    r = {"a": {"c": 1, "d": 3}, "d": 1}
    assert deep_merge(l, r) == {"a": {"b": 1, "c": 1, "d": 3}, "d": 1, "e": 4}

    a = {"a": {"foo": {"first": "first", "last": "laaaast"}}, "b": {"bar": 123}, "c": [6, 7]}
    b = {"a": {"foo": {"last": "last"}}, "b": {"baz": 456}, "c": [8, 9]}
    assert deep_merge(a, b) == {
        "a": {"foo": {"first": "first", "last": "last"}},
        "b": {"bar": 123, "baz": 456},
        "c": [8, 9],
    }


def test_utc() -> None:
    # datetime in utc
    assert utc_str(datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)) == "2020-01-01T00:00:00Z"
    # no timezone: assume utc
    assert utc_str(datetime(2020, 1, 1, 0, 0, 0, 0)) == "2020-01-01T00:00:00Z"
    # different timezone: convert to utc
    assert utc_str(datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=pytz.timezone("CET"))) == "2019-12-31T23:00:00Z"
    # gmt same timezone as utc
    assert utc_str(datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=pytz.timezone("GMT"))) == "2020-01-01T00:00:00Z"

    # valid utc
    assert parse_utc("2020-01-01T00:00:00Z") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    # no timezone: assume utc
    assert parse_utc("2020-01-01T00:00:00") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    # different timezone: convert to utc
    assert parse_utc("2019-12-31T23:00:00-01:00") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    assert parse_utc("2019-12-31T22:00:00-02:00") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    assert parse_utc("2020-01-01T00:00:00+00:00") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    # other formats
    assert parse_utc("20200101T000000Z") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    assert parse_utc("20200101000000") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    assert parse_utc("20200101") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    assert parse_utc("2020-01-01") == datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
