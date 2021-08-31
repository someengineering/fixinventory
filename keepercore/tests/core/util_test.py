import json

from core.util import AccessJson, uuid_str


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


def test_uuid() -> None:
    assert uuid_str("foo") == uuid_str("foo")
    assert uuid_str("foo") != uuid_str("bla")
    assert uuid_str() != uuid_str()
