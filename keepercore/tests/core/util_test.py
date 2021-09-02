import json

import pytest
from aiostream import stream

from core.util import AccessJson, force_gen


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
