from typing import List

import pytest
from aiostream import stream
from pytest import fixture

from core.cli.cli import CLI, Sink, CLIDependencies
from core.error import CLIParseError

from core.types import JsonElement

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import filled_graph_db, graph_db, test_db, foo_model

# noinspection PyUnresolvedReferences
from core.cli.command import ListSink

# noinspection PyUnresolvedReferences
from tests.core.cli.cli_test import cli, sink, cli_deps

# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus


@fixture
def json_source() -> str:
    nums = ",".join([f'{{ "num": {a}}}' for a in range(0, 100)])
    return "json [" + nums + "," + nums + "]"


@pytest.mark.asyncio
async def test_echo_source(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    # no arg passed to json
    result = await cli.execute_cli_command("echo", sink)
    assert result[0] == [""]

    # simple string passed to json
    result = await cli.execute_cli_command("echo this is a string", sink)
    assert result[0] == ["this is a string"]

    result = await cli.execute_cli_command('echo "foo bla bar"', sink)
    assert result[0] == ["foo bla bar"]


@pytest.mark.asyncio
async def test_json_source(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    # json object passed to json
    result = await cli.execute_cli_command('json {"a": 1}', sink)
    assert result[0] == [{"a": 1}]

    # json array passed to json
    result = await cli.execute_cli_command('json [{"a": 1}, {"b":2}]', sink)
    assert result[0] == [{"a": 1}, {"b": 2}]

    # json string passed to json
    result = await cli.execute_cli_command('json "foo bla bar"', sink)
    assert result[0] == ["foo bla bar"]


@pytest.mark.asyncio
async def test_query_source(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    result = await cli.execute_cli_command(
        'query isinstance("foo") and reported.some_int==0 --> reported.identifier=~"9_"', sink
    )
    assert len(result[0]) == 10


@pytest.mark.asyncio
async def test_sleep_source(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    with pytest.raises(CLIParseError):
        await cli.evaluate_cli_command("sleep forever")
    result = await cli.execute_cli_command("sleep 0.001; echo hello", sink)
    assert result == [[""], ["hello"]]


@pytest.mark.asyncio
async def test_count_command(cli: CLI, sink: Sink[List[JsonElement]], json_source: str) -> None:
    # count instances
    result = await cli.execute_cli_command(f"{json_source} | count", sink)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 200, "not_matched": 0}

    # count attributes
    result = await cli.execute_cli_command(f"{json_source} | count num", sink)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 9900, "not_matched": 0}

    # count unknown attributes
    result = await cli.execute_cli_command(f"{json_source} | count does_not_exist", sink)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 0, "not_matched": 200}


@pytest.mark.asyncio
async def test_chunk_command(cli: CLI, sink: Sink[List[JsonElement]], json_source: str) -> None:
    result: list[list[str]] = await cli.execute_cli_command(f"{json_source} | chunk 50", sink)
    assert len(result[0]) == 4  # 200 in chunks of 50
    for a in result[0]:
        assert len(a) == 50


@pytest.mark.asyncio
async def test_flatten_command(cli: CLI, sink: Sink[List[JsonElement]], json_source: str) -> None:
    result = await cli.execute_cli_command(f"{json_source} | chunk 50 | flatten", sink)
    assert len(result[0]) == 200


@pytest.mark.asyncio
async def test_uniq_command(cli: CLI, sink: Sink[List[JsonElement]], json_source: str) -> None:
    result = await cli.execute_cli_command(f"{json_source} | uniq", sink)
    assert len(result[0]) == 100


@pytest.mark.asyncio
async def test_desire_command(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    result = await cli.execute_cli_command('query isinstance("foo") | desire a="test" b=1 c=true', sink)
    assert len(result[0]) == 13
    for elem in result[0]:
        assert elem["desired"] == {"a": "test", "b": 1, "c": True}


@pytest.mark.asyncio
async def test_clean_command(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    result = await cli.execute_cli_command('query isinstance("foo") | clean', sink)
    assert len(result[0]) == 13
    for elem in result[0]:
        assert elem["desired"] == {"clean": True}


@pytest.mark.asyncio
async def test_list_sink(cli: CLI, cli_deps: CLIDependencies) -> None:
    sink = await ListSink(cli_deps).parse()
    result = await cli.execute_cli_command("json [1,2,3]", sink)
    assert result == [[1, 2, 3]]


@pytest.mark.asyncio
async def test_flat_sink(cli: CLI) -> None:
    parsed = await cli.evaluate_cli_command("json [1,2,3]; json [4,5,6]; json [7,8,9]")
    result = await stream.list(stream.concat(stream.iterate(p.generator for p in parsed)))
    assert result == [1, 2, 3, 4, 5, 6, 7, 8, 9]


@pytest.mark.asyncio
async def test_format(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    # access properties by name and path
    result = await cli.execute_cli_command('json {"a":"b", "b": {"c":"d"}} | format a:{a} b:{b.c} na:{fuerty}', sink)
    assert result[0] == ["a:b b:d na:null"]
    # access deeply nested properties with dict and array
    result = await cli.execute_cli_command(
        'json {"a":{"b":{"c":{"d":[0,1,2, {"e":"f"}]}}}} | format will be an >{a.b.c.d[3].e}<', sink
    )
    assert result[0] == ["will be an >f<"]
    # make sure any path that is not available leads to the null value
    result = await cli.execute_cli_command("json {} | format {a}:{b.c.d}:{foo.bla[23].test}", sink)
    assert result[0] == ["null:null:null"]
