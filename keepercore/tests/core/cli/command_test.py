from typing import List

import pytest
from aiostream import stream
from pytest import fixture

from core.cli.cli import CLI, Sink, CLIDependencies

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import filled_graph_db, graph_db, test_db, foo_model

# noinspection PyUnresolvedReferences
from core.cli.command import ListSink

# noinspection PyUnresolvedReferences
from tests.core.cli.cli_test import cli, sink, cli_deps

# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus


@fixture
def echo_source() -> str:
    nums = ",".join([f'{{ "num": {a}}}' for a in range(0, 100)])
    return "echo [" + nums + "," + nums + "]"


@pytest.mark.asyncio
async def test_echo_source(cli: CLI, sink: Sink[List[str]]) -> None:
    result = await cli.execute_cli_command('echo [{"a": 1}, {"b":2}]', sink)
    assert result[0] == [{"a": 1}, {"b": 2}]

    result = await cli.execute_cli_command("echo [1,2,3,4]", sink)
    assert result[0] == [1, 2, 3, 4]

    result = await cli.execute_cli_command('echo "foo bla bar"', sink)
    assert result[0] == ["foo bla bar"]


@pytest.mark.asyncio
async def test_match_source(cli: CLI, sink: Sink[List[str]]) -> None:
    result = await cli.execute_cli_command('match isinstance("foo") and some_int==0 --> identifier=~"9_"', sink)
    assert len(result[0]) == 10


@pytest.mark.asyncio
async def test_count_command(cli: CLI, sink: Sink[List[str]], echo_source: str) -> None:
    # count instances
    result = await cli.execute_cli_command(f"{echo_source} | count", sink)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 200, "not_matched": 0}

    # count attributes
    result = await cli.execute_cli_command(f"{echo_source} | count num", sink)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 9900, "not_matched": 0}

    # count unknown attributes
    result = await cli.execute_cli_command(f"{echo_source} | count does_not_exist", sink)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 0, "not_matched": 200}


@pytest.mark.asyncio
async def test_chunk_command(cli: CLI, sink: Sink[List[str]], echo_source: str) -> None:
    result = await cli.execute_cli_command(f"{echo_source} | chunk 50", sink)
    assert len(result[0]) == 4  # 200 in chunks of 50
    for a in result[0]:
        assert len(a) == 50


@pytest.mark.asyncio
async def test_flatten_command(cli: CLI, sink: Sink[List[str]], echo_source: str) -> None:
    result = await cli.execute_cli_command(f"{echo_source} | chunk 50 | flatten", sink)
    assert len(result[0]) == 200


@pytest.mark.asyncio
async def test_uniq_command(cli: CLI, sink: Sink[List[str]], echo_source: str) -> None:
    result = await cli.execute_cli_command(f"{echo_source} | uniq", sink)
    assert len(result[0]) == 100


@pytest.mark.asyncio
async def test_desire_command(cli: CLI, sink: Sink[List[str]]) -> None:
    result = await cli.execute_cli_command('match isinstance("foo") | desire a="test" b=1 c=true', sink)
    assert len(result[0]) == 11
    for elem in result[0]:
        assert elem["desired"] == {"a": "test", "b": 1, "c": True}


@pytest.mark.asyncio
async def test_mark_delete_command(cli: CLI, sink: Sink[List[str]]) -> None:
    result = await cli.execute_cli_command('match isinstance("foo") | mark_delete', sink)
    assert len(result[0]) == 11
    for elem in result[0]:
        assert elem["desired"] == {"delete": True}


@pytest.mark.asyncio
async def test_list_sink(cli: CLI, cli_deps: CLIDependencies) -> None:
    sink = await ListSink(cli_deps).parse()
    result = await cli.execute_cli_command("echo [1,2,3]", sink)
    assert result == [[1, 2, 3]]


@pytest.mark.asyncio
async def test_flat_sink(cli: CLI) -> None:
    parsed = await cli.evaluate_cli_command("echo [1,2,3]; echo [4,5,6]; echo [7,8,9]")
    result = await stream.list(stream.concat(stream.iterate(p.generator for p in parsed)))
    assert result == [1, 2, 3, 4, 5, 6, 7, 8, 9]
