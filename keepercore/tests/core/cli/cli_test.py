from typing import List

import pytest
from pytest import fixture

from core.cli.cli import CLI, CLIDependencies, Sink
from core.cli.command import (
    ListSink,
    MatchSource,
    CountCommand,
    ChunkCommand,
    all_parts,
    FlattenCommand,
    UniqCommand,
    EchoSource,
)
from core.db.db_access import DbAccess
from core.db.graphdb import ArangoGraphDB
from core.error import CLIParseError
from core.event_bus import EventBus
from core.model.model import Model
from core.types import JsonElement

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import filled_graph_db, graph_db, test_db, foo_model

# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus
from tests.core.model import ModelHandlerStatic


@fixture
def cli_deps(filled_graph_db: ArangoGraphDB, event_bus: EventBus, foo_model: Model) -> CLIDependencies:
    db_access = DbAccess(filled_graph_db.db.db, event_bus)
    model_handler = ModelHandlerStatic(foo_model)
    return CLIDependencies(event_bus, db_access, model_handler)


@fixture
def cli(cli_deps: CLIDependencies) -> CLI:
    env = {"graph": "ns"}
    return CLI(cli_deps, all_parts(cli_deps), env)


@fixture
async def sink(cli_deps: CLIDependencies) -> Sink[List[JsonElement]]:
    return await ListSink(cli_deps).parse()


@pytest.mark.asyncio
async def test_multi_command(cli: CLI) -> None:
    nums = ",".join([f'{{ "num": {a}}}' for a in range(0, 100)])
    source = "echo [" + nums + "," + nums + "]"
    command1 = f"{source} | chunk 7"
    command2 = f"{source} | chunk | flatten | uniq"
    command3 = f"{source} | chunk 10"
    commands = ";".join([command1, command2, command3])
    result = await cli.evaluate_cli_command(commands)
    assert len(result) == 3
    line1, line2, line3 = result
    assert len(line1.parts) == 2
    l1p1, l1p2 = line1.parts
    assert isinstance(l1p1, EchoSource)
    assert isinstance(l1p2, ChunkCommand)
    assert len(line2.parts) == 4
    l2p1, l2p2, l2p3, l2p4 = line2.parts
    assert isinstance(l2p1, EchoSource)
    assert isinstance(l2p2, ChunkCommand)
    assert isinstance(l2p3, FlattenCommand)
    assert isinstance(l2p4, UniqCommand)
    assert len(line3.parts) == 2
    l3p1, l3p2 = line3.parts
    assert isinstance(l3p1, EchoSource)
    assert isinstance(l3p2, ChunkCommand)


@pytest.mark.asyncio
async def test_query_database(cli: CLI) -> None:
    query = 'match isinstance("foo") and some_string=="hello" --> f>12 and f<100 and g[*]==2'
    count = "count f"
    commands = "|".join([query, count])
    result = await cli.evaluate_cli_command(commands)
    assert len(result) == 1
    line1 = result[0]
    assert len(line1.parts) == 2
    p1, p2 = line1.parts
    assert isinstance(p1, MatchSource)
    assert isinstance(p2, CountCommand)

    with pytest.raises(CLIParseError):
        await cli.evaluate_cli_command("match this is not a query")  # command is un-parsable

    with pytest.raises(CLIParseError):
        cli.cli_env = {}  # delete the env
        await cli.evaluate_cli_command("match id==3")  # no graph specified


@pytest.mark.asyncio
async def test_unknown_command(cli: CLI) -> None:
    with pytest.raises(CLIParseError) as ex:
        await cli.evaluate_cli_command("echo foo | uniq |  some_not_existing_command")
    assert str(ex.value) == "Command >some_not_existing_command< is not known. typo?"


@pytest.mark.asyncio
async def test_order_of_commands(cli: CLI) -> None:
    with pytest.raises(CLIParseError) as ex:
        await cli.evaluate_cli_command("uniq")
    assert str(ex.value) == "Command >uniq< can not be used in this position: no source data given"

    with pytest.raises(CLIParseError) as ex:
        await cli.evaluate_cli_command("echo foo | uniq | match bla==23")
    assert str(ex.value) == "Command >match< can not be used in this position: must be the first command"


@pytest.mark.asyncio
async def test_help(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    result = await cli.execute_cli_command("help", sink)
    assert len(result[0]) == 1

    result = await cli.execute_cli_command("help count", sink)
    assert len(result[0]) == 1


@pytest.mark.asyncio
async def test_parse_env_vars(cli: CLI, sink: Sink[List[JsonElement]]) -> None:
    result = await cli.execute_cli_command('test=foo bla="bar"   d=true env', sink)
    # the env is allowed to have more items. Check only for this subset.
    assert {"test": "foo", "bla": "bar", "d": True}.items() <= result[0][0].items()
