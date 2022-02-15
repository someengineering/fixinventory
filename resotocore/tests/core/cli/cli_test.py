from asyncio import Queue

import pytest
from aiostream import stream
from pytest import fixture
from typing import Tuple, List, AsyncIterator

from core.analytics import InMemoryEventSender
from core.cli.model import ParsedCommands, ParsedCommand, CLIContext
from core.cli.cli import CLI, multi_command_parser
from core.cli.model import CLIDependencies
from core.cli.command import (
    ExecuteQueryCommand,
    ChunkCommand,
    FlattenCommand,
    UniqCommand,
    EchoCommand,
    aliases,
    AggregateToCountCommand,
    all_commands,
    PredecessorsPart,
)
from core.db.db_access import DbAccess
from core.db.graphdb import ArangoGraphDB
from core.dependencies import parse_args
from core.error import CLIParseError
from core.message_bus import MessageBus
from core.model.adjust_node import NoAdjust
from core.model.graph_access import EdgeType
from core.model.model import Model
from core.query.template_expander import TemplateExpander
from core.worker_task_queue import WorkerTaskQueue, WorkerTaskDescription
from tests.core.model import ModelHandlerStatic

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import filled_graph_db, graph_db, test_db, foo_kinds, foo_model, local_client, system_db

# noinspection PyUnresolvedReferences
from tests.core.message_bus_test import message_bus

# noinspection PyUnresolvedReferences
from tests.core.worker_task_queue_test import worker, task_queue, performed_by, incoming_tasks

# noinspection PyUnresolvedReferences
from tests.core.analytics import event_sender

# noinspection PyUnresolvedReferences
from tests.core.query.template_expander_test import expander


@fixture
async def cli_deps(
    filled_graph_db: ArangoGraphDB,
    message_bus: MessageBus,
    event_sender: InMemoryEventSender,
    foo_model: Model,
    task_queue: WorkerTaskQueue,
    worker: Tuple[WorkerTaskDescription, WorkerTaskDescription, WorkerTaskDescription],
    expander: TemplateExpander,
) -> AsyncIterator[CLIDependencies]:
    db_access = DbAccess(filled_graph_db.db.db, event_sender, NoAdjust())
    model_handler = ModelHandlerStatic(foo_model)
    args = parse_args(["--graphdb-database", "test", "--graphdb-username", "test", "--graphdb-password", "test"])
    deps = CLIDependencies(
        message_bus=message_bus,
        event_sender=event_sender,
        db_access=db_access,
        model_handler=model_handler,
        worker_task_queue=task_queue,
        args=args,
        template_expander=expander,
        forked_tasks=Queue(),
    )
    yield deps
    await deps.stop()


@fixture
def cli(cli_deps: CLIDependencies) -> CLI:
    env = {"graph": "ns", "section": "reported"}
    return CLI(cli_deps, all_commands(cli_deps), env, aliases())


def test_command_line_parser() -> None:
    def check(cmd_lind: str, expected: List[List[str]]) -> None:
        parsed: List[ParsedCommands] = multi_command_parser.parse(cmd_lind)

        def cmd_to_str(cmd: ParsedCommand) -> str:
            arg = f" {cmd.args}" if cmd.args else ""
            return f"{cmd.cmd}{arg}"

        assert [[cmd_to_str(cmd) for cmd in line.commands] for line in parsed] == expected

    check("test", [["test"]])
    check("test | bla |  bar", [["test", "bla", "bar"]])
    check('query is(foo) and bla.test=="foo"', [['query is(foo) and bla.test=="foo"']])
    check('a 1 | b "s" | c 1.23 | d', [["a 1", 'b "s"', "c 1.23", "d"]])
    check('jq ". | {a:.foo, b: .bla}" ', [['jq ". | {a:.foo, b: .bla}"']])
    check("a|b|c;d|e|f;g|e|h", [["a", "b", "c"], ["d", "e", "f"], ["g", "e", "h"]])
    check("add_job 'what \" test | foo | bla'", [["add_job 'what \" test | foo | bla'"]])
    check('add_job what \\" test \\| foo \\| bla', [['add_job what " test | foo | bla']])


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
    assert len(line1.commands) == 2
    l1p1, l1p2 = line1.commands
    assert isinstance(l1p1, EchoCommand)
    assert isinstance(l1p2, ChunkCommand)
    assert len(line2.commands) == 4
    l2p1, l2p2, l2p3, l2p4 = line2.commands
    assert isinstance(l2p1, EchoCommand)
    assert isinstance(l2p2, ChunkCommand)
    assert isinstance(l2p3, FlattenCommand)
    assert isinstance(l2p4, UniqCommand)
    assert len(line3.commands) == 2
    l3p1, l3p2 = line3.commands
    assert isinstance(l3p1, EchoCommand)
    assert isinstance(l3p2, ChunkCommand)


@pytest.mark.asyncio
async def test_query_database(cli: CLI) -> None:
    query = 'query is("foo") and some_string=="hello" --> f>12 and f<100 and g[*]==2'
    count = "count f"
    commands = "|".join([query, count])
    result = await cli.evaluate_cli_command(commands)
    assert len(result) == 1
    line1 = result[0]
    assert len(line1.commands) == 2
    p1, p2 = line1.commands
    assert isinstance(p1, ExecuteQueryCommand)
    assert isinstance(p2, AggregateToCountCommand)

    with pytest.raises(Exception):
        await cli.evaluate_cli_command("query this is not a query")  # command is un-parsable

    with pytest.raises(CLIParseError):
        cli.cli_env = {}  # delete the env
        await cli.evaluate_cli_command("query id==3")  # no graph specified


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
        await cli.evaluate_cli_command("echo foo | uniq | query bla==23")
    assert str(ex.value) == "Command >query< can not be used in this position: must be the first command"


@pytest.mark.asyncio
async def test_help(cli: CLI) -> None:
    result = await cli.execute_cli_command("help", stream.list)
    assert len(result[0]) == 1

    result = await cli.execute_cli_command("help count", stream.list)
    assert len(result[0]) == 1


@pytest.mark.asyncio
async def test_parse_env_vars(cli: CLI) -> None:
    result = await cli.execute_cli_command('test=foo bla="bar"   d=true env', stream.list)
    # the env is allowed to have more items. Check only for this subset.
    assert {"test": "foo", "bla": "bar", "d": True}.items() <= result[0][0].items()


def test_parse_predecessor_successor_ancestor_descendant_args() -> None:
    plain = CLIContext()
    w_delete = CLIContext(env={"edge_type": EdgeType.delete})
    assert PredecessorsPart.parse_args(None, w_delete) == (1, EdgeType.delete)
    assert PredecessorsPart.parse_args(None, plain) == (1, EdgeType.default)
    assert PredecessorsPart.parse_args("--with-origin", plain) == (0, EdgeType.default)
    assert PredecessorsPart.parse_args("--with-origin", w_delete) == (0, EdgeType.delete)
    assert PredecessorsPart.parse_args("--with-origin delete", plain) == (0, EdgeType.delete)
    assert PredecessorsPart.parse_args("--with-origin delete", w_delete) == (0, EdgeType.delete)
    assert PredecessorsPart.parse_args("delete", w_delete) == (1, EdgeType.delete)


@pytest.mark.asyncio
async def test_create_query_parts(cli: CLI) -> None:
    commands = await cli.evaluate_cli_command('query some_int==0 | query identifier=~"9_" | descendants')
    assert len(commands) == 1
    assert len(commands[0].commands) == 1
    assert commands[0].commands[0].name == "execute_query"
    assert (
        commands[0].executable_commands[0].arg
        == '(reported.some_int == 0 and reported.identifier =~ "9_") -default[1:]->'
    )
    commands = await cli.evaluate_cli_command("query some_int==0 | descendants")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 -default[1:]->"
    commands = await cli.evaluate_cli_command("query some_int==0 | ancestors | ancestors")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 <-default[2:]-"
    commands = await cli.evaluate_cli_command("query some_int==0 | predecessors | predecessors")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 <-default[2]-"
    commands = await cli.evaluate_cli_command("query some_int==0 | successors | successors | successors")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 -default[3]->"
    commands = await cli.evaluate_cli_command("query some_int==0 | successors | predecessors")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 -default-> all <-default-"
    # defining the edge type is supported as well
    commands = await cli.evaluate_cli_command("query some_int==0 | successors delete")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 -delete->"
    commands = await cli.evaluate_cli_command("query some_int==0 | predecessors delete")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 <-delete-"
    commands = await cli.evaluate_cli_command("query some_int==0 | descendants delete")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 -delete[1:]->"
    commands = await cli.evaluate_cli_command("query some_int==0 | ancestors delete")
    assert commands[0].executable_commands[0].arg == "reported.some_int == 0 <-delete[1:]-"
    commands = await cli.evaluate_cli_command("query some_int==0 | aggregate foo, bla as bla: sum(bar)")
    assert (
        commands[0].executable_commands[0].arg
        == "aggregate(reported.foo, reported.bla as bla: sum(reported.bar)):reported.some_int == 0"
    )
