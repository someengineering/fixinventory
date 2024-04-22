from typing import List

import pytest

from fixcore.cli import strip_quotes, js_value_at, args_parts_parser, args_parts_unquoted_parser, list_sink
from fixcore.cli.cli import multi_command_parser, CLIService
from fixcore.cli.command import (
    ExecuteSearchCommand,
    ChunkCommand,
    FlattenCommand,
    UniqCommand,
    EchoCommand,
    AggregateToCountCommand,
    PredecessorsPart,
    DumpCommand,
)
from fixcore.cli.model import (
    ParsedCommands,
    ParsedCommand,
    CLIContext,
    CLI,
    InfraAppAlias,
    CLICommand,
    ExecutableCommand,
)
from fixcore.error import CLIParseError
from fixcore.model.graph_access import EdgeTypes
from fixcore.util import utc


def test_strip() -> None:
    assert strip_quotes("'test'") == "test"
    assert strip_quotes('"test"') == "test"


def test_split_args_parser() -> None:
    assert args_parts_parser.parse("1 2   3    4") == ["1", "2", "3", "4"]
    assert args_parts_parser.parse('(id == "1  \\"2 3 () 4 5")') == ["(id", "==", '"1  \\"2 3 () 4 5"', ")"]
    assert args_parts_parser.parse("'doo' \"bla\" '\\'bar'") == ["doo", '"bla"', "\\'bar"]
    assert args_parts_unquoted_parser.parse("1 2   3    4") == ["1", "2", "3", "4"]
    assert args_parts_unquoted_parser.parse('(id == "1  \\"2 3 () 4 5")') == ["(id", "==", '1  \\"2 3 () 4 5', ")"]
    assert args_parts_unquoted_parser.parse("'doo' \"bla\" '\\'bar'") == ["doo", "bla", "\\'bar"]


def test_command_line_parser() -> None:
    def check(cmd_lind: str, expected: List[List[str]]) -> None:
        parsed: List[ParsedCommands] = multi_command_parser.parse(cmd_lind)

        def cmd_to_str(cmd: ParsedCommand) -> str:
            arg = f" {cmd.args}" if cmd.args else ""
            return f"{cmd.cmd}{arg}"

        assert [[cmd_to_str(cmd) for cmd in line.commands] for line in parsed] == expected

    check("test", [["test"]])
    check("test | bla |  bar", [["test", "bla", "bar"]])
    check('search is(foo) and bla.test=="foo"', [['search is(foo) and bla.test=="foo"']])
    check('a 1 | b "s" | c 1.23 | d', [["a 1", 'b "s"', "c 1.23", "d"]])
    check('jq ". | {a:.foo, b: .bla}" ', [['jq ". | {a:.foo, b: .bla}"']])
    check("a|b|c;d|e|f;g|e|h", [["a", "b", "c"], ["d", "e", "f"], ["g", "e", "h"]])
    check("add_job 'what \" test | foo | bla'", [["add_job 'what \" test | foo | bla'"]])
    check('add_job what \\" test \\| foo \\| bla', [['add_job what " test | foo | bla']])


@pytest.mark.asyncio
async def test_multi_command(cli: CLI) -> None:
    nums = ",".join([f'{{ "num": {a}}}' for a in range(0, 100)])
    source = "echo [" + nums + "," + nums + "]"
    command1 = f"{source} | chunk 7 | dump"
    command2 = f"{source} | chunk | flatten | uniq | dump"
    command3 = f"{source} | chunk 10 | dump"
    commands = ";".join([command1, command2, command3])
    result = await cli.evaluate_cli_command(commands)
    assert len(result) == 3
    line1, line2, line3 = result
    assert len(line1.commands) == 3
    l1p1, l1p2, _ = line1.commands
    assert isinstance(l1p1, EchoCommand)
    assert isinstance(l1p2, ChunkCommand)
    assert len(line2.commands) == 5
    l2p1, l2p2, l2p3, l2p4, _ = line2.commands
    assert isinstance(l2p1, EchoCommand)
    assert isinstance(l2p2, ChunkCommand)
    assert isinstance(l2p3, FlattenCommand)
    assert isinstance(l2p4, UniqCommand)
    assert len(line3.commands) == 3
    l3p1, l3p2, _ = line3.commands
    assert isinstance(l3p1, EchoCommand)
    assert isinstance(l3p2, ChunkCommand)


@pytest.mark.asyncio
async def test_query_database(cli: CLIService) -> None:
    query = 'search is("foo") and some_string=="hello" --> f>12 and f<100 and g[*]==2'
    commands = "|".join([query, "count f", "dump"])
    result = await cli.evaluate_cli_command(commands)
    assert len(result) == 1
    line1 = result[0]
    assert len(line1.commands) == 3
    p1, p2, p3 = line1.commands
    assert isinstance(p1, ExecuteSearchCommand)
    assert isinstance(p2, AggregateToCountCommand)
    assert isinstance(p3, DumpCommand)

    with pytest.raises(Exception):
        await cli.evaluate_cli_command("search a>>>>")  # command is un-parsable

    with pytest.raises(CLIParseError):
        cli.cli_env = {}  # delete the env
        await cli.evaluate_cli_command("query id==3")  # no graph specified


@pytest.mark.asyncio
async def test_unknown_command(cli: CLI) -> None:
    with pytest.raises(CLIParseError) as ex:
        await cli.evaluate_cli_command("echo foo | uniq |  some_not_existing_command")
    assert str(ex.value) == "Command >some_not_existing_command< is not known. Typo?"


@pytest.mark.asyncio
async def test_order_of_commands(cli: CLI) -> None:
    with pytest.raises(CLIParseError) as ex:
        await cli.evaluate_cli_command("uniq")
    assert str(ex.value) == "Command >uniq< can not be used in this position: no source data given"

    with pytest.raises(CLIParseError) as ex:
        await cli.evaluate_cli_command("echo foo | uniq | search bla==23")
    assert str(ex.value) == "Command >search< can not be used in this position: must be the first command"


@pytest.mark.asyncio
async def test_help(cli: CLI) -> None:
    result = await cli.execute_cli_command("help", list_sink)
    assert len(result[0]) == 1

    # help for command
    result = await cli.execute_cli_command("help count", list_sink)
    assert len(result[0]) == 1

    # help for alias
    result = await cli.execute_cli_command("help kind", list_sink)
    assert len(result[0]) == 1

    # help for alias template
    result = await cli.execute_cli_command("help discord", list_sink)
    assert len(result[0]) == 1

    # help for infra app alias
    cli.register_infra_app_alias(InfraAppAlias("testcommand", "this is a test alias", "this is a readme", []))
    result = await cli.execute_cli_command("help testcommand", list_sink)
    assert len(result[0]) == 1


@pytest.mark.asyncio
async def test_parse_env_vars(cli: CLI) -> None:
    result = await cli.execute_cli_command('test=foo bla="bar"   d=true env', list_sink)
    # the env is allowed to have more items. Check only for this subset.
    assert {"test": "foo", "bla": "bar", "d": True}.items() <= result[0][0].items()


def test_parse_predecessor_successor_ancestor_descendant_args() -> None:
    plain = CLIContext()
    w_delete = CLIContext(env={"edge_type": EdgeTypes.delete})
    assert PredecessorsPart.parse_args(None, w_delete) == (1, EdgeTypes.delete)
    assert PredecessorsPart.parse_args(None, plain) == (1, EdgeTypes.default)
    assert PredecessorsPart.parse_args("--with-origin", plain) == (0, EdgeTypes.default)
    assert PredecessorsPart.parse_args("--with-origin", w_delete) == (0, EdgeTypes.delete)
    assert PredecessorsPart.parse_args("--with-origin delete", plain) == (0, EdgeTypes.delete)
    assert PredecessorsPart.parse_args("--with-origin delete", w_delete) == (0, EdgeTypes.delete)
    assert PredecessorsPart.parse_args("delete", w_delete) == (1, EdgeTypes.delete)


@pytest.mark.asyncio
async def test_create_query_parts(cli: CLI) -> None:
    commands = await cli.evaluate_cli_command('search some_int==0 | search id=~"9_" | descendants')
    sort = "sort reported.kind asc, reported.name asc, reported.id asc"
    assert len(commands) == 1
    assert len(commands[0].commands) == 2  # list command is added automagically
    assert commands[0].commands[0].name == "execute_search"
    assert (
        commands[0].executable_commands[0].arg
        == f"'(reported.some_int == 0 and reported.id =~ \"9_\") {sort} -default[1:]-> all {sort}'"
    )
    commands = await cli.evaluate_cli_command("search some_int==0 | descendants")
    assert "-default[1:]->" in commands[0].executable_commands[0].arg  # type: ignore
    commands = await cli.evaluate_cli_command("search some_int==0 | ancestors | ancestors")
    assert "<-default[2:]-" in commands[0].executable_commands[0].arg  # type: ignore
    commands = await cli.evaluate_cli_command("search some_int==0 | predecessors | predecessors")
    assert "<-default[2]-" in commands[0].executable_commands[0].arg  # type: ignore
    commands = await cli.evaluate_cli_command("search some_int==0 | successors | successors | successors")
    assert "-default[3]->" in commands[0].executable_commands[0].arg  # type: ignore
    commands = await cli.evaluate_cli_command("search some_int==0 | successors | predecessors")
    assert f"-default-> all {sort} <-default-" in commands[0].executable_commands[0].arg  # type: ignore
    # defining the edge type is supported as well
    commands = await cli.evaluate_cli_command("search some_int==0 | successors delete")
    assert "-delete->" in commands[0].executable_commands[0].arg  # type: ignore
    commands = await cli.evaluate_cli_command("search some_int==0 | predecessors delete")
    assert "<-delete-" in commands[0].executable_commands[0].arg  # type: ignore
    commands = await cli.evaluate_cli_command("search some_int==0 | descendants delete")
    assert "-delete[1:]->" in commands[0].executable_commands[0].arg  # type: ignore
    commands = await cli.evaluate_cli_command("search some_int==0 | ancestors delete")
    assert "<-delete[1:]-" in commands[0].executable_commands[0].arg  # type: ignore
    commands = await cli.evaluate_cli_command("search some_int==0 | aggregate foo, bla as bla: sum(bar) as a")
    assert (
        commands[0].executable_commands[0].arg
        == f"'aggregate(reported.foo, reported.bla as bla: sum(reported.bar) as a):reported.some_int == 0 sort a asc'"
    )

    # multiple head/tail commands are combined correctly
    commands = await cli.evaluate_cli_command("search is(volume) | head -10 | tail -5 | head -3")
    assert commands[0].executable_commands[0].arg == f"'is(\"volume\") {sort} limit 5, 3'"
    commands = await cli.evaluate_cli_command("search is(volume) sort name asc | head -10 | tail -5 | head -3")
    assert commands[0].executable_commands[0].arg == "'is(\"volume\") sort reported.name asc limit 5, 3'"
    commands = await cli.evaluate_cli_command("search is(volume) | head -10 | tail -5 | head -3 | tail 10 | head 100")
    assert commands[0].executable_commands[0].arg == f"'is(\"volume\") {sort} limit 5, 3'"
    commands = await cli.evaluate_cli_command("search is(volume) | tail -10")
    assert (
        commands[0].executable_commands[0].arg
        == f"'is(\"volume\") sort reported.kind desc, reported.name desc, reported.id desc limit 10 reversed '"
    )
    commands = await cli.evaluate_cli_command("search is(volume) sort name | tail -10 | head 5")
    assert commands[0].executable_commands[0].arg == "'is(\"volume\") sort reported.name desc limit 5, 5 reversed '"
    commands = await cli.evaluate_cli_command("search is(volume) sort name | tail -10 | head 5 | head 3 | tail 2")
    assert commands[0].executable_commands[0].arg == "'is(\"volume\") sort reported.name desc limit 7, 2 reversed '"

    pipes = await cli.evaluate_cli_command("history --change node_vulnerable | sort /changed_at asc | limit 0, 10")
    no_pipes = await cli.evaluate_cli_command("history --change node_vulnerable sort /changed_at asc limit 0, 10")
    assert pipes[0].executable_commands[0].arg == no_pipes[0].executable_commands[0].arg


@pytest.mark.asyncio
async def test_replacements(cli: CLI) -> None:
    async def execute(template: str, replace_place_holder: bool = True) -> str:
        result = await cli.evaluate_cli_command(f"echo {template}", replace_place_holder=replace_place_holder)
        return result[0].parsed_commands.commands[0].args  # type: ignore

    # lookup keys are not case-sensitive
    today = utc().date().strftime("%Y-%m-%d")
    assert await execute("@today@ and @TODAY@") == f"{today} and {today}"

    # if the value is not provided, but a function is called
    assert await execute("@no_replacement@") == "@no_replacement@"

    # replacement is not touched if flag is set
    assert await execute("@today@", False) == "@today@"


def test_js_value_at() -> None:
    js = {"foo": {"bla": {"test": 123}}, "b": [{"a": 1, "b": [1, 2, 3]}, {"a": 2, "b": [1, 2, 3]}]}
    assert js_value_at(js, "b[0].a") == 1
    assert js_value_at(js, "b[0].b") == [1, 2, 3]
    assert js_value_at(js, "b[*].a") == [1, 2]
    assert js_value_at(js, "b[*].b[*]") == [[1, 2, 3], [1, 2, 3]]
    assert js_value_at(js, "b[*].b[2]") == [3, 3]
    assert js_value_at(js, "b[1].b[2]") == 3
    js = {"checks": [{"id": "1", "name": "foo"}, {"id": "2", "name": "bar"}]}
    assert js_value_at(js, "checks.id") == ["1", "2"]


def test_escape_character_parsing() -> None:
    def assert_command(to_parse: str, cmd: str, arg: str) -> None:
        parsed = multi_command_parser.parse(to_parse)
        assert len(parsed) == 1
        assert len(parsed[0].commands) == 1
        first = parsed[0].commands[0]
        assert first.cmd == cmd
        assert first.args == arg

    assert_command("echo 'f\\boo'", "echo", "'f\boo'")  # <bs>b --> \b
    assert_command("echo 'f\\noo'", "echo", "'f\noo'")  # <bs>n --> \n
    assert_command("echo 'f\\\\oo'", "echo", "'f\\\\oo'")  # <bs><bs> --> <bs><bs>
    assert_command("echo 'f\\u00a7oo'", "echo", "'f§oo'")  # <bs>unicode_number --> character
    assert_command("echo 'f\\\"oo'", "echo", "'f\\\"oo'")  # <bs>" --> <bs>"
    assert_command("echo 'f\\'oo'", "echo", "'f\\'oo'")  # <bs>' --> <bs>'


def test_get_kwargs() -> None:
    ec = ExecutableCommand(None, None, None, None)  # type: ignore
    d = {"a": 1, "b": "str", "previous_command": ec}
    assert CLICommand.get_previous_command(d) == ec
    assert CLICommand.get_from("a", int, d) == 1
    assert CLICommand.get_from("a", str, d) is None
    assert CLICommand.get_from("c", str, d) is None
