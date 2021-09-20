from __future__ import annotations

import asyncio
import calendar
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timedelta
from functools import reduce
from itertools import takewhile
from typing import Optional, Union, Callable, TypeVar, Any, Coroutine, AsyncGenerator

from aiostream import stream
from aiostream.core import Stream
from parsy import Parser

from core.db.db_access import DbAccess
from core.error import CLIParseError
from core.event_bus import EventBus
from core.model.graph_access import EdgeType, Section
from core.model.model_handler import ModelHandler
from core.model.typed_model import class_fqn
from core.parse_util import make_parser, literal_dp, equals_dp, json_value_dp, space_dp
from core.query.model import Query, Navigation, AllTerm, Aggregate
from core.query.query_parser import term_parser, aggregate_parameter_parser
from core.task.job_handler import JobHandler
from core.types import JsonElement
from core.util import split_esc, utc_str, utc, from_utc
from core.worker_task_queue import WorkerTaskQueue

try:
    # noinspection PyUnresolvedReferences
    from tzlocal import get_localzone
except ImportError:
    pass


T = TypeVar("T")
# Allow the function to return either a coroutine or the result directly
Result = Union[T, Coroutine[Any, Any, T]]
JsGen = Union[Stream, AsyncGenerator[JsonElement, None]]
# A source provides a stream of objects
Source = JsGen
# Every Command will return a function that transforms a JsGen to another JsGen
Flow = Callable[[JsGen], JsGen]
# A sink function takes a stream and creates a result
Sink = Callable[[JsGen], Coroutine[Any, Any, T]]


class CLIDependencies:
    def __init__(self) -> None:
        self.lookup: dict[str, Any] = {}

    @property
    def event_bus(self) -> EventBus:
        return self.lookup["event_bus"]  # type:ignore

    @property
    def db_access(self) -> DbAccess:
        return self.lookup["db_access"]  # type:ignore

    @property
    def model_handler(self) -> ModelHandler:
        return self.lookup["model_handler"]  # type:ignore

    @property
    def job_handler(self) -> JobHandler:
        return self.lookup["job_handler"]  # type:ignore

    @property
    def worker_task_queue(self) -> WorkerTaskQueue:
        return self.lookup["worker_task_queue"]  # type:ignore


class CLIPart(ABC):
    """
    The CLIPart is the base for all participants of the cli execution.
    Source: generates a stream of objects
    Flow: transforms the elements in a stream of objects
    Sink: takes a stream of objects and creates a result
    """

    def __init__(self, dependencies: CLIDependencies):
        self.dependencies = dependencies

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def help(self) -> str:
        # if not defined in subclass, fallback to inline doc
        doc = inspect.getdoc(type(self))
        return doc if doc else f"{self.name}: no help available."

    @abstractmethod
    def info(self) -> str:
        pass


class CLISource(CLIPart, ABC):
    """
    Subclasses of CLISource can create a stream.
    """

    @abstractmethod
    async def parse(self, arg: Optional[str] = None, **env: str) -> Result[Source]:
        yield None  # only here for mypy: it detects a coroutine otherwise

    @staticmethod
    async def empty() -> Source:
        for _ in range(0, 0):
            yield {}


class QueryPart(CLISource, ABC):
    async def parse(self, arg: Optional[str] = None, **env: str) -> Result[Source]:
        async for a in self.empty():
            yield a


class CLICommand(CLIPart, ABC):
    """
    Subclasses of CLICommand can transform the incoming stream into another stream and
    eventually performing a side effect.

    Simple CLICommands can simply override the process_single method.
    If a CLICommand wants to interact with the stream directly, tbe parse method has to be overridden.
    """

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        pass


class CLISink(CLIPart):
    """
    Subclasses of a sink transform the incoming stream into a result.
    Most useful sinks:
    - ConsoleSink: prints to stdout and returns None
    - ListSink: collects all elements and returns the final list
    """

    @abstractmethod
    async def parse(self, arg: Optional[str] = None, **env: str) -> Sink[Any]:
        pass


class ReportedPart(QueryPart):
    """
    Usage: reported <property.path> <op> <value"

    Part of a query.
    The reported section contains the values directly from the collector.
    With this command you can query this section for a matching property.
    The property is the complete path in the json structure.
    Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
    value is a json encoded value to match.

    Example:
        reported prop1 == "a"             # matches documents with reported section like { "prop1": "a" ....}
        reported some.nested in [1,2,3]   # matches documents with reported section like { "some": { "nested" : 1 ..}..}
        reported array[*] == 2            # matches documents with reported section like { "array": [1, 2, 3] ... }
        reported array[1] == 2            # matches documents with reported section like { "array": [1, 2, 3] ... }

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return Section.reported

    def info(self) -> str:
        return "Matches a property in the reported section."


class DesiredPart(QueryPart):
    """
    Usage: desired <property.path> <op> <value"

    Part of a query.
    The desired section contains values set by tools to change the state of this node.
    With this command you can query this section for a matching property.
    The property is the complete path in the json structure.
    Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
    value is a json encoded value to match.

    Example:
        desired prop1 == "a"             # matches documents with desired section like { "prop1": "a" ....}
        desired prop1 =~ "a.*"           # matches documents with desired section like { "prop1": "a" ....}
        desired some.nested in [1,2,3]   # matches documents with desired section like { "some": { "nested" : 1 ..}..}
        desired array[*] == 2            # matches documents with desired section like { "array": [1, 2, 3] ... }
        desired array[1] == 2            # matches documents with desired section like { "array": [1, 2, 3] ... }

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return Section.desired

    def info(self) -> str:
        return "Matches a property in the desired section."


class MetadataPart(QueryPart):
    """
    Usage: metadata <property.path> <op> <value"

    Part of a query.
    The metadata section is set by the collector and holds additional meta information about this node.
    With this command you can query this section for a matching property.
    The property is the complete path in the json structure.
    Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
    value is a json encoded value to match.

    Example:
        metadata prop1 == "a"             # matches documents with metadata section like { "prop1": "a" ....}
        metadata prop1 =~ "a.*"           # matches documents with metadata section like { "prop1": "a" ....}
        metadata some.nested in [1,2,3]   # matches documents with metadata section like { "some": { "nested" : 1 ..}..}
        metadata array[*] == 2            # matches documents with metadata section like { "array": [1, 2, 3] ... }
        metadata array[1] == 2            # matches documents with metadata section like { "array": [1, 2, 3] ... }

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return Section.metadata

    def info(self) -> str:
        return "Matches a property in the metadata section."


class Predecessor(QueryPart):
    """
    Usage: predecessors [edge_type]

    Part of a query.
    Select all predecessors of this node in the graph.
    The graph may contain different types of edges (e.g. the delete graph or the dependency graph).
    In order to define which graph to walk, the edge_type can be specified.

    Parameter:
        edge_type [Optional, defaults to dependency]: This argument defines which edge type to use.

    Example:
        metadata prop1 == "a" | predecessors | match prop2 == "b"

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "predecessors"

    def info(self) -> str:
        return "Select all predecessors of this node in the graph."


class Successor(QueryPart):
    """
    Usage: successors [edge_type]

    Part of a query.
    Select all successors of this node in the graph.
    The graph may contain different types of edges (e.g. the delete graph or the dependency graph).
    In order to define which graph to walk, the edge_type can be specified.

    Parameter:
        edge_type [Optional, defaults to dependency]: This argument defines which edge type to use.

    Example:
        metadata prop1 == "a" | successors | match prop2 == "b"

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "successors"

    def info(self) -> str:
        return "Select all successor of this node in the graph."


class Ancestor(QueryPart):
    """
    Usage: ancestors [edge_type]

    Part of a query.
    Select all ancestors of this node in the graph.
    The graph may contain different types of edges (e.g. the delete graph or the dependency graph).
    In order to define which graph to walk, the edge_type can be specified.

    Parameter:
        edge_type [Optional, defaults to dependency]: This argument defines which edge type to use.

    Example:
        metadata prop1 == "a" | ancestors | match prop2 == "b"

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "ancestors"

    def info(self) -> str:
        return "Select all ancestors of this node in the graph."


class Descendant(QueryPart):
    """
    Usage: descendants [edge_type]

    Part of a query.
    Select all descendants of this node in the graph.
    The graph may contain different types of edges (e.g. the delete graph or the dependency graph).
    In order to define which graph to walk, the edge_type can be specified.

    Parameter:
        edge_type [Optional, defaults to dependency]: This argument defines which edge type to use.

    Example:
        metadata prop1 == "a" | descendants | match prop2 == "b"

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "descendants"

    def info(self) -> str:
        return "Select all descendants of this node in the graph."


class AggregatePart(QueryPart):
    """
    Usage: aggregate [group_prop, .., group_prop]: [function(), .. , function()]

    Part of a query.
    Using the results of a query by aggregating over properties of this result
    by aggregating over given properties and applying given aggregation functions.

    Parameter:
        group_prop: the name of the property to use for grouping. Multiple grouping variables are possible.
                    Every grouping variable can be renamed via an as name directive. (prop as prop_name)
        function(): grouping function to be applied on every resulting node.
                    Following functions are possible: sum, count, min, max, avg
                    The function contains the variable name (e.g.: min(path.to.prop))
                    It is possible to use static values (e.g.: sum(1))
                    It is possible to use simple math expressions in the function (e.g. min(path.to.prop * 3 + 2))
                    It is possible to name the result of this function (e.g. count(foo) as number_of_foos)

    Example:
        aggregate reported.kind as kind, reported.cloud.name as cloud, reported.region.name as region : sum(1) as count
            [
                { "count": 228, "group": { "cloud": "aws", "kind": "aws_ec2_instance", "region": "us-east-1" }},
                { "count": 326, "group": { "cloud": "gcp", "kind": "gcp_instance", "region": "us-west1" }},
                .
                .
            ]
        aggregate reported.instance_status as status: sum(reported.cores) as cores, sum(reported.memory) as mem
            [
                { "cores": 116, "mem": 64 , "group": { "status": "busy" }},
                { "cores": 2520, "mem": 9824, "group": { "status": "running" }},
                { "cores": 257, "mem": 973, "group": { "status": "stopped" }},
                { "cores": 361, "mem": 1441, "group": { "status": "terminated" }},
            ]

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "aggregate"

    def info(self) -> str:
        return "Aggregate this query by the provided specification"


class MergeAncestorsPart(QueryPart):
    """
    Usage: merge_ancestors [kind, kind as name, ..., kind]

    For all query results, merge the nodes with ancestor nodes of given kind.
    Multiple ancestors can be provided.
    Note: the first defined ancestor kind is used to stop the search of all other kinds.
          This should be taken into consideration when the list of ancestor kinds is defined!
    The resulting reported content of the ancestor node is merged into the current reported node
    with the kind name or the alias.

    Parameter:
        kind [Mandatory] [as name]: search the ancestors of this node for a node of define kind.
                                    Merge the result into the current node either under the kind name or the alias name.

    Example:
        compute_instance: the graph os traversed starting with the current node in direction to the root.
                          When a node is found, which is of type compute_instance, the reported content of this node
                          is merged with the reported content of the compute_instance node:
                          { "id": "xyz", "reported": { "kind": "ebs", "compute_instance": { props from compute_instance}
        compute_instance as ci:
                          { "id": "xyz", "reported": { "kind": "ebs", "ci": { props from compute_instance}


    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "merge_ancestors"

    def info(self) -> str:
        return "Merge the results of this query with the content of ancestor nodes of given type"


class HelpCommand(CLISource):
    """
    Usage: help [command]

    Parameter:
        command [optional]: if given shows the help for a specific command

    Show help text for a command or general help information.
    """

    def __init__(self, dependencies: CLIDependencies, parts: list[CLIPart], aliases: dict[str, str]):
        super().__init__(dependencies)
        self.parts = {p.name: p for p in parts + [self]}
        self.aliases = {a: n for a, n in aliases.items() if n in self.parts and a not in self.parts}

    @property
    def name(self) -> str:
        return "help"

    def info(self) -> str:
        return "Shows available commands, as well as help for any specific command."

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        if not arg:
            all_parts = sorted(self.parts.values(), key=lambda p: p.name)
            parts = (p for p in all_parts if isinstance(p, (CLISource, CLICommand)))
            available = "\n".join(f"   {part.name} - {part.info()}" for part in parts)
            aliases = "\n".join(f"   {alias} ({cmd}) - {self.parts[cmd].info()}" for alias, cmd in self.aliases.items())
            replacements = "\n".join(f"   @{key}@ -> {value}" for key, value in CLI.replacements().items())
            result = (
                f"\nkeepercore CLI\n\n\n"
                f"Valid placeholder string:\n{replacements}\n\n"
                f"Available Commands:\n{available}\n\n"
                f"Available Aliases:\n{aliases}\n\n"
                f"Note that you can pipe commands using the pipe character (|)\n"
                f"and chain multiple commands using the semicolon (;)."
            )
        elif arg and arg in self.parts:
            cmd = self.parts[arg]
            result = f"{cmd.name} - {cmd.info()}\n\n{cmd.help()}"
        else:
            result = f"No command found with this name: {arg}"

        return stream.just(result)


@dataclass
class ParsedCommandLine:
    """
    The parsed command line holds:
    - env: the resulting environment coming from the parsed environment + the provided environment
    - parts: all parts this command is defined from
    - generator: this generator can be used in order to execute the command line
    """

    env: JsonElement
    parts_with_args: list[tuple[CLIPart, str]]
    generator: AsyncGenerator[JsonElement, None]

    async def to_sink(self, sink: Sink[T]) -> T:
        return await sink(self.generator)

    @property
    def parts(self) -> list[CLIPart]:
        return [part for part, _ in self.parts_with_args]


@make_parser
def key_value_parser() -> Parser:
    key = yield literal_dp
    yield equals_dp
    value = yield json_value_dp
    return key, value


key_values_parser: Parser = key_value_parser.sep_by(space_dp).map(dict)
CLIArg = tuple[CLIPart, str]


class CLI:
    """
    The CLI has a defined set of dependencies and knows a list if commands.
    A string can parsed into a command line that can be executed based on the list of available commands.
    """

    def __init__(
        self, dependencies: CLIDependencies, parts: list[CLIPart], env: dict[str, Any], aliases: dict[str, str]
    ):
        help_cmd = HelpCommand(dependencies, parts, aliases)
        cmds = {p.name: p for p in parts + [help_cmd]}
        alias_cmds = {alias: cmds[name] for alias, name in aliases.items() if name in cmds and alias not in cmds}
        self.parts = cmds | alias_cmds
        self.cli_env = env
        self.dependencies = dependencies
        self.aliases = aliases

    @staticmethod
    def create_query(parts: list[tuple[QueryPart, str]]) -> str:
        query: Query = Query.by(AllTerm())
        for part, arg_in in parts:
            arg = arg_in.strip()
            if isinstance(part, ReportedPart):
                query = query.filter(term_parser.parse(arg).on_section(Section.reported))
            elif isinstance(part, DesiredPart):
                query = query.filter(term_parser.parse(arg).on_section(Section.desired))
            elif isinstance(part, MetadataPart):
                query = query.filter(term_parser.parse(arg).on_section(Section.metadata))
            elif isinstance(part, Predecessor):
                query = query.traverse_in(1, 1, arg if arg else EdgeType.default)
            elif isinstance(part, Successor):
                query = query.traverse_out(1, 1, arg if arg else EdgeType.default)
            elif isinstance(part, Ancestor):
                query = query.traverse_in(1, Navigation.Max, arg if arg else EdgeType.default)
            elif isinstance(part, Descendant):
                query = query.traverse_out(1, Navigation.Max, arg if arg else EdgeType.default)
            elif isinstance(part, AggregatePart):
                group_vars, group_function_vars = aggregate_parameter_parser.parse(arg)
                query = Query(query.parts, query.preamble, Aggregate(group_vars, group_function_vars))
            elif isinstance(part, MergeAncestorsPart):
                query = Query(query.parts, query.preamble | {"merge_with_ancestors": arg}, query.aggregate)
            else:
                raise AttributeError(f"Do not understand: {part} of type: {class_fqn(part)}")
        return str(query.simplify())

    async def evaluate_cli_command(
        self, cli_input: str, replace_place_holder: bool = True, **env: str
    ) -> list[ParsedCommandLine]:
        def parse_single_command(command: str) -> tuple[CLIPart, str]:
            p = command.strip().split(" ", 1)
            part_str, args_str = (p[0], p[1]) if len(p) == 2 else (p[0], "")
            if part_str in self.parts:
                part: CLIPart = self.parts[part_str]
                return part, args_str
            else:
                raise CLIParseError(f"Command >{part_str}< is not known. typo?")

        def combine_single_command(commands: list[CLIArg]) -> list[CLIArg]:
            parts = list(takewhile(lambda x: isinstance(x[0], QueryPart), commands))
            query = self.create_query(parts)  # type: ignore

            # fmt: off
            result = [(self.parts["query"], query), *commands[len(parts):]] if parts else commands
            # fmt: on
            for index, part_num in enumerate(result):
                part, _ = part_num
                expected = CLICommand if index else CLISource
                if not isinstance(part, expected):
                    detail = "no source data given" if index == 0 else "must be the first command"
                    raise CLIParseError(f"Command >{part.name}< can not be used in this position: {detail}")
            return result

        async def parse_arg(part: Any, args_str: str, **resulting_env: str) -> Any:
            try:
                fn = part.parse(args_str, **resulting_env)
                return await fn if asyncio.iscoroutine(fn) else fn
            except Exception as ex:
                kind = type(ex).__name__
                raise CLIParseError(f"{part.name}: can not parse: {args_str}: {kind}: {str(ex)}") from ex

        async def parse_line(line: str) -> ParsedCommandLine:
            def make_stream(in_stream: Union[Stream, AsyncGenerator[JsonElement, None]]) -> Stream:
                return in_stream if isinstance(in_stream, Stream) else stream.iterate(in_stream)

            parsed_env, rest = key_values_parser.parse_partial(line)
            resulting_env = self.cli_env | env | parsed_env
            parts_with_args = combine_single_command([parse_single_command(cmd) for cmd in split_esc(rest, "|")])

            if parts_with_args:
                source, source_arg = parts_with_args[0]
                flow = make_stream(await parse_arg(source, source_arg, **resulting_env))
                for command, arg in parts_with_args[1:]:
                    flow_fn: Flow = await parse_arg(command, arg, **resulting_env)
                    # noinspection PyTypeChecker
                    flow = make_stream(flow_fn(flow))
                # noinspection PyTypeChecker
                return ParsedCommandLine(resulting_env, parts_with_args, flow)
            else:
                return ParsedCommandLine(resulting_env, [], CLISource.empty())

        replaced = self.replace_placeholder(cli_input, **env)
        first = await parse_line(split_esc(replaced, ";")[0])
        keep_raw = not replace_place_holder or (first.parts and first.parts[0].name == "add_job")
        data = cli_input if keep_raw else replaced
        return [await parse_line(cmd_line) for cmd_line in split_esc(data, ";")]

    async def execute_cli_command(self, cli_input: str, sink: Sink[T], **env: str) -> list[Any]:
        return [await parsed.to_sink(sink) for parsed in await self.evaluate_cli_command(cli_input, True, **env)]

    @staticmethod
    def replacements(**env: str) -> dict[str, str]:
        now_string = env.get("now")
        ut = from_utc(now_string) if now_string else utc()
        t = ut.date()
        try:
            n = get_localzone().localize(ut)
        except Exception:
            n = ut
        return {
            "UTC": utc_str(ut),
            "NOW": utc_str(n),
            "TODAY": t.strftime("%Y-%m-%d"),
            "TOMORROW": (t + timedelta(days=1)).isoformat(),
            "YESTERDAY": (t + timedelta(days=-1)).isoformat(),
            "YEAR": t.strftime("%Y"),
            "MONTH": t.strftime("%m"),
            "DAY": t.strftime("%d"),
            "TIME": n.strftime("%H:%M:%S"),
            "HOUR": n.strftime("%H"),
            "MINUTE": n.strftime("%M"),
            "SECOND": n.strftime("%S"),
            "TZ_OFFSET": n.strftime("%z"),
            "TZ": n.strftime("%Z"),
            "MONDAY": (t + timedelta((calendar.MONDAY - t.weekday()) % 7)).isoformat(),
            "TUESDAY": (t + timedelta((calendar.TUESDAY - t.weekday()) % 7)).isoformat(),
            "WEDNESDAY": (t + timedelta((calendar.WEDNESDAY - t.weekday()) % 7)).isoformat(),
            "THURSDAY": (t + timedelta((calendar.THURSDAY - t.weekday()) % 7)).isoformat(),
            "FRIDAY": (t + timedelta((calendar.FRIDAY - t.weekday()) % 7)).isoformat(),
            "SATURDAY": (t + timedelta((calendar.SATURDAY - t.weekday()) % 7)).isoformat(),
            "SUNDAY": (t + timedelta((calendar.SUNDAY - t.weekday()) % 7)).isoformat(),
        }

    @staticmethod
    def replace_placeholder(cli_input: str, **env: str) -> str:
        return reduce(lambda res, kv: res.replace(f"@{kv[0]}@", kv[1]), CLI.replacements(**env).items(), cli_input)
