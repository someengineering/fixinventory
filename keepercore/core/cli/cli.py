from __future__ import annotations
import asyncio
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Union, Callable, TypeVar, Any, Coroutine, List, AsyncGenerator, Tuple, Dict

from aiostream import stream
from aiostream.core import Stream
from parsy import Parser

from core.db.db_access import DbAccess
from core.error import CLIParseError
from core.event_bus import EventBus
from core.model.model_handler import ModelHandler
from core.parse_util import make_parser, literal_dp, equals_dp, value_dp, space_dp
from core.types import JsonElement
from core.util import identity, split_esc

T = TypeVar("T")
# Allow the function to return either a coroutine or the result directly
Result = Union[T, Coroutine[Any, Any, T]]
# A flow function receives a t
# When a t is returned, it will be passed to the next function
# If None is returned, the value is discarded
FlowFunction = Callable[[T], Result[Optional[T]]]
# A source provides a stream of objects
Source = AsyncGenerator[JsonElement, None]
# Every Command will return a function that takes a stream and returns a stream of objects.
Flow = Callable[[Stream], AsyncGenerator[JsonElement, None]]
# A sink function takes a stream and creates a result
Sink = Callable[[Stream], Coroutine[Any, Any, T]]


@dataclass(frozen=True)
class CLIDependencies:
    event_bus: EventBus
    db_access: DbAccess
    model_handler: ModelHandler


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

    async def parse(self, arg: Optional[str], **env: str) -> Union[Source, Flow, Sink[Any]]:
        pass


class CLISource(CLIPart):
    """
    Subclasses of CLISource can create a stream.
    """

    @abstractmethod
    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        pass

    @staticmethod
    async def empty() -> Source:
        for _ in range(0, 0):
            yield {}


class CLICommand(CLIPart, ABC):
    """
    Subclasses of CLICommand can transform the incoming stream into another stream and
    eventually performing a side effect.

    Simple CLICommands can simply override the process_single method.
    If a CLICommand wants to interact with the stream directly, tbe parse method has to be overridden.
    """

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        single_function = await self.process_single(arg)
        return self.flow_from_function(single_function)

    async def process_single(self, arg: Optional[str] = None) -> FlowFunction[JsonElement]:
        return identity

    @staticmethod
    def flow_from_function(fn: FlowFunction[JsonElement]) -> Flow:
        def process(content: Stream) -> AsyncGenerator[JsonElement, None]:
            return stream.filter(stream.map(content, fn), lambda x: x is not None)  # type: ignore

        return process


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


class HelpCommand(CLISource):
    """
    Usage: help [command]

    Parameter:
        command [optional]: if given shows the help for a specific command

    Show help text for a command or general help information.
    """

    def __init__(self, dependencies: CLIDependencies, parts: List[CLIPart]):
        super().__init__(dependencies)
        self.parts: Dict[str, CLIPart] = {p.name: p for p in parts + [self]}

    @property
    def name(self) -> str:
        return "help"

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        if not arg:
            available = "\n".join(
                f" -{cmd}" for cmd, part in self.parts.items() if isinstance(part, (CLISource, CLICommand))
            )
            result = (
                f"{self.help()}\n\nAvailable Commands:\n{available}\n\n"
                f"Note that you can pipe commands using the pipe character (|)\n"
                f"and chain multiple commands using the semicolon (;)."
            )
        elif arg and arg in self.parts:
            cmd = self.parts[arg]
            result = cmd.help()
        else:
            result = f"No command found with this name: {arg}"

        return stream.just(result)  # type: ignore


@dataclass
class ParsedCommandLine:
    """
    The parsed command line holds:
    - env: the resulting environment coming from the parsed environment + the provided environment
    - parts: all parts this command is defined from
    - generator: this generator can be used in order to execute the command line
    """

    env: JsonElement
    parts: List[CLIPart]
    generator: AsyncGenerator[JsonElement, None]

    async def to_sink(self, sink: Sink[T]) -> T:
        return await sink(self.generator)


@make_parser
def key_value_parser() -> Parser:
    key = yield literal_dp
    yield equals_dp
    value = yield value_dp
    return key, value


key_values_parser: Parser = key_value_parser.sep_by(space_dp).map(dict)


class CLI:
    """
    The CLI has a defined set of dependencies and knows a list if commands.
    A string can parsed into a command line that can be executed based on the list of available commands.
    """

    def __init__(self, dependencies: CLIDependencies, parts: List[CLIPart], env: Dict[str, Any]):
        help_cmd = HelpCommand(dependencies, parts)
        self.parts = {p.name: p for p in parts + [help_cmd]}
        self.cli_env = env

    async def evaluate_cli_command(self, cli_input: str, **env: str) -> List[ParsedCommandLine]:
        def parse_single_command(index: int, command: str) -> Tuple[CLIPart, str]:
            expected = CLISource if index == 0 else CLICommand
            p = command.strip().split(" ", 1)
            part_str, args_str = (p[0], p[1]) if len(p) == 2 else (p[0], "")
            if part_str in self.parts:
                part: CLIPart = self.parts[part_str]
                if isinstance(part, expected):
                    return part, args_str
                else:
                    detail = "no source data given" if index == 0 else "must be the first command"
                    raise CLIParseError(f"Command >{part_str}< can not be used in this position: {detail}")
            else:
                raise CLIParseError(f"Command >{part_str}< is not known. typo?")

        async def parse_arg(part: CLIPart, args_str: str, **resulting_env: str) -> Any:
            try:
                fn = part.parse(args_str, **resulting_env)
                return await fn if asyncio.iscoroutine(fn) else fn
            except Exception as ex:
                kind = type(ex).__name__
                raise CLIParseError(f"{part.name}: can not parse: {args_str}: {kind}: {str(ex)}") from ex

        async def parse_line(line: str) -> ParsedCommandLine:
            parsed_env, rest = key_values_parser.parse_partial(line)
            resulting_env = self.cli_env | env | parsed_env
            parts_with_args = [parse_single_command(idx, cmd) for idx, cmd in enumerate(split_esc(rest, "|"))]
            parts = [part for part, _ in parts_with_args]
            if parts_with_args:
                source, source_arg = parts_with_args[0]
                flow = await parse_arg(source, source_arg, **resulting_env)
                flow = flow if isinstance(flow, Stream) else stream.iterate(flow)
                for command, arg in parts_with_args[1:]:
                    flow_fn: Flow = await parse_arg(command, arg, **resulting_env)
                    flow = flow_fn(flow)
                    flow = flow if isinstance(flow, Stream) else stream.iterate(flow)
                return ParsedCommandLine(resulting_env, parts, flow)
            else:
                return ParsedCommandLine(resulting_env, [], CLISource.empty())

        return [await parse_line(cmd_line) for cmd_line in split_esc(cli_input, ";")]

    async def execute_cli_command(self, cli_input: str, sink: Sink[T], **env: str) -> List[T]:
        return [await parsed.to_sink(sink) for parsed in await self.evaluate_cli_command(cli_input, **env)]
