from __future__ import annotations

import inspect
import json
from abc import ABC, abstractmethod
from argparse import Namespace
from asyncio import Queue, Task, iscoroutine
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Any, Dict, Tuple, Callable, Union, Awaitable, Type, cast

from aiohttp import ClientSession, TCPConnector
from aiostream import stream
from aiostream.core import Stream
from rich.jupyter import JupyterMixin
from parsy import test_char, string

from core.analytics import AnalyticsEventSender
from core.cli import JsGen, T, Sink
from core.db.db_access import DbAccess
from core.error import CLIParseError
from core.console_renderer import ConsoleRenderer
from core.message_bus import MessageBus
from core.parse_util import l_curly_dp, r_curly_dp
from core.model.model_handler import ModelHandler
from core.query.model import Query, variable_to_absolute, PathRoot
from core.query.template_expander import TemplateExpander
from core.task.job_handler import JobHandler
from core.types import Json, JsonElement
from core.util import AccessJson
from core.worker_task_queue import WorkerTaskQueue


class MediaType(Enum):
    Json = 1
    FilePath = 2

    @property
    def json(self) -> bool:
        return self == MediaType.Json

    @property
    def file_path(self) -> bool:
        return self == MediaType.FilePath

    def __repr__(self) -> str:
        return "application/json" if self == MediaType.Json else "application/octet-stream"


no_closing_p = test_char(lambda x: x != "}", "No closing bracket").at_least(1).concat()
no_bracket_p = test_char(lambda x: x not in ("{", "}"), "No opening bracket").at_least(1).concat()
double_curly_open_dp = string("{{")
double_curly_close_dp = string("}}")
l_or_r_curly_dp = string("{") | string("}")


@dataclass(frozen=True)
class CLIContext:
    env: Dict[str, str] = field(default_factory=dict)
    uploaded_files: Dict[str, str] = field(default_factory=dict)  # id -> path
    query: Optional[Query] = None
    query_options: Dict[str, Any] = field(default_factory=dict)
    console_formatter: Optional[ConsoleRenderer] = None

    def variable_in_section(self, variable: str) -> str:
        # if there is no query, always assume the root section
        section = self.env.get("section") if self.query else PathRoot
        return variable_to_absolute(section, variable)

    def render_console(self, element: Union[str, JupyterMixin]) -> str:
        if self.console_formatter:
            return self.console_formatter.render(element)
        elif isinstance(element, JupyterMixin):
            return str(element)
        else:
            return element

    def formatter(self, format_string: str) -> Callable[[Any], str]:
        """
        A renderer can be used to string format objects based on a provided format string.
        """

        def format_variable(name: str) -> str:
            assert "__" not in name, "No dunder attributes allowed"
            return "{" + self.variable_in_section(name) + "}"

        def render_simple_property(prop: Any) -> str:
            return json.dumps(prop) if isinstance(prop, bool) else str(prop)

        variable = (l_curly_dp >> no_closing_p << r_curly_dp).map(format_variable)
        token = double_curly_open_dp | double_curly_close_dp | no_bracket_p | variable | l_or_r_curly_dp
        format_string_parser = token.many().concat()
        formatter: str = format_string_parser.parse(format_string)

        def format_object(obj: Any) -> str:
            return formatter.format_map(AccessJson.wrap(obj, "null", render_simple_property))

        return format_object


EmptyContext = CLIContext()


class CLIEngine(ABC):
    @abstractmethod
    async def evaluate_cli_command(
        self,
        cli_input: str,
        context: CLIContext = EmptyContext,
        replace_place_holder: bool = True,
    ) -> List[ParsedCommandLine]:
        pass


class CLIDependencies:
    def __init__(self, **deps: Any) -> None:
        self.lookup: Dict[str, Any] = deps

    def extend(self, **deps: Any) -> CLIDependencies:
        self.lookup = {**self.lookup, **deps}
        return self

    @property
    def args(self) -> Namespace:
        return self.lookup["args"]  # type: ignore

    @property
    def message_bus(self) -> MessageBus:
        return self.lookup["message_bus"]  # type:ignore

    @property
    def event_sender(self) -> AnalyticsEventSender:
        return self.lookup["event_sender"]  # type:ignore

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

    @property
    def template_expander(self) -> TemplateExpander:
        return self.lookup["template_expander"]  # type:ignore

    @property
    def forked_tasks(self) -> Queue[Tuple[Task[JsonElement], str]]:
        return self.lookup["forked_tasks"]  # type:ignore

    @property
    def cli(self) -> CLIEngine:
        return self.lookup["cli"]  # type:ignore

    @property
    def http_session(self) -> ClientSession:
        session: Optional[ClientSession] = self.lookup.get("http_session")
        if not session:
            connector = TCPConnector(limit=0, ssl=False, ttl_dns_cache=300)
            session = ClientSession(connector=connector)
            self.lookup["http_session"] = session
        return session

    async def stop(self) -> None:
        if "http_session" in self.lookup:
            await self.http_session.close()


@dataclass
class CLICommandRequirement:
    name: str


@dataclass
class CLIFileRequirement(CLICommandRequirement):
    path: str  # local client path


class CLIAction(ABC):
    def __init__(self, produces: MediaType, requires: Optional[List[CLICommandRequirement]]) -> None:
        self.produces = produces
        self.required = requires if requires else []

    @staticmethod
    def make_stream(in_stream: JsGen) -> Stream:
        return in_stream if isinstance(in_stream, Stream) else stream.iterate(in_stream)


class CLISource(CLIAction):
    def __init__(
        self,
        fn: Callable[[], Union[Tuple[Optional[int], JsGen], Awaitable[Tuple[Optional[int], JsGen]]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
    ) -> None:
        super().__init__(produces, requires)
        self._fn = fn

    async def source(self) -> Tuple[Optional[int], Stream]:
        res = self._fn()
        count, gen = await res if iscoroutine(res) else res
        return count, self.make_stream(await gen if iscoroutine(gen) else gen)

    @staticmethod
    def with_count(
        fn: Callable[[], Union[JsGen, Awaitable[JsGen]]],
        count: Optional[int],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
    ) -> CLISource:
        async def combine() -> Tuple[Optional[int], JsGen]:
            res = fn()
            gen = await res if iscoroutine(res) else res
            return count, gen

        return CLISource(combine, produces, requires)

    @staticmethod
    def single(
        fn: Callable[[], Union[JsGen, Awaitable[JsGen]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
    ) -> CLISource:
        return CLISource.with_count(fn, 1, produces, requires)

    @staticmethod
    def empty() -> CLISource:
        return CLISource.with_count(stream.empty, 0)


class CLIFlow(CLIAction):
    def __init__(
        self,
        fn: Callable[[JsGen], Union[JsGen, Awaitable[JsGen]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
    ) -> None:
        super().__init__(produces, requires)
        self._fn = fn

    async def flow(self, in_stream: JsGen) -> Stream:
        gen = self._fn(self.make_stream(in_stream))
        return self.make_stream(await gen if iscoroutine(gen) else gen)


class CLICommand(ABC):
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

    def rendered_help(self, ctx: CLIContext) -> str:
        text = f"\n**{self.name}: {self.info()}**\n\n{self.help()}"
        return ctx.render_console(text)

    @abstractmethod
    def info(self) -> str:
        pass

    @abstractmethod
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        pass


class InternalPart(ABC):
    """
    Internal parts can be executed but are not shown via help.
    They usually get injected by the CLI Interpreter to ease usability.
    """


class OutputTransformer(ABC):
    """
    Mark all commands that transform the output stream (formatting).
    """


class PreserveOutputFormat(ABC):
    """
    Mark all commands where the output should not be flattened to default line output.
    """


@dataclass
class ParsedCommand:
    cmd: str
    args: Optional[str] = None


@dataclass
class ParsedCommands:
    commands: List[ParsedCommand]
    env: Json = field(default_factory=dict)


@dataclass
class ExecutableCommand:
    name: str  # the name of the command or alias
    command: CLICommand
    arg: Optional[str]
    action: CLIAction


@dataclass
class ParsedCommandLine:
    """
    The parsed command line holds:
    - ctx: the resulting environment coming from the parsed environment + the provided environment
    - commands: all commands this command is defined from
    - generator: this generator can be used in order to execute the command line
    """

    ctx: CLIContext
    parsed_commands: ParsedCommands
    executable_commands: List[ExecutableCommand]
    unmet_requirements: List[CLICommandRequirement]

    def __post_init__(self) -> None:
        def expect_action(cmd: ExecutableCommand, expected: Type[T]) -> T:
            action = cmd.action
            if isinstance(action, expected):
                return action
            else:
                message = "must be the first command" if issubclass(type(action), CLISource) else "no source data given"
                raise CLIParseError(f"Command >{cmd.command.name}< can not be used in this position: {message}")

        if self.executable_commands:
            expect_action(self.executable_commands[0], CLISource)
            for command in self.executable_commands[1:]:
                expect_action(command, CLIFlow)

    async def to_sink(self, sink: Sink[T]) -> T:
        _, generator = await self.execute()
        return await sink(generator)

    @property
    def commands(self) -> List[CLICommand]:
        return [part.command for part in self.executable_commands]

    @property
    def produces(self) -> MediaType:
        # the last command in the chain defines the resulting media type
        return self.executable_commands[-1].action.produces if self.executable_commands else MediaType.Json

    async def execute(self) -> Tuple[Optional[int], Stream]:
        if self.executable_commands:
            source_action = cast(CLISource, self.executable_commands[0].action)
            count, flow = await source_action.source()
            for command in self.executable_commands[1:]:
                flow_action = cast(CLIFlow, command.action)
                flow = await flow_action.flow(flow)
            return count, flow
        else:
            return 0, stream.empty()
