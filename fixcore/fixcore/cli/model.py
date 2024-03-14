from __future__ import annotations

import calendar
import inspect
import json
from abc import ABC, abstractmethod
from asyncio import iscoroutine
from datetime import timedelta
from enum import Enum
from functools import reduce
from pathlib import Path
from textwrap import dedent
from typing import (
    Optional,
    List,
    Any,
    Dict,
    Tuple,
    Callable,
    Union,
    Awaitable,
    Type,
    cast,
    Set,
    AsyncIterator,
    TYPE_CHECKING,
)

from aiostream import stream
from aiostream.core import Stream
from attrs import define, field
from parsy import test_char, string
from rich.jupyter import JupyterMixin

from fixcore.cli import JsGen, T, Sink, JsStream
from fixcore.console_renderer import ConsoleRenderer, ConsoleColorSystem
from fixcore.core_config import AliasTemplateConfig, AliasTemplateParameterConfig
from fixcore.error import CLIParseError
from fixcore.ids import GraphName
from fixcore.user.model import Permission, AuthorizedUser
from fixcore.query.model import Query, variable_to_absolute, PathRoot
from fixcore.query.template_expander import render_template
from fixcore.types import Json, JsonElement
from fixcore.util import AccessJson, uuid_str, from_utc, utc, utc_str
from fixlib.parse_util import l_curly_dp, r_curly_dp
from fixlib.utils import get_local_tzinfo

if TYPE_CHECKING:
    from fixcore.dependencies import TenantDependencies


class MediaType(Enum):
    Json = 1
    FilePath = 2
    Markdown = 3
    String = 4

    @property
    def text(self) -> bool:
        return self in (MediaType.Json, MediaType.String, MediaType.Markdown)

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

# use this property name as reference to self when defined via .
self_name = "self_" + uuid_str()


@define(frozen=True)
class FilePath:
    user: Path
    local: Path

    def json(self) -> Json:
        return {"user_path": str(self.user), "local_path": str(self.local)}

    @staticmethod
    def from_path(in_path: JsonElement) -> FilePath:
        if isinstance(in_path, str):
            p = Path(in_path)
            return FilePath(Path(p.name), p.expanduser().absolute())
        elif isinstance(in_path, dict) and "user_path" in in_path and "local_path" in in_path:
            return FilePath(Path(in_path["user_path"]), Path(in_path["local_path"]).expanduser().absolute())
        else:
            raise ValueError(f"Invalid file path: {in_path}")

    @staticmethod
    def user_local(user: Union[str, Path], local: Union[str, Path]) -> FilePath:
        return FilePath(Path(user), Path(local).expanduser().absolute())


@define(frozen=True)
class CLIContext:
    env: Dict[str, str] = field(factory=dict)
    uploaded_files: Dict[str, str] = field(factory=dict)  # id -> path
    query: Optional[Query] = None
    query_options: Dict[str, Any] = field(factory=dict)
    commands: List[ExecutableCommand] = field(factory=list)
    console_renderer: Optional[ConsoleRenderer] = None
    source: Optional[str] = None  # who is calling
    user: Optional[AuthorizedUser] = None

    @property
    def graph_name(self) -> GraphName:
        return GraphName(self.env["graph"])

    @property
    def section(self) -> str:
        return self.env.get("section", PathRoot)

    @property
    def intern(self) -> bool:
        # currently only 2 sources: api and task_handler
        return self.source == "task_handler"

    @property
    def user_permissions(self) -> Set[Permission]:
        return self.user.permissions if self.user else set()

    def variable_in_section(self, variable: str) -> str:
        # if there is no entity provider, always assume the root section
        section = (
            self.env.get("section")
            if self.query or self.commands and isinstance(self.commands[0].command, EntityProvider)
            else PathRoot
        )
        return variable_to_absolute(section, variable)

    def render_console(self, element: Union[str, JupyterMixin]) -> str:
        if self.console_renderer:
            return self.console_renderer.render(element)
        elif isinstance(element, JupyterMixin):
            return str(element)
        else:
            return element

    def text_generator(
        self, line: ParsedCommandLine, in_stream: AsyncIterator[JsonElement]
    ) -> AsyncIterator[JsonElement]:
        async def render_markdown() -> AsyncIterator[str]:
            async for e in in_stream:
                yield self.render_console(e)  # type: ignore

        if line.produces == MediaType.Markdown:
            return render_markdown()
        else:
            return in_stream

    def supports_color(self) -> bool:
        return (
            self.console_renderer is not None
            and self.console_renderer.color_system is not None
            and self.console_renderer.color_system != ConsoleColorSystem.monochrome
        )

    def formatter(self, format_string: str) -> Callable[[Json], str]:
        return self.formatter_with_variables(format_string, False)[0]

    def formatter_with_variables(
        self, format_string: str, collect_variables: bool = True
    ) -> Tuple[Callable[[Json], str], Optional[Set[str]]]:
        """
        A renderer can be used to string format objects based on a provided format string.
        """

        variables: Optional[Set[str]] = set() if collect_variables else None

        def format_variable(name: str) -> str:
            assert "__" not in name, "No dunder attributes allowed"
            if name in (".", "/"):
                in_section = self_name
            else:
                in_section = self.variable_in_section(name)
                if collect_variables:
                    variables.add(in_section)  # type: ignore
            return "{" + in_section + "}"

        def render_simple_property(prop: Any) -> str:
            return json.dumps(prop) if prop is None or isinstance(prop, bool) else str(prop)

        variable = (l_curly_dp >> no_closing_p << r_curly_dp).map(format_variable)
        token = double_curly_open_dp | double_curly_close_dp | no_bracket_p | variable | l_or_r_curly_dp
        format_string_parser = token.many().concat()
        formatter: str = format_string_parser.parse(format_string)

        def format_object(obj: Any) -> str:
            return formatter.format_map(AccessJson.wrap(obj, "null", render_simple_property, self_name))

        return format_object, variables


EmptyContext = CLIContext()


class CLIEngine(ABC):
    @abstractmethod
    async def evaluate_cli_command(
        self, cli_input: str, context: CLIContext = EmptyContext, replace_place_holder: bool = True
    ) -> List[ParsedCommandLine]:
        pass


@define
class CLICommandRequirement:
    name: str


@define
class CLIFileRequirement(CLICommandRequirement):
    path: str  # local client path


class CLIAction(ABC):
    def __init__(
        self,
        produces: MediaType,
        requires: Optional[List[CLICommandRequirement]],
        envelope: Optional[Dict[str, str]],
        required_permissions: Optional[Set[Permission]] = None,
    ) -> None:
        self.produces = produces
        self.required = requires or []
        self.envelope: Dict[str, str] = envelope or {}
        self.required_permissions = required_permissions or set()

    @staticmethod
    def make_stream(in_stream: JsGen) -> JsStream:
        return in_stream if isinstance(in_stream, Stream) else stream.iterate(in_stream)


@define
class CLISourceContext:
    count: Optional[int] = None
    total_count: Optional[int] = None


class CLISource(CLIAction):
    def __init__(
        self,
        fn: Callable[[], Union[Tuple[CLISourceContext, JsGen], Awaitable[Tuple[CLISourceContext, JsGen]]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
        envelope: Optional[Dict[str, str]] = None,
        required_permissions: Optional[Set[Permission]] = None,
    ) -> None:
        super().__init__(produces, requires, envelope, required_permissions)
        self._fn = fn

    async def source(self) -> Tuple[CLISourceContext, JsStream]:
        res = self._fn()
        context, gen = await res if iscoroutine(res) else res
        return context, self.make_stream(await gen if iscoroutine(gen) else gen)

    @staticmethod
    def only_count(
        fn: Callable[[], Union[Tuple[int, JsGen], Awaitable[Tuple[int, JsGen]]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
        envelope: Optional[Dict[str, str]] = None,
        required_permissions: Optional[Set[Permission]] = None,
    ) -> CLISource:
        async def combine() -> Tuple[CLISourceContext, JsGen]:
            res = fn()
            count, gen = await res if iscoroutine(res) else res
            return CLISourceContext(count=count, total_count=count), gen

        return CLISource(combine, produces, requires, envelope, required_permissions)

    @staticmethod
    def no_count(
        fn: Callable[[], Union[JsGen, Awaitable[JsGen]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
        envelope: Optional[Dict[str, str]] = None,
        required_permissions: Optional[Set[Permission]] = None,
    ) -> CLISource:
        return CLISource.with_count(fn, None, produces, requires, envelope, required_permissions)

    @staticmethod
    def with_count(
        fn: Callable[[], Union[JsGen, Awaitable[JsGen]]],
        count: Optional[int],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
        envelope: Optional[Dict[str, str]] = None,
        required_permissions: Optional[Set[Permission]] = None,
    ) -> CLISource:
        async def combine() -> Tuple[CLISourceContext, JsGen]:
            res = fn()
            gen = await res if iscoroutine(res) else res
            return CLISourceContext(count=count), gen

        return CLISource(combine, produces, requires, envelope, required_permissions)

    @staticmethod
    def single(
        fn: Callable[[], Union[JsGen, Awaitable[JsGen]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
        envelope: Optional[Dict[str, str]] = None,
        required_permissions: Optional[Set[Permission]] = None,
    ) -> CLISource:
        return CLISource.with_count(fn, 1, produces, requires, envelope, required_permissions)

    @staticmethod
    def empty() -> CLISource:
        return CLISource.with_count(stream.empty, 0)


class CLIFlow(CLIAction):
    def __init__(
        self,
        fn: Callable[[JsStream], Union[JsGen, Awaitable[JsGen]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
        envelope: Optional[Dict[str, str]] = None,
        required_permissions: Optional[Set[Permission]] = None,
    ) -> None:
        super().__init__(produces, requires, envelope, required_permissions)
        self._fn = fn

    async def flow(self, in_stream: JsGen) -> JsStream:
        gen = self._fn(self.make_stream(in_stream))
        return self.make_stream(await gen if iscoroutine(gen) else gen)


@define
class ArgInfo:
    # If the argument has a name. It is quite common that arguments do not have a name
    # but are expected at some position.
    # Example: `count <kind>`: kind is the argument at position 1 without a name
    name: Optional[str] = None
    # Defines if this argument expects a value.
    # Some arguments are only flags, while others expect a value.
    # Example: `--compress` is a flag without value
    # Example: `--count <kind>` is an argument with value
    expects_value: bool = False
    # If the value has to be picked from a list of values (enumeration).
    # Example: `--format svg|png|jpg`
    possible_values: List[str] = field(factory=list)
    # If this argument is allowed to be specified multiple times
    can_occur_multiple_times: bool = False
    # Give a type hint for the argument value.
    # Allowed values are:
    # - `file`: the argument expects a file path
    # - `kind`: the argument expects a kind in the model
    # - `property`: the argument expects a property in the model
    # - `command`: the argument expects a command on the cli
    # - `event`: the event handled or emitted by the task handler
    # - `search`: the argument expects a search string
    value_hint: Optional[str] = None
    # Help text of the argument option.
    help_text: Optional[str] = None
    # If multiple options share the same group, only one of them can be selected.
    # Use groups if you have multiple options, where only one is allowed to be selected.s
    option_group: Optional[str] = None


# mypy does not support recursive type aliases: define 3 levels as maximum here
ArgsInfo = Union[
    Dict[str, Union[Dict[str, Union[Dict[str, Union[Any, List[ArgInfo]]], List[ArgInfo]]], List[ArgInfo]]],
    List[ArgInfo],
]


class CLICommand(ABC):
    """
    The CLIPart is the base for all participants of the cli execution.
    Source: generates a stream of objects
    Flow: transforms the elements in a stream of objects
    Sink: takes a stream of objects and creates a result
    """

    def __init__(
        self, dependencies: TenantDependencies, category: str = "misc", allowed_in_source_position: bool = False
    ) -> None:
        self.dependencies = dependencies
        self.category = category
        self.allowed_in_source_position = allowed_in_source_position

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
    def args_info(self) -> ArgsInfo:
        pass

    @abstractmethod
    def info(self) -> str:
        pass

    @abstractmethod
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        pass

    @staticmethod
    def get_from(name: str, kind: Type[T], kwargs: Dict[str, Any]) -> Optional[T]:
        if (kd := kwargs.get(name)) and isinstance(kd, kind):
            return kd  # type: ignore
        return None

    @staticmethod
    def get_previous_command(kwargs: Dict[str, Any]) -> Optional[ExecutableCommand]:
        return CLICommand.get_from("previous_command", ExecutableCommand, kwargs)

    def additional_properties_to_show(self) -> List[Tuple[List[str], str]]:
        # Override this method to add additional properties to output commands (e.g., list)
        return []


@define(order=True, hash=True, frozen=True)
class AliasTemplateParameter:
    name: str
    description: str
    default: Optional[JsonElement] = None

    def example_value(self) -> JsonElement:
        return self.default if self.default else f"test-{self.name.replace('_', '-')}"

    @property
    def arg_name(self) -> str:
        return "--" + self.name.replace("_", "-")


@define(order=True, hash=True, frozen=True)
class InfraAppAliasParameter:
    name: str
    help: str
    default: Optional[JsonElement]

    @property
    def arg_name(self) -> str:
        return "--" + self.name.replace("_", "-")


# pylint: disable=not-an-iterable
@define(order=True, hash=True, frozen=True)
class InfraAppAlias:
    name: str
    description: str
    readme: str
    parameters: List[InfraAppAliasParameter]

    def template(self) -> str:
        return f"apps run {self.name}" + r" {{args}}"

    def render(self, props: Json) -> str:
        return render_template(self.template(), props)

    def help(self) -> str:
        args = " ".join(f"{arg.arg_name} <value>" for arg in self.parameters)

        indent = "        "
        desc = ""
        if self.readme:
            for line in self.readme.splitlines():
                desc += f"\n{indent}{line}"

        def param_info_infra_apps(param: InfraAppAliasParameter) -> str:
            default = f" [default: {param.default}]" if param.default else " [required]"
            return f"- `{param.arg_name}`{default}: {param.help}"

        arg_info = f"\n{indent}".join(param_info_infra_apps(param) for param in (self.parameters or []))
        result = dedent(
            f"""
        {self.name}: {self.description}
        ```shell
        {self.name} {args}
        ```
        {desc}
        ## Parameters
        {arg_info}"""
        )
        return result

    def rendered_help(self, ctx: CLIContext) -> str:
        return ctx.render_console(self.help())


# pylint: disable=not-an-iterable
@define(order=True, hash=True, frozen=True)
class AliasTemplate:
    name: str
    info: str
    template: str
    parameters: List[AliasTemplateParameter] = field(factory=list)
    description: Optional[str] = None
    # only use args_description if the template does not use explicit parameters
    args_description: Dict[str, str] = field(factory=dict)
    allowed_in_source_position: bool = False

    def render(self, props: Json) -> str:
        return render_template(self.template, props)

    def args_info(self) -> ArgsInfo:
        args_desc = [ArgInfo(name, expects_value=True, help_text=desc) for name, desc in self.args_description.items()]
        param = [
            ArgInfo(
                p.arg_name,
                expects_value=True,
                help_text=f"[{'required' if p.default is None else 'optional'}] {p.description}",
            )
            for p in sorted(self.parameters, key=lambda p: p.default is not None)  # required parameters first
        ]
        return args_desc + param

    def help_with_params(self) -> str:
        args = " ".join(f"{arg.arg_name} <value>" for arg in self.parameters)

        def param_info(p: AliasTemplateParameter) -> str:
            default = f" [default: {p.default}]" if p.default else " [required]"
            return f"- `{p.arg_name}`{default}: {p.description}"

        def sort_required_name(p: AliasTemplateParameter) -> Any:
            return p.default is not None, p.name

        indent = "            "
        arg_info = f"\n{indent}".join(param_info(arg) for arg in sorted(self.parameters, key=sort_required_name))
        minimal = " ".join(f'{p.arg_name} "{p.example_value()}"' for p in self.parameters if p.default is None)
        desc = ""
        if self.description:
            for line in self.description.splitlines():
                desc += f"\n{indent}{line}"

        return dedent(
            f"""
            {self.name}: {self.info}
            ```shell
            {self.name} {args}
            ```
            {desc}
            ## Parameters
            {arg_info}

            ## Template
            ```shell
            > {self.template}
            ```

            ## Example
            ```shell
            # Executing this command
            > {self.name} {minimal}
            # Will expand to this command
            > {self.render({p.name: p.example_value() for p in self.parameters})}
            ```
            """
        )

    def help_no_params_args(self) -> str:
        args = ""
        args_info = ""
        for arg_name, arg_description in self.args_description.items():
            args += f" [{arg_name}]"
            args_info += f"\n- `{arg_name}`: {arg_description}"

        args_info = args_info or ("<args>" if "{args}" in self.template else "")
        return (
            f"{self.name}: {self.info}\n```shell\n{self.name} {args}\n```\n\n"
            f"## Parameters\n{args_info}\n\n{self.description}\n\n"
        )

    def help(self) -> str:
        return self.help_with_params() if self.parameters else self.help_no_params_args()

    def rendered_help(self, ctx: CLIContext) -> str:
        return ctx.render_console(self.help())

    @staticmethod
    def from_config(cfg: AliasTemplateConfig) -> AliasTemplate:
        def arg(p: AliasTemplateParameterConfig) -> AliasTemplateParameter:
            return AliasTemplateParameter(p.name, p.description, p.default)

        return AliasTemplate(
            name=cfg.name,
            info=cfg.info,
            template=cfg.template,
            parameters=[arg(a) for a in cfg.parameters],
            description=cfg.description,
            allowed_in_source_position=cfg.allowed_in_source_position or False,
        )


@define
class WorkerCustomCommand:
    """
    A worker might provide custom commands. This definition is provided by the worker.
    """

    name: str
    info: Optional[str] = None
    args_description: Dict[str, str] = field(factory=dict)
    description: Optional[str] = None
    filter: Dict[str, List[str]] = field(factory=dict)
    allowed_on_kind: Optional[str] = None
    expect_node_result: bool = False

    def to_template(self) -> AliasTemplate:
        allowed_kind = f" --allowed-on {self.allowed_on_kind}" if self.allowed_on_kind else ""
        result_flag = "" if self.expect_node_result else " --no-node-result"
        command = f"--command '{self.name}'"
        args = "--arg '{{args}}'"
        return AliasTemplate(
            name=self.name,
            info=self.info or "",
            args_description=self.args_description,
            template=f"execute-task{result_flag}{allowed_kind} {command} {args}",
            description=self.description,
        )


class InternalPart(ABC):
    """
    Internal parts can be executed but are not shown via help.
    They usually get injected by the CLI Interpreter to ease usability.
    """


class EntityProvider(ABC):
    """
    Mark this command as a provider of entities with: id, reported, desired, metadata.
    """


class OutputTransformer(ABC):
    """
    Mark all commands that transform the output stream (formatting).
    """


class PreserveOutputFormat(ABC):
    """
    Mark all commands where the output should not be flattened to default line output.
    """


class NoTerminalOutput(ABC):
    """
    Mark all commands where the output should not contain any terminal escape codes.
    """


@define
class ParsedCommand:
    cmd: str
    args: Optional[str] = None


@define
class ParsedCommands:
    commands: List[ParsedCommand]
    env: Json = field(factory=dict)


@define
class ExecutableCommand:
    name: str  # the name of the command or alias
    command: CLICommand
    arg: Optional[str]
    action: CLIAction


@define
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
    envelope: Dict[str, str]

    def __attrs_post_init__(self) -> None:
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

    def is_allowed_to_execute(self) -> bool:
        if self.ctx.user is None:
            return False
        return all(self.ctx.user.has_permission(cmd.action.required_permissions) for cmd in self.executable_commands)

    async def execute(self) -> Tuple[CLISourceContext, JsStream]:
        if self.executable_commands:
            source_action = cast(CLISource, self.executable_commands[0].action)
            context, flow = await source_action.source()
            for command in self.executable_commands[1:]:
                flow_action = cast(CLIFlow, command.action)
                flow = await flow_action.flow(flow)
            return context, flow
        else:
            return CLISourceContext(count=0), stream.empty()  # type: ignore


class CLI(ABC):
    @abstractmethod
    async def evaluate_cli_command(
        self, cli_input: str, context: CLIContext = EmptyContext, replace_place_holder: bool = True
    ) -> List[ParsedCommandLine]:
        pass

    @abstractmethod
    async def execute_cli_command(self, cli_input: str, sink: Sink[T], ctx: CLIContext = EmptyContext) -> List[T]:
        pass

    @abstractmethod
    def register_infra_app_alias(self, alias: InfraAppAlias) -> None:
        pass

    @abstractmethod
    def unregister_infra_app_alias(self, name: str) -> None:
        pass

    @abstractmethod
    def register_alias_template(self, template: AliasTemplate) -> None:
        """
        Called when something introduces a custom command.
        """

    @abstractmethod
    def unregister_alias_template(self, name: str) -> None:
        """
        Called when something removes a custom command.
        """

    @property
    @abstractmethod
    def direct_commands(self) -> Dict[str, CLICommand]:
        pass

    @property
    @abstractmethod
    def alias_commands(self) -> Dict[str, CLICommand]:
        pass

    @property
    @abstractmethod
    def commands(self) -> Dict[str, CLICommand]:
        pass

    @property
    @abstractmethod
    def env(self) -> Dict[str, Any]:
        pass

    @property
    @abstractmethod
    def dependencies(self) -> TenantDependencies:
        pass

    @property
    @abstractmethod
    def alias_templates(self) -> Dict[str, AliasTemplate]:
        pass

    @property
    @abstractmethod
    def infra_app_aliases(self) -> Dict[str, InfraAppAlias]:
        pass

    @staticmethod
    def replacements(**env: str) -> Dict[str, str]:
        now_string = env.get("now")
        ut = from_utc(now_string) if now_string else utc()
        t = ut.date()
        try:
            n = ut.astimezone(get_local_tzinfo())
        except Exception:
            n = ut
        return dict(
            UTC=utc_str(ut),
            NOW=n.strftime("%Y-%m-%dT%H:%M:%S%z"),
            TODAY=t.strftime("%Y-%m-%d"),
            TOMORROW=(t + timedelta(days=1)).isoformat(),
            YESTERDAY=(t + timedelta(days=-1)).isoformat(),
            YEAR=t.strftime("%Y"),
            MONTH=t.strftime("%m"),
            DAY=t.strftime("%d"),
            TIME=n.strftime("%H:%M:%S"),
            HOUR=n.strftime("%H"),
            MINUTE=n.strftime("%M"),
            SECOND=n.strftime("%S"),
            TZ_OFFSET=n.strftime("%z"),
            TZ=n.strftime("%Z"),
            MONDAY=(t + timedelta((calendar.MONDAY - t.weekday()) % 7)).isoformat(),
            TUESDAY=(t + timedelta((calendar.TUESDAY - t.weekday()) % 7)).isoformat(),
            WEDNESDAY=(t + timedelta((calendar.WEDNESDAY - t.weekday()) % 7)).isoformat(),
            THURSDAY=(t + timedelta((calendar.THURSDAY - t.weekday()) % 7)).isoformat(),
            FRIDAY=(t + timedelta((calendar.FRIDAY - t.weekday()) % 7)).isoformat(),
            SATURDAY=(t + timedelta((calendar.SATURDAY - t.weekday()) % 7)).isoformat(),
            SUNDAY=(t + timedelta((calendar.SUNDAY - t.weekday()) % 7)).isoformat(),
        )

    @staticmethod
    def replace_placeholder(cli_input: str, **env: str) -> str:
        # We do not use the template renderer here on purpose:
        # - the string is processed before it is evaluated - there is no way to escape the @ symbol
        # - the string might contain @ symbols
        result = reduce(lambda res, kv: res.replace(f"@{kv[0]}@", kv[1]), CLI.replacements(**env).items(), cli_input)
        result = reduce(
            lambda res, kv: res.replace(f"@{kv[0].lower()}@", kv[1]), CLI.replacements(**env).items(), result
        )
        return result
