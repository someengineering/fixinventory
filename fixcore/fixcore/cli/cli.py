from __future__ import annotations

import asyncio
import logging
from asyncio import Task
from contextlib import suppress
from itertools import takewhile
from operator import attrgetter
from textwrap import dedent
from typing import Dict, List, Tuple, Union, Sequence
from typing import Optional, Any, TYPE_CHECKING

from aiostream import stream
from attrs import evolve
from parsy import Parser
from rich.padding import Padding

from fixcore import version
from fixcore.analytics import CoreEvent
from fixcore.cli import cmd_with_args_parser, key_values_parser, T, Sink, args_values_parser, JsGen
from fixcore.cli.command import (
    SearchPart,
    PredecessorsPart,
    SuccessorsPart,
    AncestorsPart,
    DescendantsPart,
    AggregateCommand,
    CountCommand,
    HeadCommand,
    TailCommand,
    SearchCLIPart,
    ExecuteSearchCommand,
    JobsCommand,
    WelcomeCommand,
    SortPart,
    LimitPart,
    HistoryPart,
    ReportCommand,
    WriteCommand,
)
from fixcore.cli.model import (
    ParsedCommand,
    ParsedCommands,
    ExecutableCommand,
    ParsedCommandLine,
    CLICommand,
    InternalPart,
    CLIContext,
    CLI,
    EmptyContext,
    CLISource,
    NoTerminalOutput,
    OutputTransformer,
    PreserveOutputFormat,
    AliasTemplate,
    InfraAppAlias,
    ArgsInfo,
    ArgInfo,
    AliasTemplateParameter,
)
from fixcore.console_renderer import ConsoleRenderer
from fixcore.error import CLIParseError
from fixcore.model.typed_model import class_fqn
from fixcore.query.model import (
    Query,
    Navigation,
    AllTerm,
    Aggregate,
    AggregateVariable,
    AggregateVariableName,
    AggregateFunction,
    PathRoot,
    Limit,
    Sort,
)
from fixcore.query.query_parser import aggregate_parameter_parser, sort_args_p, limit_parser_direct
from fixcore.service import Service
from fixcore.types import JsonElement
from fixcore.user.model import Permission
from fixcore.util import group_by
from fixlib.parse_util import make_parser, pipe_p, semicolon_p

if TYPE_CHECKING:
    from fixcore.dependencies import TenantDependencies

log = logging.getLogger(__name__)


@make_parser
def single_command_parser() -> Parser:
    parsed = yield cmd_with_args_parser
    cmd_args = [a.strip() for a in parsed.strip().split(" ", 1)]
    cmd, args = cmd_args if len(cmd_args) == 2 else (cmd_args[0], None)
    return ParsedCommand(cmd, args)


single_commands = single_command_parser.sep_by(pipe_p, min=1)


@make_parser
def command_line_parser() -> Parser:
    maybe_env = yield key_values_parser.optional()
    commands = yield single_commands
    return ParsedCommands(commands, maybe_env if maybe_env else {})


# multiple piped commands are separated by semicolon
multi_command_parser = command_line_parser.sep_by(semicolon_p)


class HelpCommand(CLICommand):
    """
    Usage: help [command]

    Parameter:
        command [optional]: if given shows the help for a specific command

    Show help text for a command or general help information.
    """

    def __init__(
        self,
        dependencies: TenantDependencies,
        parts: List[CLICommand],
        alias_names: Dict[str, str],
        alias_templates: Dict[str, AliasTemplate],
        infra_app_aliases: Dict[str, InfraAppAlias],
    ):
        super().__init__(dependencies, "misc", True)
        self.all_parts = {p.name: p for p in parts + [self]}
        self.parts = {p.name: p for p in parts + [self] if not isinstance(p, InternalPart)}
        self.alias_names = {a: n for a, n in alias_names.items() if n in self.parts and a not in self.parts}
        self.reverse_alias_names: Dict[str, List[str]] = {
            k: [e[0] for e in v] for k, v in group_by(lambda a: a[1], self.alias_names.items()).items()
        }
        self.alias_templates = alias_templates
        self.infra_app_aliases = infra_app_aliases

    @property
    def name(self) -> str:
        return "help"

    def info(self) -> str:
        return "Shows available commands, as well as help for any specific command."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(None, expects_value=True, value_hint="command")]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        def placeholders() -> str:
            replacements = "\n".join(f"- `@{key}@` -> {value}" for key, value in CLI.replacements(**ctx.env).items())
            return ctx.render_console(f"## Valid placeholder string: \n\n{replacements}")

        def overview() -> str:
            all_parts = sorted(self.parts.values(), key=lambda p: p.name)
            parts = [p for p in all_parts if isinstance(p, CLICommand)]
            templates = list(sorted(self.alias_templates.values(), key=attrgetter("name")))
            alias_templates = "\n".join(f"- `{a.name}` - {a.info}" for a in templates)

            sorted_infra_app_aliases = list(sorted(self.infra_app_aliases.values(), key=attrgetter("name")))
            infra_app_aliases = "\n".join(f"- `{a.name}` - {a.description}" for a in sorted_infra_app_aliases)

            result = f"## Custom Commands \n{alias_templates}\n ## Infrastructure Apps \n{infra_app_aliases}\n"
            for category in ["search", "format", "action", "setup", "misc"]:
                result += f"\n\n## {category.capitalize()} Commands\n"
                for part in parts:
                    if part.category == category:
                        result += f"- `{part.name}` - {part.info()}\n"

            result += dedent(
                """

                 *Note* that you can pipe commands using the pipe character (|)
                 and chain multiple commands using the semicolon (;).

                 Use `help <command>` to show help for a specific command. \\
                 Use `help placeholders` to see the list of available placeholders.
                 """
            )
            headline = ctx.render_console(f"# fixcore CLI ({version()})")
            # ck mascot is centered (rendered if color is enabled)
            middle = (
                int((ctx.console_renderer.width - 22) / 2)
                if ctx.console_renderer is not None and ctx.console_renderer.width is not None
                else 0
            )
            logo = ctx.render_console(Padding(WelcomeCommand.ck, pad=(0, 0, 0, middle))) if ctx.supports_color() else ""
            return headline + logo + ctx.render_console(result)

        def help_command() -> JsGen:
            if not arg:
                result = overview()
            elif arg == "placeholders":
                result = placeholders()
            elif arg in self.all_parts:
                maybe_aliases = self.reverse_alias_names.get(arg)
                result = ""
                if maybe_aliases:
                    result += f'{arg} can also invoked via: {", ".join(maybe_aliases)}\n\n'
                result += self.all_parts[arg].rendered_help(ctx)
            elif arg in self.alias_names:
                alias = self.alias_names[arg]
                explain = f"{arg} is an alias for {alias}\n\n"
                result = explain + self.all_parts[alias].rendered_help(ctx)
            elif arg in self.alias_templates:
                result = self.alias_templates[arg].rendered_help(ctx)
            elif arg in self.infra_app_aliases:
                result = self.infra_app_aliases[arg].rendered_help(ctx)
            else:
                result = f"No command found with this name: {arg}"

            return stream.just(result)

        return CLISource.single(help_command, required_permissions={Permission.read})


CLIArg = Tuple[CLICommand, Optional[str]]
# If no sort is defined in the part, we use this default sort order
DefaultSort = [Sort("/reported.kind"), Sort("/reported.name"), Sort("/reported.id")]
# Default sort order for history searches
HistorySort = [Sort("/changed_at"), Sort("/reported.kind"), Sort("/reported.name"), Sort("/reported.id")]


class CLIService(CLI, Service):
    """
    The CLI has a defined set of dependencies and knows a list if commands.
    A string can be parsed into a command line that can be executed based on the list of available commands.
    """

    def __init__(
        self,
        dependencies: TenantDependencies,
        parts: List[CLICommand],
        env: Dict[str, Any],
        alias_names: Dict[str, str],
    ):
        super().__init__()
        dependencies.extend(cli=self)
        alias_templates_list = [AliasTemplate.from_config(cmd) for cmd in dependencies.config.custom_commands.commands]
        alias_templates = {a.name: a for a in alias_templates_list}
        infra_app_aliases: Dict[str, InfraAppAlias] = {}
        help_cmd = HelpCommand(
            dependencies,
            parts,
            alias_names,
            alias_templates,
            infra_app_aliases,
        )
        cmds = {p.name: p for p in parts + [help_cmd]}
        alias_cmds = {alias: cmds[name] for alias, name in alias_names.items() if name in cmds and alias not in cmds}
        self.cli_env = env
        self.alias_names = alias_names
        self.__direct_commands = cmds
        self.__alias_commands = alias_cmds
        self.__commands: Dict[str, CLICommand] = {**cmds, **alias_cmds}
        self.__dependencies = dependencies
        self.__alias_templates = alias_templates
        self.__infra_app_aliases = infra_app_aliases
        self.reaper: Optional[Task[None]] = None

    @property
    def direct_commands(self) -> Dict[str, CLICommand]:
        return self.__direct_commands

    @property
    def alias_commands(self) -> Dict[str, CLICommand]:
        return self.__alias_commands

    @property
    def commands(self) -> Dict[str, CLICommand]:
        return self.__commands

    @property
    def env(self) -> Dict[str, Any]:
        return self.cli_env

    @property
    def dependencies(self) -> TenantDependencies:
        return self.__dependencies

    @property
    def alias_templates(self) -> Dict[str, AliasTemplate]:
        return self.__alias_templates

    @property
    def infra_app_aliases(self) -> Dict[str, InfraAppAlias]:
        return self.__infra_app_aliases

    def _no_name_conflict(self, name: str) -> bool:
        return (
            name not in self.direct_commands
            and name not in self.alias_commands
            and name not in self.alias_templates
            and name not in self.infra_app_aliases
        )

    def register_infra_app_alias(self, alias: InfraAppAlias) -> None:
        """
        Called when an infra app is registered.
        """
        if self._no_name_conflict(alias.name):
            self.__infra_app_aliases[alias.name] = alias

    def unregister_infra_app_alias(self, name: str) -> None:
        del self.__infra_app_aliases[name]

    def register_alias_template(self, template: AliasTemplate) -> None:
        """
        Called when something introduces a custom command.
        The registered templated will always override any existing template.
        """
        if self._no_name_conflict(template.name):
            self.alias_templates[template.name] = template

    def unregister_alias_template(self, name: str) -> None:
        """
        Called when something removes a custom command.
        """
        if name in self.alias_templates:
            del self.alias_templates[name]

    async def start(self) -> None:
        self.reaper = asyncio.create_task(self.reap_tasks())

    async def stop(self) -> None:
        if self.reaper:
            self.reaper.cancel()
            await asyncio.gather(self.reaper, return_exceptions=True)

        while not self.dependencies.forked_tasks.empty():
            task, _ = self.dependencies.forked_tasks.get_nowait()
            loop = asyncio.get_event_loop()
            with suppress(asyncio.CancelledError):
                if not task.done() or not task.cancelled():
                    task.cancel()
                loop.run_until_complete(task)

    async def reap_tasks(self) -> None:
        while True:
            try:
                task, info = await self.dependencies.forked_tasks.get()
                try:
                    res = await task
                    log.info(f"Spawned task {info} completed with: {res}")
                except Exception as ex:
                    log.info(f"Spawned task {info} failed. Reason {ex}")
            except Exception as ex:
                log.warning(f"Error in main loop: {ex}")

    def command(
        self, name: str, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any
    ) -> ExecutableCommand:
        """
        Create an executable command for given command name, args and context.
        :param name: the name of the command to execute (must be a known command)
        :param arg: the arg of the command (must be parsable by the command)
        :param ctx: the context of this command.
        :return: the ready to run executable command.
        :raises:
            CLIParseError: if the name of the command is not known, or the argument fails to parse.
        """
        if name in self.commands:
            command = self.commands[name]
            try:
                action = command.parse(arg, ctx, cmd_name=name, **kwargs)
                return ExecutableCommand(name, command, arg, action)
            except Exception as ex:
                raise CLIParseError(f"{name} can not parse arg {arg}. Reason: {ex}") from ex
        else:
            raise CLIParseError(f"Command >{name}< is not known. Typo?")

    async def create_query(
        self, commands: List[ExecutableCommand], ctx: CLIContext
    ) -> Tuple[Query, Dict[str, Any], List[ExecutableCommand]]:
        """
        Takes a list of query part commands and combine them to a single executable query command.
        This process can also introduce new commands that should run after the query is finished.
        Therefore, a list of executable commands is returned.
        :param commands: the incoming executable commands, which actions are all instances of SearchCLIPart.
        :param ctx: the context to execute within.
        :return: the resulting list of commands to execute.
        """

        # Pass parsed options to execute query
        # Multiple query commands are possible - so the dict is combined with every parsed query.
        parsed_options: Dict[str, Any] = {}

        async def parse_query(query_arg: str) -> Query:
            nonlocal parsed_options
            parsed, query_part = ExecuteSearchCommand.parse_known(query_arg)
            parsed_options = {**parsed_options, **parsed}
            # empty string is interpreted as no filter
            query_part = "all" if query_part.strip() == "" else query_part
            # section expansion is disabled here: it will happen on the final query after all parts have been combined
            return await self.dependencies.template_expander.parse_query(
                "".join(query_part), None, omit_section_expansion=True, env=ctx.env
            )

        query: Query = Query.by(AllTerm())
        additional_commands: List[ExecutableCommand] = []
        # We need to remember the first head/tail, since tail will reverse the sort order
        first_head_tail_in_a_row: Optional[CLICommand] = None
        default_sort = DefaultSort
        head_tail_keep_order = True
        for command in commands:
            part = command.command
            arg = command.arg if command.arg else ""
            if isinstance(part, SearchPart):
                query = query.combine(await parse_query(arg))
            elif isinstance(part, HistoryPart):
                parsed_options["history"] = True
                default_sort = HistorySort
                query = query.combine(await parse_query(arg))
                if not query.current_part.sort and not query.aggregate:
                    query = query.set_sort(*HistorySort)
            elif isinstance(part, SortPart):
                if query.current_part.sort == default_sort:
                    query = query.set_sort(*sort_args_p.parse(arg))
                else:
                    query = query.add_sort(*sort_args_p.parse(arg))
            elif isinstance(part, LimitPart):
                query = query.with_limit(limit_parser_direct.parse(arg))
            elif isinstance(part, PredecessorsPart):
                origin, edge = PredecessorsPart.parse_args(arg, ctx)
                query = query.traverse_in(origin, 1, edge)
            elif isinstance(part, SuccessorsPart):
                origin, edge = PredecessorsPart.parse_args(arg, ctx)
                query = query.traverse_out(origin, 1, edge)
            elif isinstance(part, AncestorsPart):
                origin, edge = PredecessorsPart.parse_args(arg, ctx)
                query = query.traverse_in(origin, Navigation.Max, edge)
            elif isinstance(part, DescendantsPart):
                origin, edge = PredecessorsPart.parse_args(arg, ctx)
                query = query.traverse_out(origin, Navigation.Max, edge)
            elif isinstance(part, AggregateCommand):
                group_vars, group_function_vars = aggregate_parameter_parser.parse(arg)
                query = evolve(query, aggregate=Aggregate(group_vars, group_function_vars))
            elif isinstance(part, CountCommand):
                # count command followed by a query: make it an aggregation
                # since the output of aggregation is not exactly the same as count
                # we also add the aggregate_to_count command after the query
                assert query.aggregate is None, "Can not combine aggregate and count!"
                group_by_var = [AggregateVariable(AggregateVariableName(arg), "name")] if arg else []
                aggregate = Aggregate(group_by_var, [AggregateFunction("sum", 1, (), "count")])
                # If the query should be explained, we want the output as is
                if "explain" not in parsed_options:
                    additional_commands.append(self.command("aggregate_to_count", None, ctx))
                query = evolve(query, aggregate=aggregate)
                query = query.set_sort(Sort(f"{PathRoot}count"))
            elif isinstance(part, HeadCommand):
                size = HeadCommand.parse_size(arg)
                limit = query.parts[0].limit or Limit(0, size)
                if first_head_tail_in_a_row and head_tail_keep_order:
                    query = query.with_limit(Limit(limit.offset, min(limit.length, size)))
                elif first_head_tail_in_a_row and not head_tail_keep_order:
                    length = min(limit.length, size)
                    query = query.with_limit(Limit(limit.offset + limit.length - length, length))
                else:
                    query = query.with_limit(size)
            elif isinstance(part, TailCommand):
                size = HeadCommand.parse_size(arg)
                limit = query.parts[0].limit or Limit(0, size)
                if first_head_tail_in_a_row and head_tail_keep_order:
                    query = query.with_limit(Limit(limit.offset + max(0, limit.length - size), min(limit.length, size)))
                elif first_head_tail_in_a_row and not head_tail_keep_order:
                    query = query.with_limit(Limit(limit.offset, min(limit.length, size)))
                else:
                    head_tail_keep_order = False
                    query = query.with_limit(size)
                    p = query.current_part
                    # the limit might have created a new part - make sure there is a sort order
                    p = p if p.sort else evolve(p, sort=default_sort)
                    # reverse the sort order -> limit -> reverse the result
                    query.parts[0] = evolve(p, sort=[s.reversed() for s in p.sort], reverse_result=True)
            else:
                raise AttributeError(f"Do not understand: {part} of type: {class_fqn(part)}")

            # Remember the first head tail in a row of head tails
            if isinstance(part, (HeadCommand, TailCommand)):
                if not first_head_tail_in_a_row:
                    first_head_tail_in_a_row = part
            else:
                first_head_tail_in_a_row = None
                head_tail_keep_order = True

        # Define default sort order, if not already defined
        # A sort order is required to always return the result in a deterministic way to the user.
        # Deterministic order is required for head/tail to work
        if query.is_simple_fulltext_search():
            # Do not define any additional sort order for fulltext searches
            # Fulltext searches are using the BM25 score as default sort order
            default_sort = []
        parts = [pt if pt.sort else evolve(pt, sort=default_sort) for pt in query.parts]
        query = evolve(query, parts=parts)

        # If the last part is a navigation, we need to add sort which will ingest a new part.
        with_sort = query.set_sort(*default_sort) if query.current_part.navigation else query
        section = ctx.env.get("section", PathRoot)
        # If this is an aggregate query, the default sort needs to be changed
        if query.aggregate is not None and query.current_part.sort == default_sort:
            with_sort = query.set_sort(*query.aggregate.sort_by_fn(section))

        # When all parts are combined, interpret the result on defined section.
        final_query = with_sort.on_section(section)
        options = ExecuteSearchCommand.argument_string(parsed_options)
        query_string = str(final_query)
        execute_search = self.command("execute_search", f"{options}'{query_string}'", ctx)
        return final_query, parsed_options, [execute_search, *additional_commands]

    async def evaluate_cli_command(
        self, cli_input: str, context: CLIContext = EmptyContext, replace_place_holder: bool = True
    ) -> List[ParsedCommandLine]:
        async def combine_query_parts(
            commands: List[ExecutableCommand], ctx: CLIContext
        ) -> Tuple[CLIContext, List[ExecutableCommand]]:
            parts = list(takewhile(lambda x: isinstance(x.command, SearchCLIPart), commands))
            if parts:
                query, options, query_parts = await self.create_query(parts, ctx)
                ctx_wq = evolve(ctx, query=query, query_options=options, commands=commands)
                remaining = executable_commands(
                    commands[len(parts) :], ctx_wq, offset=len(parts), previous_command=query_parts[-1]
                )
                rewritten_parts = [*query_parts, *remaining]
            else:
                ctx_wq = evolve(ctx, commands=commands)
                rewritten_parts = executable_commands(commands, ctx_wq)
            # re-evaluate remaining commands - to take the adapted context into account
            return ctx_wq, rewritten_parts

        def rewrite_command_line(cmds: List[ExecutableCommand], ctx: CLIContext) -> List[ExecutableCommand]:
            """
            Rewrite the command line to make it more user-friendly.
            Rules:
            - add the list command if no output format is defined
            - add a format to write commands if no output format is defined
            - report benchmark run will be formatted as benchmark result automatically
            """
            if ctx.env.get("no_rewrite") or len(cmds) == 0:
                return cmds
            first_cmd = cmds[0]
            last_cmd = cmds[-1]
            single = cmds[0] if len(cmds) == 1 else None
            result = cmds

            def no_format() -> bool:
                return not any(c for c in result if isinstance(c.command, (OutputTransformer, PreserveOutputFormat)))

            def fmt_benchmark() -> ExecutableCommand:
                return self.command("format", "--benchmark-result", ctx)

            def fmt_list() -> ExecutableCommand:
                return self.command("list", None, ctx)

            # benchmark run as single command is rewritten to benchmark run | format --benchmark-result
            if single and isinstance(single.command, ReportCommand) and ReportCommand.is_run_action(single.arg):
                result = [single, fmt_benchmark()]
            # if the last command is a write command without any format: add the format
            elif isinstance(last_cmd.command, WriteCommand) and no_format():
                # format is either list (default) or benchmark
                fmt = fmt_benchmark() if isinstance(first_cmd.command, ReportCommand) else fmt_list()
                result = [*cmds[0:-1], fmt, cmds[-1]]

            # produces text and no resulting output transformer is defined: add the default `list` command
            if last_cmd.action.produces.text and no_format():
                result = [*result, fmt_list()]
            return result

        def adjust_context(parsed: ParsedCommands) -> CLIContext:
            cmd_env = {**self.cli_env, **context.env, **parsed.env}
            ctx = evolve(context, env=cmd_env)
            last_command = self.commands.get(parsed.commands[-1].cmd) if parsed.commands else None
            if isinstance(last_command, NoTerminalOutput) and ctx.console_renderer:
                return evolve(ctx, env=cmd_env, console_renderer=ConsoleRenderer.default_renderer())
            else:
                return evolve(context, env=cmd_env)

        # iterate the list of commands and pass information about position, previous command, etc.
        def executable_commands(
            commands: Sequence[Union[ParsedCommand, ExecutableCommand]],
            ctx: CLIContext,
            *,
            previous_command: Optional[ExecutableCommand] = None,
            offset: int = 0,
        ) -> List[ExecutableCommand]:
            result: List[ExecutableCommand] = []
            for pos, c in enumerate(commands):
                name, arg = (c.cmd, c.args) if isinstance(c, ParsedCommand) else (c.name, c.arg)
                command = self.command(name, arg, ctx, position=pos + offset, previous_command=previous_command)
                previous_command = command
                result.append(command)
            return result

        async def parse_line(parsed: ParsedCommands) -> ParsedCommandLine:
            ctx = adjust_context(parsed)
            executable = executable_commands(parsed.commands, ctx)
            rewritten = rewrite_command_line(executable, ctx)
            ctx, commands = await combine_query_parts(rewritten, ctx)
            not_met = [r for cmd in commands for r in cmd.action.required if r.name not in context.uploaded_files]
            envelope = {k: v for cmd in commands for k, v in cmd.action.envelope.items()}
            return ParsedCommandLine(ctx, parsed, commands, not_met, envelope)

        def expand_aliases(line: ParsedCommands) -> ParsedCommands:
            def expand_alias(alias_cmd: ParsedCommand) -> List[ParsedCommand]:
                alias: AliasTemplate = self.alias_templates[alias_cmd.cmd]
                available: Dict[str, AliasTemplateParameter] = {p.name: p for p in alias.parameters}
                props: Dict[str, JsonElement] = self.replacements(**{**self.cli_env, **context.env})  # type: ignore
                props["args"] = alias_cmd.args or ""
                for p in alias.parameters:
                    props[p.name] = p.default
                # only parse properties, if there are any declared
                if alias.parameters:
                    args = (alias_cmd.args or "").strip()
                    parser = args_values_parser if args.startswith("--") else key_values_parser
                    props.update(parser.parse(args))
                undefined = [
                    available[k].arg_name for k, v in props.items() if k != "args" and v is None and k in available
                ]
                if undefined:
                    raise AttributeError(
                        f"Alias {alias_cmd.cmd} not enough parameters provided. Missing: {', '.join(undefined)}"
                    )
                rendered = alias.render(props)
                log.debug(f"The rendered alias template is: {rendered}")
                return single_commands.parse(rendered)  # type: ignore

            def expand_infra_app_alias(alias_cmd: ParsedCommand) -> List[ParsedCommand]:
                alias: InfraAppAlias = self.infra_app_aliases[alias_cmd.cmd]
                props: Dict[str, JsonElement] = self.replacements(**{**self.cli_env, **context.env})  # type: ignore
                props["args"] = alias_cmd.args or ""
                rendered = alias.render(props)
                log.debug(f"The rendered infra app alias template is: {rendered}")
                return single_commands.parse(rendered)  # type: ignore

            result: List[ParsedCommand] = []
            for cmd in line.commands:
                if cmd.cmd in self.alias_templates:
                    result.extend(expand_alias(cmd))
                elif cmd.cmd in self.infra_app_aliases:
                    result.extend(expand_infra_app_alias(cmd))
                else:
                    result.append(cmd)

            return ParsedCommands(result, line.env)

        async def send_analytics(parsed: List[ParsedCommands], raw: List[ParsedCommands]) -> None:
            command_names = [cmd.cmd for line in parsed for cmd in line.commands]
            used_aliases = [cmd.cmd for line in raw for cmd in line.commands if cmd.cmd in self.alias_templates]
            used_infra_app_aliases = [
                cmd.cmd for line in raw for cmd in line.commands if cmd.cmd in self.infra_app_aliases
            ]
            fix_session_id = context.env.get("fix_session_id")
            await self.dependencies.event_sender.core_event(
                CoreEvent.CLICommand,
                {
                    "command_names": command_names,
                    "used_aliases": used_aliases,
                    "used_infra_app_aliases": used_infra_app_aliases,
                    "session_id": fix_session_id,
                    "source": context.source or "unknown",
                },
                command_lines=len(parsed),
                commands=len(command_names),
            )

        def replace_placeholders(parsed: ParsedCommands) -> ParsedCommands:
            cmd_env = {**self.cli_env, **context.env, **parsed.env}

            def replace_command(cmd: ParsedCommand) -> ParsedCommand:
                args = cmd.args if cmd.args is None else self.replace_placeholder(cmd.args, **cmd_env)
                return ParsedCommand(cmd.cmd, args)

            return ParsedCommands([replace_command(cmd) for cmd in parsed.commands], parsed.env)

        # parse command lines (raw)
        raw_parsed: List[ParsedCommands] = multi_command_parser.parse(cli_input)
        # expand aliases
        command_lines = [expand_aliases(cmd_line) for cmd_line in raw_parsed]
        # send analytics
        await send_analytics(command_lines, raw_parsed)
        # decide, if placeholders should be replaced
        first_command = command_lines[0].commands[0] if command_lines and command_lines[0].commands else None
        keep_raw = not replace_place_holder or (first_command and JobsCommand.is_jobs_update(first_command))
        command_lines = command_lines if keep_raw else [replace_placeholders(cmd_line) for cmd_line in command_lines]
        res = [await parse_line(cmd_line) for cmd_line in command_lines]
        return res

    async def execute_cli_command(self, cli_input: str, sink: Sink[T], ctx: CLIContext = EmptyContext) -> List[T]:
        return [await parsed.to_sink(sink) for parsed in await self.evaluate_cli_command(cli_input, ctx, True)]
