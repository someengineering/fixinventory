from __future__ import annotations

import asyncio
import calendar
import logging
from asyncio import Task
from contextlib import suppress
from functools import reduce

from attrs import evolve
from datetime import timedelta
from itertools import takewhile
from operator import attrgetter
from textwrap import dedent
from typing import Dict, List, Tuple
from typing import Optional, Any

from aiostream import stream
from aiostream.core import Stream
from parsy import Parser
from rich.padding import Padding

from resotolib.parse_util import make_parser, pipe_p, semicolon_p
from resotolib.utils import get_local_tzinfo
from resotocore import version
from resotocore.analytics import CoreEvent
from resotocore.cli import cmd_with_args_parser, key_values_parser, T, Sink
from resotocore.cli.command import (
    SearchPart,
    PredecessorsPart,
    SuccessorsPart,
    AncestorsPart,
    DescendantsPart,
    AggregatePart,
    CountCommand,
    HeadCommand,
    TailCommand,
    SearchCLIPart,
    ExecuteSearchCommand,
    JobsCommand,
    WelcomeCommand,
    SortPart,
    LimitPart,
    WorkerCustomCommand,
    HistoryPart,
)
from resotocore.cli.model import (
    ParsedCommand,
    ParsedCommands,
    ExecutableCommand,
    ParsedCommandLine,
    CLICommand,
    CLIDependencies,
    InternalPart,
    CLIContext,
    EmptyContext,
    CLISource,
    NoTerminalOutput,
    AliasTemplate,
    ArgsInfo,
    ArgInfo,
)
from resotocore.console_renderer import ConsoleRenderer
from resotocore.error import CLIParseError
from resotocore.model.typed_model import class_fqn
from resotocore.query.model import (
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
from resotocore.query.query_parser import aggregate_parameter_parser, sort_args_p, limit_parser_direct
from resotocore.types import JsonElement
from resotocore.util import utc_str, utc, from_utc, group_by

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
        dependencies: CLIDependencies,
        parts: List[CLICommand],
        alias_names: Dict[str, str],
        alias_templates: Dict[str, AliasTemplate],
    ):
        super().__init__(dependencies, "misc", True)
        self.all_parts = {p.name: p for p in parts + [self]}
        self.parts = {p.name: p for p in parts + [self] if not isinstance(p, InternalPart)}
        self.alias_names = {a: n for a, n in alias_names.items() if n in self.parts and a not in self.parts}
        self.reverse_alias_names: Dict[str, List[str]] = {
            k: [e[0] for e in v] for k, v in group_by(lambda a: a[1], self.alias_names.items()).items()
        }
        self.alias_templates = alias_templates

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
            result = f"## Custom Commands \n{alias_templates}\n"
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
            headline = ctx.render_console(f"# resotocore CLI ({version()})")
            # ck mascot is centered (rendered if color is enabled)
            middle = (
                int((ctx.console_renderer.width - 22) / 2)
                if ctx.console_renderer is not None and ctx.console_renderer.width is not None
                else 0
            )
            logo = ctx.render_console(Padding(WelcomeCommand.ck, pad=(0, 0, 0, middle))) if ctx.supports_color() else ""
            return headline + logo + ctx.render_console(result)

        def help_command() -> Stream:
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
            else:
                result = f"No command found with this name: {arg}"

            return stream.just(result)

        return CLISource.single(help_command)


CLIArg = Tuple[CLICommand, Optional[str]]
# If no sort is defined in the part, we use this default sort order
DefaultSort = [Sort("/reported.kind"), Sort("/reported.name"), Sort("/reported.id")]
# Default sort order for history searches
HistorySort = [Sort("/changed_at"), Sort("/reported.kind"), Sort("/reported.name"), Sort("/reported.id")]


class CLI:
    """
    The CLI has a defined set of dependencies and knows a list if commands.
    A string can be parsed into a command line that can be executed based on the list of available commands.
    """

    def __init__(
        self, dependencies: CLIDependencies, parts: List[CLICommand], env: Dict[str, Any], alias_names: Dict[str, str]
    ):
        dependencies.extend(cli=self)
        alias_templates_list = [AliasTemplate.from_config(cmd) for cmd in dependencies.config.custom_commands.commands]
        alias_templates = {a.name: a for a in alias_templates_list}
        help_cmd = HelpCommand(dependencies, parts, alias_names, alias_templates)
        cmds = {p.name: p for p in parts + [help_cmd]}
        alias_cmds = {alias: cmds[name] for alias, name in alias_names.items() if name in cmds and alias not in cmds}
        self.direct_commands = cmds
        self.alias_commands = alias_cmds
        self.commands: Dict[str, CLICommand] = {**cmds, **alias_cmds}
        self.cli_env = env
        self.dependencies = dependencies
        self.alias_names = alias_names
        self.alias_templates = alias_templates
        self.reaper: Optional[Task[None]] = None

    def register_worker_custom_command(self, command: WorkerCustomCommand) -> None:
        """
        Called when a worker connects that introduces a custom command.
        The registered templated will always override any existing template.
        """
        if command.name not in self.direct_commands and command.name not in self.alias_commands:
            template = command.to_template()
            self.alias_templates[template.name] = template

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

        await self.dependencies.stop()

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

    def command(self, name: str, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> ExecutableCommand:
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
                action = command.parse(arg, ctx, cmd_name=name)
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
                "".join(query_part), None, omit_section_expansion=True, **ctx.env
            )

        query: Query = Query.by(AllTerm())
        additional_commands: List[ExecutableCommand] = []
        # We need to remember the first head/tail, since tail will reverse the sort order
        first_head_tail_in_a_row: Optional[CLICommand] = None
        head_tail_keep_order = True
        for command in commands:
            part = command.command
            arg = command.arg if command.arg else ""
            if isinstance(part, SearchPart):
                query = query.combine(await parse_query(arg))
            elif isinstance(part, HistoryPart):
                parsed_options["history"] = True
                query = query.combine(await parse_query(arg))
                if not query.current_part.sort and not query.aggregate:
                    query = query.set_sort(*HistorySort)
            elif isinstance(part, SortPart):
                if query.current_part.sort == DefaultSort:
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
            elif isinstance(part, AggregatePart):
                group_vars, group_function_vars = aggregate_parameter_parser.parse(arg)
                query = evolve(query, aggregate=Aggregate(group_vars, group_function_vars))
            elif isinstance(part, CountCommand):
                # count command followed by a query: make it an aggregation
                # since the output of aggregation is not exactly the same as count
                # we also add the aggregate_to_count command after the query
                assert query.aggregate is None, "Can not combine aggregate and count!"
                group_by_var = [AggregateVariable(AggregateVariableName(arg), "name")] if arg else []
                aggregate = Aggregate(group_by_var, [AggregateFunction("sum", 1, [], "count")])
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
                    p = p if p.sort else evolve(p, sort=DefaultSort)
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
            parts = [pt if pt.sort else evolve(pt, sort=DefaultSort) for pt in query.parts]
            query = evolve(query, parts=parts)

        # If the last part is a navigation, we need to add sort which will ingest a new part.
        with_sort = query.set_sort(*DefaultSort) if query.current_part.navigation else query
        # When all parts are combined, interpret the result on defined section.
        final_query = with_sort.on_section(ctx.env.get("section", PathRoot))
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
                ctx_wq = evolve(ctx, query=query, query_options=options)
                # re-evaluate remaining commands - to take the adapted context into account
                remaining = [self.command(c.name, c.arg, ctx_wq) for c in commands[len(parts) :]]  # noqa: E203
                return ctx_wq, [*query_parts, *remaining]
            return ctx, commands

        def adjust_context(parsed: ParsedCommands) -> CLIContext:
            cmd_env = {**self.cli_env, **context.env, **parsed.env}
            ctx = evolve(context, env=cmd_env)
            last_command = self.commands.get(parsed.commands[-1].cmd) if parsed.commands else None
            if isinstance(last_command, NoTerminalOutput) and ctx.console_renderer:
                return evolve(ctx, env=cmd_env, console_renderer=ConsoleRenderer.default_renderer())
            else:
                return evolve(context, env=cmd_env)

        async def parse_line(parsed: ParsedCommands) -> ParsedCommandLine:
            ctx = adjust_context(parsed)
            ctx, commands = await combine_query_parts([self.command(c.cmd, c.args, ctx) for c in parsed.commands], ctx)
            not_met = [r for cmd in commands for r in cmd.action.required if r.name not in context.uploaded_files]
            envelope = {k: v for cmd in commands for k, v in cmd.action.envelope.items()}
            return ParsedCommandLine(ctx, parsed, commands, not_met, envelope)

        def expand_aliases(line: ParsedCommands) -> ParsedCommands:
            def expand_alias(alias_cmd: ParsedCommand) -> List[ParsedCommand]:
                alias: AliasTemplate = self.alias_templates[alias_cmd.cmd]
                props: Dict[str, JsonElement] = self.replacements(**{**self.cli_env, **context.env})  # type: ignore
                props["args"] = alias_cmd.args
                for p in alias.parameters:
                    props[p.name] = p.default
                # only parse properties, if there are any declared
                if alias.parameters:
                    props.update(key_values_parser.parse(alias_cmd.args or ""))
                undefined = [k for k, v in props.items() if k != "args" and v is None]
                if undefined:
                    raise AttributeError(f"Alias {alias_cmd.cmd} missing attributes: {', '.join(undefined)}")
                rendered = alias.render(props)
                log.debug(f"The rendered alias template is: {rendered}")
                return single_commands.parse(rendered)  # type: ignore

            result: List[ParsedCommand] = []
            for cmd in line.commands:
                if cmd.cmd in self.alias_templates:
                    result.extend(expand_alias(cmd))
                else:
                    result.append(cmd)

            return ParsedCommands(result, line.env)

        async def send_analytics(parsed: List[ParsedCommands], raw: List[ParsedCommands]) -> None:
            command_names = [cmd.cmd for line in parsed for cmd in line.commands]
            used_aliases = [cmd.cmd for line in raw for cmd in line.commands if cmd.cmd in self.alias_templates]
            resoto_session_id = context.env.get("resoto_session_id")
            await self.dependencies.event_sender.core_event(
                CoreEvent.CLICommand,
                {
                    "command_names": command_names,
                    "used_aliases": used_aliases,
                    "session_id": resoto_session_id,
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
        keep_raw = not replace_place_holder or JobsCommand.is_jobs_update(command_lines[0].commands[0])
        command_lines = command_lines if keep_raw else [replace_placeholders(cmd_line) for cmd_line in command_lines]
        res = [await parse_line(cmd_line) for cmd_line in command_lines]
        return res

    async def execute_cli_command(self, cli_input: str, sink: Sink[T], ctx: CLIContext = EmptyContext) -> List[Any]:
        return [await parsed.to_sink(sink) for parsed in await self.evaluate_cli_command(cli_input, ctx, True)]

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
