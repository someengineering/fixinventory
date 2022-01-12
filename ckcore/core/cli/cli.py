from __future__ import annotations

import asyncio
import calendar
import logging
from asyncio import Task
from dataclasses import replace
from datetime import timedelta, datetime
from functools import reduce
from typing import Dict, List, Tuple
from typing import Optional, Any

from aiostream import stream
from aiostream.core import Stream
from itertools import takewhile
from parsy import Parser
from tzlocal import get_localzone

from core.analytics import CoreEvent
from core.cli import cmd_with_args_parser, key_values_parser, T, Sink
from core.cli.command import (
    QueryAllPart,
    ReportedPart,
    DesiredPart,
    MetadataPart,
    PredecessorPart,
    SuccessorPart,
    AncestorPart,
    DescendantPart,
    AggregatePart,
    MergeAncestorsPart,
    CountCommand,
    HeadCommand,
    TailCommand,
    QueryPart,
    ExecuteQueryCommand,
    JobsCommand,
)
from core.cli.model import (
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
)
from core.error import CLIParseError
from core.model.graph_access import Section
from core.model.typed_model import class_fqn
from core.parse_util import (
    make_parser,
    pipe_p,
    semicolon_p,
)
from core.query.model import (
    Query,
    Navigation,
    AllTerm,
    Aggregate,
    AggregateVariable,
    AggregateVariableName,
    AggregateFunction,
    SortOrder,
)
from core.query.query_parser import aggregate_parameter_parser
from core.util import utc_str, utc, from_utc

log = logging.getLogger(__name__)


@make_parser
def single_command_parser() -> Parser:
    parsed = yield cmd_with_args_parser
    cmd_args = [a.strip() for a in parsed.strip().split(" ", 1)]
    cmd, args = cmd_args if len(cmd_args) == 2 else (cmd_args[0], None)
    return ParsedCommand(cmd, args)


@make_parser
def command_line_parser() -> Parser:
    maybe_env = yield key_values_parser.optional()
    commands = yield single_command_parser.sep_by(pipe_p, min=1)
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

    def __init__(self, dependencies: CLIDependencies, parts: List[CLICommand], aliases: Dict[str, str]):
        super().__init__(dependencies)
        self.all_parts = {p.name: p for p in parts + [self]}
        self.parts = {p.name: p for p in parts + [self] if not isinstance(p, InternalPart)}
        self.aliases = {a: n for a, n in aliases.items() if n in self.parts and a not in self.parts}

    @property
    def name(self) -> str:
        return "help"

    def info(self) -> str:
        return "Shows available commands, as well as help for any specific command."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        def help_command() -> Stream:
            def show_cmd(cmd: CLICommand) -> str:
                return f"{cmd.name} - {cmd.info()}\n\n{cmd.help()}"

            if not arg:
                all_parts = sorted(self.parts.values(), key=lambda p: p.name)
                parts = (p for p in all_parts if isinstance(p, CLICommand))
                available = "\n".join(f"   {part.name} - {part.info()}" for part in parts)
                aliases = "\n".join(
                    f"   {alias} ({cmd}) - {self.parts[cmd].info()}" for alias, cmd in self.aliases.items()
                )
                replacements = "\n".join(f"   @{key}@ -> {value}" for key, value in CLI.replacements().items())
                result = (
                    f"\nckcore CLI\n\n\n"
                    f"Valid placeholder string:\n{replacements}\n\n"
                    f"Available Commands:\n{available}\n\n"
                    f"Available Aliases:\n{aliases}\n\n"
                    f"Note that you can pipe commands using the pipe character (|)\n"
                    f"and chain multiple commands using the semicolon (;)."
                )
            elif arg and arg in self.all_parts:
                result = show_cmd(self.all_parts[arg])
            elif arg and arg in self.aliases:
                alias = self.aliases[arg]
                explain = f"{arg} is an alias for {alias}\n\n"
                result = explain + show_cmd(self.all_parts[alias])
            else:
                result = f"No command found with this name: {arg}"

            return stream.just(result)

        return CLISource.single(help_command)


CLIArg = Tuple[CLICommand, Optional[str]]


class CLI:
    """
    The CLI has a defined set of dependencies and knows a list if commands.
    A string can be parsed into a command line that can be executed based on the list of available commands.
    """

    def __init__(
        self, dependencies: CLIDependencies, parts: List[CLICommand], env: Dict[str, Any], aliases: Dict[str, str]
    ):
        dependencies.extend(cli=self)
        help_cmd = HelpCommand(dependencies, parts, aliases)
        cmds = {p.name: p for p in parts + [help_cmd]}
        alias_cmds = {alias: cmds[name] for alias, name in aliases.items() if name in cmds and alias not in cmds}
        self.commands: Dict[str, CLICommand] = {**cmds, **alias_cmds}
        self.cli_env = env
        self.dependencies = dependencies
        self.aliases = aliases
        self.reaper: Optional[Task[None]] = None

    async def start(self) -> None:
        self.reaper = asyncio.create_task(self.reap_tasks())

    async def stop(self) -> None:
        if self.reaper:
            self.reaper.cancel()
            await asyncio.gather(self.reaper, return_exceptions=True)

        while not self.dependencies.forked_tasks.empty():
            task, _ = self.dependencies.forked_tasks.get_nowait()
            task.cancel()

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
            raise CLIParseError(f"Command >{name}< is not known. typo?")

    async def create_query(
        self, commands: List[ExecutableCommand], ctx: CLIContext
    ) -> Tuple[Query, Dict[str, Any], List[ExecutableCommand]]:
        """
        Takes a list of query part commands and combine them to a single executable query command.
        This process can also introduce new commands that should run after the query is finished.
        Therefore, a list of executable commands is returned.
        :param commands: the incoming executable commands, which actions are all instances of QueryPart.
        :param ctx: the context to execute within.
        :return: the resulting list of commands to execute.
        """

        # Pass parsed options to execute query
        # Multiple query commands are possible - so the dict is combined with every parsed query.
        parsed_options: Dict[str, Any] = {}

        async def parse_query(query_arg: str) -> Query:
            nonlocal parsed_options
            parsed, query_part = ExecuteQueryCommand.parse_known(query_arg)
            parsed_options = {**parsed_options, **parsed}
            return await self.dependencies.template_expander.parse_query("".join(query_part))

        query: Query = Query.by(AllTerm())
        additional_commands: List[ExecutableCommand] = []
        for command in commands:
            part = command.command
            arg = command.arg if command.arg else ""
            if isinstance(part, QueryAllPart):
                query = query.combine(await parse_query(arg))
            elif isinstance(part, ReportedPart):
                query = query.combine((await parse_query(arg)).on_section(Section.reported))
            elif isinstance(part, DesiredPart):
                query = query.combine((await parse_query(arg)).on_section(Section.desired))
            elif isinstance(part, MetadataPart):
                query = query.combine((await parse_query(arg)).on_section(Section.metadata))
            elif isinstance(part, PredecessorPart):
                origin, edge = PredecessorPart.parse_args(arg)
                query = query.traverse_in(origin, 1, edge)
            elif isinstance(part, SuccessorPart):
                origin, edge = PredecessorPart.parse_args(arg)
                query = query.traverse_out(origin, 1, edge)
            elif isinstance(part, AncestorPart):
                origin, edge = PredecessorPart.parse_args(arg)
                query = query.traverse_in(origin, Navigation.Max, edge)
            elif isinstance(part, DescendantPart):
                origin, edge = PredecessorPart.parse_args(arg)
                query = query.traverse_out(origin, Navigation.Max, edge)
            elif isinstance(part, AggregatePart):
                group_vars, group_function_vars = aggregate_parameter_parser.parse(arg)
                query = replace(query, aggregate=Aggregate(group_vars, group_function_vars))
            elif isinstance(part, MergeAncestorsPart):
                query = replace(query, preamble={**query.preamble, **{"merge_with_ancestors": arg}})
            elif isinstance(part, CountCommand):
                # count command followed by a query: make it an aggregation
                # since the output of aggregation is not exactly the same as count
                # we also add the aggregate_to_count command after the query
                assert query.aggregate is None, "Can not combine aggregate and count!"
                group_by = [AggregateVariable(AggregateVariableName(arg), "name")] if arg else []
                aggregate = Aggregate(group_by, [AggregateFunction("sum", 1, [], "count")])
                # If the query should be explained, we want the output as is
                if "explain" not in parsed_options:
                    additional_commands.append(self.command("aggregate_to_count", None, ctx))
                query = replace(query, aggregate=aggregate)
                query = query.add_sort("count")
            elif isinstance(part, HeadCommand):
                size = HeadCommand.parse_size(arg)
                query = query.with_limit(size)
            elif isinstance(part, TailCommand):
                size = HeadCommand.parse_size(arg)
                if not query.current_part.sort:
                    query = query.add_sort("_key", SortOrder.Desc)
                query = query.with_limit(size)
            else:
                raise AttributeError(f"Do not understand: {part} of type: {class_fqn(part)}")

        options = ExecuteQueryCommand.argument_string(parsed_options)
        query_string = str(query)
        execute_query = self.command("execute_query", options + query_string, ctx)
        return query, parsed_options, [execute_query, *additional_commands]

    async def evaluate_cli_command(
        self, cli_input: str, context: CLIContext = EmptyContext, replace_place_holder: bool = True
    ) -> List[ParsedCommandLine]:
        async def combine_query_parts(
            commands: List[ExecutableCommand], ctx: CLIContext
        ) -> Tuple[CLIContext, List[ExecutableCommand]]:
            parts = list(takewhile(lambda x: isinstance(x.command, QueryPart), commands))
            if parts:
                query, options, query_parts = await self.create_query(parts, ctx)
                ctx_wq = replace(ctx, query=query, query_options=options)
                # re-evaluate remaining commands - to take the adapted context into account
                remaining = [self.command(c.name, c.arg, ctx_wq) for c in commands[len(parts) :]]  # noqa: E203
                return ctx_wq, [*query_parts, *remaining]
            return ctx, commands

        async def parse_line(parsed: ParsedCommands) -> ParsedCommandLine:
            cmd_env = {**self.cli_env, **context.env, **parsed.env}
            ctx = replace(context, env=cmd_env)
            ctx, commands = await combine_query_parts([self.command(c.cmd, c.args, ctx) for c in parsed.commands], ctx)
            not_met = [r for cmd in commands for r in cmd.action.required if r.name not in context.uploaded_files]
            return ParsedCommandLine(ctx, parsed, commands, not_met)

        async def send_analytics(parsed: List[ParsedCommandLine]) -> None:
            command_names = [cmd.cmd for line in parsed for cmd in line.parsed_commands.commands]
            ck_session_id = context.env.get("ck_session_id")
            await self.dependencies.event_sender.core_event(
                CoreEvent.CLICommand,
                {"command_names": command_names, "session_id": ck_session_id},
                command_lines=len(parsed),
                commands=len(command_names),
            )

        replaced = self.replace_placeholder(cli_input, **context.env)
        command_lines: List[ParsedCommands] = multi_command_parser.parse(replaced)
        keep_raw = not replace_place_holder or JobsCommand.is_jobs_update(command_lines[0].commands[0])
        command_lines = multi_command_parser.parse(cli_input) if keep_raw else command_lines
        res = [await parse_line(cmd_line) for cmd_line in command_lines]
        await send_analytics(res)
        return res

    async def execute_cli_command(self, cli_input: str, sink: Sink[T], ctx: CLIContext = EmptyContext) -> List[Any]:
        return [await parsed.to_sink(sink) for parsed in await self.evaluate_cli_command(cli_input, ctx, True)]

    @staticmethod
    def replacements(**env: str) -> Dict[str, str]:
        now_string = env.get("now")
        ut = from_utc(now_string) if now_string else utc()
        t = ut.date()
        try:
            n = datetime.now(get_localzone())
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
