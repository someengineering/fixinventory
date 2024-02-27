import logging
from argparse import Namespace
from pydoc import locate
from typing import List, AsyncIterator, Type, Optional, Any

from aiostream import stream, pipe
from jinja2 import Environment

from fixcore.cli import NoExitArgumentParser, JsStream, JsGen
from fixcore.cli.model import CLI, CLIContext
from fixcore.db.model import QueryModel
from fixcore.ids import GraphName
from fixcore.infra_apps.manifest import AppManifest
from fixcore.infra_apps.runtime import Runtime
from fixcore.service import Service
from fixcore.types import Json, JsonElement
from fixlib.asynchronous.utils import async_lines
from fixlib.durations import parse_optional_duration

log = logging.getLogger(__name__)


class LocalfixcoreAppRuntime(Runtime, Service):
    """
    Runtime implementation that runs the Infrastructure Apps directly on the fixcore.
    Currently, only the Jinja2 language is supported.
    """

    def __init__(self, cli: CLI) -> None:
        super().__init__()
        self.cli = cli
        self.dbaccess = cli.dependencies.db_access
        self.model_handler = cli.dependencies.model_handler
        self.template_expander = cli.dependencies.template_expander

    async def execute(
        self,
        graph: GraphName,
        manifest: AppManifest,
        config: Json,
        stdin: AsyncIterator[JsonElement],
        argv: List[str],
        ctx: CLIContext,
    ) -> AsyncIterator[JsonElement]:
        """
        Runtime implementation that runs the app locally.
        """
        async for line in self.generate_template(graph, manifest, config, stdin, argv):
            async with (await self._interpret_line(line, ctx)).stream() as streamer:
                async for item in streamer:
                    yield item

    async def generate_template(
        self,
        graph: GraphName,
        manifest: AppManifest,
        config: Json,
        stdin: AsyncIterator[JsonElement],
        argv: List[str],
    ) -> AsyncIterator[str]:
        graphdb = self.dbaccess.get_graph_db(graph)
        env = Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"], enable_async=True)
        template = env.from_string(manifest.source)

        model = await self.model_handler.load_model(graph)

        async def perform_search(search: str) -> AsyncIterator[Json]:
            # parse query
            query = await self.template_expander.parse_query(search, on_section="reported")
            async with await graphdb.search_graph_gen(QueryModel(query, model)) as ctx:
                async for result in ctx:
                    yield result

        template.globals["parse_duration"] = parse_optional_duration
        template.globals["search"] = perform_search

        args = self._args_from_manifest(manifest, argv)

        async for line in async_lines(template.generate_async(config=config, args=args, stdin=stdin)):
            line = line.strip()
            log.debug(f"Rendered infrastructure app line: {line}")
            if not line:
                continue
            yield line

    def _args_from_manifest(self, manifest: AppManifest, argv: Optional[List[str]] = None) -> Namespace:
        args_schema = manifest.args_schema or {}

        parser = NoExitArgumentParser(description=manifest.description)

        def str_to_type(type_str: Optional[str]) -> Optional[Type[Any]]:
            if type_str is None:
                return None
            supported_types = {"bool", "str", "int", "float", "complex"}
            if type_str not in supported_types:
                raise ValueError(f"Unsupported type: {type_str}")
            return locate(type_str)  # type: ignore

        for arg_name, arg_info in args_schema.items():
            kwargs = {}
            for flag in ["help", "action", "default", "type", "nargs", "required"]:
                if flag in arg_info:
                    if flag == "type":
                        kwargs[flag] = str_to_type(arg_info[flag])
                    else:
                        kwargs[flag] = arg_info[flag]
            parser.add_argument(f"--{arg_name}", **kwargs)  # type: ignore

        return parser.parse_args(argv)

    async def _interpret_line(self, line: str, ctx: CLIContext) -> JsStream:
        command_streams: List[JsGen] = []
        total_nr_outputs: int = 0
        parsed_commands = await self.cli.evaluate_cli_command(line, ctx, True)
        for parsed in parsed_commands:
            src_ctx, command_output_stream = await parsed.execute()
            total_nr_outputs = total_nr_outputs + (src_ctx.count or 0)
            command_streams.append(command_output_stream)

        return stream.iterate(command_streams) | pipe.concat(task_limit=1)
