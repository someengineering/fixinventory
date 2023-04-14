from typing import List, AsyncIterator
from resotocore.infra_apps.runtime import Runtime
from resotocore.infra_apps.manifest import AppManifest
from resotocore.types import Json, JsonElement
from resotocore.db.model import QueryModel
from resotocore.cli.model import CLI, CLIContext
from jinja2 import Environment
import logging
from aiostream.core import Stream
from aiostream import stream
from argparse import Namespace
from resotolib.durations import parse_duration


log = logging.getLogger(__name__)


class LocalResotocoreAppRuntime(Runtime):
    """
    Runtime implementation that runs the Infrastructure Apps directly on the resotocore.
    Currently, only the Jinja2 language is supported.
    """

    def __init__(self, cli: CLI) -> None:
        self.cli = cli
        self.dbaccess = cli.dependencies.db_access
        self.model_handler = cli.dependencies.model_handler
        self.template_expander = cli.dependencies.template_expander

    async def execute(
        self,
        graph: str,
        manifest: AppManifest,
        config: Json,
        stdin: AsyncIterator[JsonElement],
        kwargs: Namespace,
        ctx: CLIContext,
    ) -> AsyncIterator[JsonElement]:
        """
        Runtime implementation that runs the app locally.
        """
        try:
            async for line in self.generate_template(graph, manifest, config, stdin, kwargs):
                async with (await self._interpret_line(line, ctx)).stream() as streamer:
                    async for item in streamer:
                        yield item

        except Exception as e:
            msg = f"Error running infrastructure app: {e}"
            log.exception(msg)

    async def generate_template(
        self,
        graph: str,
        manifest: AppManifest,
        config: Json,
        stdin: AsyncIterator[JsonElement],
        kwargs: Namespace,
    ) -> AsyncIterator[str]:
        graphdb = self.dbaccess.get_graph_db(graph)
        env = Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"], enable_async=True)
        template = env.from_string(manifest.source)
        template.globals["args"] = kwargs
        template.globals["stdin"] = stdin
        template.globals["config"] = config
        template.globals["parse_duration"] = parse_duration

        model = await self.model_handler.load_model()

        async def perform_search(search: str) -> AsyncIterator[Json]:
            # parse query
            query = await self.template_expander.parse_query(search, on_section="reported")
            async with await graphdb.search_list(QueryModel(query, model)) as ctx:
                async for result in ctx:
                    yield result

        template.globals["search"] = perform_search

        async for line in template.generate_async(config=config, *kwargs._get_kwargs()):
            log.debug(f"Rendered infrastructure app line: {line}")
            line = line.strip()
            if not line:
                continue
            yield line

    async def _interpret_line(self, line: str, ctx: CLIContext) -> Stream:
        command_streams: List[Stream] = []
        total_nr_outputs: int = 0
        parsed_commands = await self.cli.evaluate_cli_command(line, ctx, True)
        for parsed in parsed_commands:
            nr_outputs, command_output_stream = await parsed.execute()
            total_nr_outputs = total_nr_outputs + (nr_outputs or 0)
            command_streams.append(command_output_stream)

        return stream.concat(stream.iterate(command_streams), task_limit=1)
