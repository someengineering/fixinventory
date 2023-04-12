from typing import List, Any, AsyncIterator, AsyncGenerator
from resotocore.infra_apps.runtime import AppResult, Success, Failure
from resotocore.infra_apps.manifest import AppManifest
from resotocore.types import Json, JsonElement
from resotocore.db.model import QueryModel
from resotocore.cli.model import CLI
from jinja2 import Environment
import logging
from aiostream import stream
from argparse import Namespace

log = logging.getLogger(__name__)


class LocalResotocoreAppRuntime:
    """
    Runtime implementation that runs the Infrastructure Apps directly on the resotocore.
    Currently, only the Jinja2 language is supported.
    """

    def __init__(self, cli: CLI) -> None:
        self.cli = cli
        self.graphdb = cli.dependencies.db_access.get_graph_db(cli.env["graph"])
        self.model_handler = cli.dependencies.model_handler
        self.template_expander = cli.dependencies.template_expander

    async def execute(
        self, manifest: AppManifest, config: Json, stdin: AsyncGenerator[JsonElement, None], kwargs: Namespace
    ) -> AppResult:
        """
        Runtime implementation that runs the app locally.
        """
        try:
            result = []
            async for line in self._generate_template(manifest, config, stdin, kwargs):
                result = await self._interpret_line(line)

            return Success(output=result)

        except Exception as e:
            msg = f"Error running infrastructure app: {e}"
            log.exception(msg)
            return Failure(error=msg)

    async def _generate_template(
        self, manifest: AppManifest, config: Json, stdin: AsyncGenerator[JsonElement, None], kwargs: Namespace
    ) -> AsyncIterator[str]:
        env = Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"], enable_async=True)
        template = env.from_string(manifest.source)
        template.globals["args"] = kwargs
        template.globals["stdin"] = stdin
        template.globals["config"] = config

        model = await self.model_handler.load_model()

        async def perform_search(search: str) -> AsyncIterator[Json]:
            # parse query
            query = await self.template_expander.parse_query(search, on_section="reported")
            async with await self.graphdb.search_list(QueryModel(query, model)) as ctx:
                async for result in ctx:
                    yield result

        template.globals["search"] = perform_search

        async for line in template.generate_async(config=config, *kwargs._get_kwargs()):
            log.debug(f"Rendered infrastructure app line: {line}")
            line = line.strip()
            if not line:
                continue
            yield line

    async def _interpret_line(self, line: str) -> List[Any]:
        return await self.cli.execute_cli_command(line, stream.list)
