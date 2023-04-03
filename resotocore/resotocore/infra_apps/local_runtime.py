from typing import Dict, List, Any, AsyncIterator
from resotocore.infra_apps.runtime import AppResult, Success, Failure
from resotocore.infra_apps.manifest import AppManifest
from resotocore.types import Json, JsonElement
from resotocore.cli.model import CLI
from jinja2 import Environment
import logging
from aiostream import stream


log = logging.getLogger(__name__)


class LocalResotocoreAppRuntime:
    """
    Runtime implementation that runs the Infrastructure Apps directly on the resotocore.
    Currently, only the Jinja2 language is supported.
    """

    def __init__(self, cli: CLI) -> None:
        self.cli = cli

    async def execute(
        self, manifest: AppManifest, config: Json, stdin: JsonElement, kwargs: Dict[str, Any]
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
        self, manifest: AppManifest, config: Json, stdin: JsonElement, kwargs: Dict[str, Any]
    ) -> AsyncIterator[str]:
        env = Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"], enable_async=True)
        template = env.from_string(manifest.source)
        # template.globals["search"] = self.cg.search

        async for line in template.generate_async(config=config, **kwargs):
            log.debug(f"Rendered infrastructure app line: {line}")
            line = line.strip()
            if not line:
                continue
            yield line

    async def _interpret_line(self, line: str) -> List[Any]:
        return await self.cli.execute_cli_command(line, stream.list)
