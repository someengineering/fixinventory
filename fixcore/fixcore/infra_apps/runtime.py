from typing import Union, List, Any, AsyncIterator
from fixcore.infra_apps.manifest import AppManifest
from fixcore.types import JsonElement, Json
from fixcore.ids import GraphName
from attrs import frozen
from abc import ABC, abstractmethod


@frozen
class Failure:
    error: str


@frozen
class Success:
    output: List[Any]


AppResult = Union[Failure, Success]


class Runtime(ABC):
    """
    Runtime is the interface to run an infrastructure app.
    """

    @abstractmethod
    async def execute(
        self,
        graph: GraphName,
        manifest: AppManifest,
        config: Json,
        stdin: AsyncIterator[JsonElement],
        argv: List[str],
        ctx: Any,  # CLIContext, but here we use Any to avoid circular dependency
    ) -> AsyncIterator[JsonElement]:
        """
        Executes the infrastructure app."""
        yield None

    @abstractmethod
    async def generate_template(
        self,
        graph: GraphName,
        manifest: AppManifest,
        config: Json,
        stdin: AsyncIterator[JsonElement],
        argv: List[str],
    ) -> AsyncIterator[str]:
        """
        Generates the template for the infrastructure app. Does not execute any commands
        """
        yield ""
