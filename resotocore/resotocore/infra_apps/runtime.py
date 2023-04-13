from typing import Awaitable, Callable, Union, Dict, List, Any, AsyncGenerator, AsyncIterator
from resotocore.infra_apps.manifest import AppManifest
from resotocore.types import JsonElement, Json
from attrs import frozen
from abc import ABC, abstractmethod
from argparse import Namespace


@frozen
class Failure:
    error: str


@frozen
class Success:
    output: List[Any]


AppResult = Union[Failure, Success]

# Interface to run an infrastructure app.
AppRunner = Callable[[AppManifest, Json, Dict[str, Any]], Awaitable[AppResult]]


class Runtime(ABC):
    """
    Runtime is the interface to run an infrastructure app.
    """

    @abstractmethod
    async def execute(
        self, manifest: AppManifest, config: Json, stdin: AsyncGenerator[JsonElement, None], kwargs: Namespace
    ) -> AppResult:
        """
        Executes the infrastructure app."""

    @abstractmethod
    async def generate_template(
        self, manifest: AppManifest, config: Json, stdin: AsyncGenerator[JsonElement, None], kwargs: Namespace
    ) -> AsyncIterator[str]:
        """
        Generates the template for the infrastructure app. Does not execute any commands
        """
