from typing import Awaitable, Callable, Union, Dict, List, Any
from resotocore.infra_apps.manifest import AppManifest
from resotocore.types import Json
from attrs import frozen


@frozen
class Failure:
    error: str


@frozen
class Success:
    output: List[Any]


AppResult = Union[Failure, Success]

# Interface to run an infrastructure app.
AppRunner = Callable[[AppManifest, Json, Dict[str, Any]], Awaitable[AppResult]]
