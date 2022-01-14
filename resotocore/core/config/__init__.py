from attr import dataclass

from core.types import Json


@dataclass
class ConfigEntity:
    id: str
    config: Json
