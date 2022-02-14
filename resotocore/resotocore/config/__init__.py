from attr import dataclass

from resotocore.types import Json


@dataclass
class ConfigEntity:
    id: str
    config: Json
