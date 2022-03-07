from abc import ABC, abstractmethod
from typing import Optional, AsyncIterator

from dataclasses import dataclass

from resotocore.types import Json


@dataclass(order=True, unsafe_hash=True, frozen=True)
class ConfigEntity:
    id: str
    config: Json


class ConfigHandler(ABC):
    @abstractmethod
    async def list_config_ids(self) -> AsyncIterator[str]:
        pass

    @abstractmethod
    async def get_config(self, cfg_id: str) -> Optional[ConfigEntity]:
        pass

    @abstractmethod
    async def put_config(self, cfg_id: str, config: Json) -> ConfigEntity:
        pass

    @abstractmethod
    async def patch_config(self, cfg_id: str, config: Json) -> ConfigEntity:
        pass

    @abstractmethod
    async def delete_config(self, cfg_id: str) -> None:
        pass
