from abc import ABC, abstractmethod
from typing import Optional, AsyncIterator, List

from dataclasses import dataclass

from resotocore.model.model import Kind
from resotocore.types import Json


@dataclass(order=True, unsafe_hash=True, frozen=True)
class ConfigEntity:
    id: str
    config: Json


@dataclass(order=True, unsafe_hash=True, frozen=True)
class ConfigModel:
    id: str
    kinds: List[Kind]


class ConfigHandler(ABC):
    @abstractmethod
    def list_config_ids(self) -> AsyncIterator[str]:
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

    @abstractmethod
    def list_config_model_ids(self) -> AsyncIterator[str]:
        pass

    @abstractmethod
    async def get_config_model(self, cfg_id: str) -> Optional[ConfigModel]:
        pass

    @abstractmethod
    async def put_config_model(self, cfg_id: str, kinds: List[Kind]) -> ConfigModel:
        pass

    @abstractmethod
    async def config_yaml(self, cfg_id: str) -> Optional[str]:
        pass
