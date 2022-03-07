from typing import Optional, AsyncIterator

from resotocore.config import ConfigHandler, ConfigEntity
from resotocore.db.configdb import ConfigEntityDb
from resotocore.types import Json


class ConfigHandlerService(ConfigHandler):
    def __init__(self, db: ConfigEntityDb) -> None:
        self.db = db

    async def list_config_ids(self) -> AsyncIterator[str]:
        return self.db.keys()

    async def get_config(self, cfg_id: str) -> Optional[ConfigEntity]:
        return await self.db.get(cfg_id)

    async def put_config(self, cfg_id: str, config: Json) -> ConfigEntity:
        return await self.db.update(ConfigEntity(cfg_id, config))

    async def patch_config(self, cfg_id: str, config: Json) -> ConfigEntity:
        current = await self.db.get(cfg_id)
        current_config = current.config if current else {}
        return await self.db.update(ConfigEntity(cfg_id, {**current_config, **config}))

    async def delete_config(self, cfg_id: str) -> None:
        return await self.db.delete(cfg_id)
