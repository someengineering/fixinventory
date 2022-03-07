from typing import Optional, AsyncIterator, List

import yaml

from resotocore.config import ConfigHandler, ConfigEntity, ConfigModel
from resotocore.db.configdb import ConfigEntityDb, ConfigModelEntityDb
from resotocore.model.model import Kind, Model, ComplexKind
from resotocore.types import Json


class ConfigHandlerService(ConfigHandler):
    def __init__(self, cfg_db: ConfigEntityDb, model_db: ConfigModelEntityDb) -> None:
        self.cfg_db = cfg_db
        self.model_db = model_db

    async def config_kind(self, cfg_id: str) -> Optional[ComplexKind]:
        config_model = await self.model_db.get(cfg_id)
        if config_model:
            model = Model.from_kinds(config_model.kinds)
            if model.complex_roots:
                return model.complex_roots[0]
        return None

    async def coerce_and_check_model(self, cfg_id: str, config: Json) -> Json:
        kind = await self.config_kind(cfg_id)
        # throws if config is not valid
        return kind.check_valid(config) or config if kind else config

    def list_config_ids(self) -> AsyncIterator[str]:
        return self.cfg_db.keys()

    async def get_config(self, cfg_id: str) -> Optional[ConfigEntity]:
        return await self.cfg_db.get(cfg_id)

    async def put_config(self, cfg_id: str, config: Json) -> ConfigEntity:
        coerced = await self.coerce_and_check_model(cfg_id, config)
        return await self.cfg_db.update(ConfigEntity(cfg_id, coerced))

    async def patch_config(self, cfg_id: str, config: Json) -> ConfigEntity:
        current = await self.cfg_db.get(cfg_id)
        current_config = current.config if current else {}
        coerced = await self.coerce_and_check_model(cfg_id, {**current_config, **config})
        return await self.cfg_db.update(ConfigEntity(cfg_id, coerced))

    async def delete_config(self, cfg_id: str) -> None:
        await self.cfg_db.delete(cfg_id)
        await self.model_db.delete(cfg_id)

    def list_config_model_ids(self) -> AsyncIterator[str]:
        return self.model_db.keys()

    async def get_config_model(self, cfg_id: str) -> Optional[ConfigModel]:
        return await self.model_db.get(cfg_id)

    async def put_config_model(self, cfg_id: str, kinds: List[Kind]) -> ConfigModel:
        # make sure there is a complex kind with name "config"
        model = Model.from_kinds(kinds)
        roots = model.complex_roots
        if len(roots) != 1:
            root_names = ", ".join(r.fqn for r in roots)
            raise AttributeError(f"Require exactly one config root kind, but got: {root_names}")
        return await self.model_db.update(ConfigModel(cfg_id, kinds))

    async def config_yaml(self, cfg_id: str) -> Optional[str]:
        config = await self.get_config(cfg_id)
        if config:
            kind = await self.config_kind(cfg_id)
            return kind.create_yaml(config.config) if kind else yaml.dump(config.config, default_flow_style=False)
        else:
            return None
