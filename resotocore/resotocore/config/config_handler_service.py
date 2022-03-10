import asyncio
from datetime import timedelta
from typing import Optional, AsyncIterator, List

import yaml

from resotocore.config import ConfigHandler, ConfigEntity, ConfigModel
from resotocore.db.configdb import ConfigEntityDb, ConfigModelEntityDb
from resotocore.model.model import Kind, Model
from resotocore.types import Json
from resotocore.util import uuid_str
from resotocore.worker_task_queue import WorkerTaskQueue, WorkerTask, WorkerTaskName


class ConfigHandlerService(ConfigHandler):
    def __init__(self, cfg_db: ConfigEntityDb, model_db: ConfigModelEntityDb, task_queue: WorkerTaskQueue) -> None:
        self.cfg_db = cfg_db
        self.model_db = model_db
        self.task_queue = task_queue

    async def coerce_and_check_model(self, cfg_id: str, config: Json) -> Json:
        model = await self.model_db.get(cfg_id)
        kind = model.complex_root if model else None
        if kind:
            # throws if config is not valid according to schema
            coerced = kind.check_valid(config)
            coerced = coerced or config
            # throws if config is not valid according to external approval
            await self.acknowledge_config_change(cfg_id, config)
            return coerced
        else:
            return config

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
            model = await self.model_db.get(cfg_id)
            kind = model.complex_root if model else None
            return kind.create_yaml(config.config) if kind else yaml.dump(config.config, default_flow_style=False)
        else:
            return None

    async def acknowledge_config_change(self, cfg_id: str, config: Json) -> None:
        """
        In case an external entity should acknowledge this config change.
        This method either return, which signals success or throws an exception.
        """
        future = asyncio.get_event_loop().create_future()
        task = WorkerTask(
            uuid_str(),
            WorkerTaskName.validate_config,
            {"config_id": cfg_id},
            {"task": WorkerTaskName.validate_config, "config": config},
            future,
            timedelta(seconds=30),
        )
        # add task to queue - do not retry
        await self.task_queue.add_task(task)
        # In case the config is not valid or no worker is available
        # this future will throw an exception.
        # Do not handle it here and let the error bubble up.
        await future
