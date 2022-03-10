import asyncio
from datetime import timedelta
from typing import Optional, AsyncIterator

import yaml

from resotocore.config import ConfigHandler, ConfigEntity, ConfigValidation
from resotocore.db.configdb import ConfigEntityDb, ConfigValidationEntityDb
from resotocore.model.model import Model
from resotocore.types import Json
from resotocore.util import uuid_str
from resotocore.worker_task_queue import WorkerTaskQueue, WorkerTask, WorkerTaskName


class ConfigHandlerService(ConfigHandler):
    def __init__(
        self, cfg_db: ConfigEntityDb, validation_db: ConfigValidationEntityDb, task_queue: WorkerTaskQueue
    ) -> None:
        self.cfg_db = cfg_db
        self.validation_db = validation_db
        self.task_queue = task_queue

    async def coerce_and_check_model(self, cfg_id: str, config: Json) -> Json:
        validation = await self.validation_db.get(cfg_id)
        kind = validation.complex_root() if validation else None
        # If model is given, check and coerce the existing model.
        # In case the config is invalid, this method will throw.
        if kind:
            coerced = kind.check_valid(config)
            config = coerced or config

        # If an external entity needs to approve this change.
        # Method throws if config is not valid according to external approval.
        if validation.external_validation:
            await self.acknowledge_config_change(cfg_id, config)

        # If we come here, everything is fine
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
        await self.validation_db.delete(cfg_id)

    def list_config_validation_ids(self) -> AsyncIterator[str]:
        return self.validation_db.keys()

    async def get_config_validation(self, cfg_id: str) -> Optional[ConfigValidation]:
        return await self.validation_db.get(cfg_id)

    async def put_config_validation(self, validation: ConfigValidation) -> ConfigValidation:
        # make sure there is a complex kind with name "config"
        if validation.kinds:
            model = Model.from_kinds(validation.kinds)
            roots = model.complex_roots
            if len(roots) != 1:
                root_names = ", ".join(r.fqn for r in roots)
                raise AttributeError(f"Require exactly one config root kind, but got: {root_names}")
        return await self.validation_db.update(validation)

    async def config_yaml(self, cfg_id: str) -> Optional[str]:
        config = await self.get_config(cfg_id)
        if config:
            validation = await self.validation_db.get(cfg_id)
            kind = validation.complex_root() if validation else None
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
