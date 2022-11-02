import asyncio
from datetime import timedelta
from typing import Optional, AsyncIterator, List

import yaml

from resotocore.analytics import AnalyticsEventSender, CoreEvent
from resotocore.config import ConfigHandler, ConfigEntity, ConfigValidation
from resotocore.db.configdb import ConfigEntityDb, ConfigValidationEntityDb
from resotocore.db.modeldb import ModelDb
from resotocore.message_bus import MessageBus, CoreMessage
from resotocore.model.model import Model, Kind, ComplexKind
from resotocore.types import Json
from resotocore.util import uuid_str, deep_merge
from resotocore.worker_task_queue import WorkerTaskQueue, WorkerTask, WorkerTaskName
from resotocore.ids import TaskId, ConfigId


class ConfigHandlerService(ConfigHandler):
    def __init__(
        self,
        cfg_db: ConfigEntityDb,
        validation_db: ConfigValidationEntityDb,
        model_db: ModelDb,
        task_queue: WorkerTaskQueue,
        message_bus: MessageBus,
        event_sender: AnalyticsEventSender,
    ) -> None:
        self.cfg_db = cfg_db
        self.validation_db = validation_db
        self.model_db = model_db
        self.task_queue = task_queue
        self.message_bus = message_bus
        self.event_sender = event_sender

    async def coerce_and_check_model(self, cfg_id: ConfigId, config: Json, validate: bool = True) -> Json:
        model = await self.get_configs_model()

        final_config = {}
        if validate:
            for key, value in config.items():
                if key in model:
                    try:
                        value_kind = model[key]
                        coerced = value_kind.check_valid(value, normalize=False)
                        final_config[key] = value_kind.sort_json(coerced or value)
                    except Exception as ex:
                        raise AttributeError(f"Error validating section {key}: {ex}") from ex
                else:
                    final_config[key] = value
        else:
            final_config = config

        # If an external entity needs to approve this change.
        # Method throws if config is not valid according to external approval.
        validation = await self.validation_db.get(cfg_id)
        if validation and validation.external_validation and validate:
            await self.acknowledge_config_change(cfg_id, final_config)

        # If we come here, everything is fine
        return final_config

    def list_config_ids(self) -> AsyncIterator[ConfigId]:
        return self.cfg_db.keys()

    async def get_config(self, cfg_id: ConfigId) -> Optional[ConfigEntity]:
        return await self.cfg_db.get(cfg_id)

    async def put_config(self, cfg: ConfigEntity, *, validate: bool = True, dry_run: bool = False) -> ConfigEntity:
        coerced = await self.coerce_and_check_model(cfg.id, cfg.config, validate)
        existing = await self.cfg_db.get(cfg.id)
        if not dry_run and (not existing or existing.config != cfg.config):
            result = await self.cfg_db.update(ConfigEntity(cfg.id, coerced, cfg.revision))
            await self.message_bus.emit_event(CoreMessage.ConfigUpdated, dict(id=result.id, revision=result.revision))
            await self.event_sender.core_event(CoreEvent.SystemConfigurationChanged, result.analytics())
            return result
        else:
            return cfg

    async def patch_config(self, cfg: ConfigEntity, *, validate: bool = True, dry_run: bool = False) -> ConfigEntity:
        current = await self.cfg_db.get(cfg.id)
        current_config = current.config if current else {}
        coerced = await self.coerce_and_check_model(cfg.id, deep_merge(current_config, cfg.config), validate)
        if not dry_run and (not current or current_config != coerced):
            result = await self.cfg_db.update(ConfigEntity(cfg.id, coerced, current.revision if current else None))
            await self.message_bus.emit_event(CoreMessage.ConfigUpdated, dict(id=result.id, revision=result.revision))
            await self.event_sender.core_event(CoreEvent.SystemConfigurationChanged, result.analytics())
            return result
        else:
            return cfg

    async def delete_config(self, cfg_id: ConfigId) -> None:
        await self.cfg_db.delete(cfg_id)
        await self.validation_db.delete(cfg_id)
        await self.message_bus.emit_event(CoreMessage.ConfigDeleted, dict(id=cfg_id))
        await self.event_sender.core_event(CoreEvent.SystemConfigurationDeleted)

    def list_config_validation_ids(self) -> AsyncIterator[str]:
        return self.validation_db.keys()

    async def get_config_validation(self, cfg_id: str) -> Optional[ConfigValidation]:
        return await self.validation_db.get(cfg_id)

    async def put_config_validation(self, validation: ConfigValidation) -> ConfigValidation:
        return await self.validation_db.update(validation)

    async def get_configs_model(self) -> Model:
        kinds = [kind async for kind in self.model_db.all()]
        return Model.from_kinds(list(kinds))

    async def update_configs_model(self, kinds: List[Kind]) -> Model:
        # load existing model
        model = await self.get_configs_model()
        # make sure the update is valid, but ignore overlapping property paths, so the same name can
        # have different types in different sections
        updated = model.update_kinds(kinds, check_overlap=False)
        # store all updated kinds
        await self.model_db.update_many(kinds)
        return updated

    async def config_yaml(self, cfg_id: ConfigId, revision: bool = False) -> Optional[str]:
        config = await self.get_config(cfg_id)
        if config:
            model = await self.get_configs_model()

            yaml_str = ""
            for num, (key, value) in enumerate(config.config.items()):
                maybe_kind = model.get(key)
                if isinstance(maybe_kind, ComplexKind):
                    part = maybe_kind.create_yaml(value, initial_level=1)
                    if num > 0:
                        yaml_str += "\n"
                    yaml_str += key + ":" + part
                else:
                    yaml_str += yaml.dump({key: value}, sort_keys=False, allow_unicode=True)

            # mix the revision into the yaml document
            if revision and config.revision:
                yaml_str += (
                    "\n\n# This property is not part of the configuration but defines the revision "
                    "of this document.\n# Please leave it here to avoid conflicting writes.\n"
                    f'_revision: "{config.revision}"'
                )

            return yaml_str
        else:
            return None

    async def acknowledge_config_change(self, cfg_id: str, config: Json) -> None:
        """
        In case an external entity should acknowledge this config change.
        This method either return, which signals success or throws an exception.
        """
        future = asyncio.get_event_loop().create_future()
        task = WorkerTask(
            TaskId(uuid_str()),
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
