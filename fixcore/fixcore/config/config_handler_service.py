import asyncio

from datetime import timedelta
from typing import Optional, AsyncIterator, List, Dict, Any, cast
import attrs
import yaml
import os
from deepdiff import DeepDiff
import hashlib

from fixcore.analytics import AnalyticsEventSender, CoreEvent
from fixcore.config import ConfigHandler, ConfigEntity, ConfigValidation, ConfigOverride
from fixcore.db.configdb import ConfigEntityDb, ConfigValidationEntityDb
from fixcore.db.modeldb import ModelDb
from fixcore.message_bus import MessageBus, CoreMessage
from fixcore.model.model import Model, Kind, ComplexKind
from fixcore.service import Service
from fixcore.types import Json, JsonElement
from fixcore.util import uuid_str, deep_merge, first
from fixcore.worker_task_queue import WorkerTaskQueue, WorkerTask, WorkerTaskName
from fixcore.ids import TaskId, ConfigId
from fixcore.core_config import CoreConfig
from fixlib.utils import merge_json_elements

from fixlib.utils import replace_env_vars


class ConfigHandlerService(ConfigHandler, Service):
    def __init__(
        self,
        cfg_db: ConfigEntityDb,
        validation_db: ConfigValidationEntityDb,
        model_db: ModelDb,
        task_queue: WorkerTaskQueue,
        message_bus: MessageBus,
        event_sender: AnalyticsEventSender,
        core_config: CoreConfig,
        override_service: ConfigOverride,
    ) -> None:
        super().__init__()
        self.cfg_db = cfg_db
        self.validation_db = validation_db
        self.model_db = model_db
        self.task_queue = task_queue
        self.message_bus = message_bus
        self.event_sender = event_sender
        self.core_config = core_config
        self.override_service = override_service
        self.old_overrides: Dict[ConfigId, Json] = {}

    async def coerce_and_check_model(self, cfg_id: ConfigId, config: Json, validate: bool = True) -> Json:
        model = await self.get_configs_model()
        # filter config roots to match top level entries in config
        config_roots = {kind.fqn: kind for kind in model.complex_kinds() if kind.aggregate_root}

        final_config = {}
        if validate:
            for key, value in config.items():
                if key in config_roots:
                    try:
                        value_kind = config_roots[key]
                        coerced = value_kind.check_valid(value, normalize=False, config_context=True)
                        final_config[key] = value_kind.sort_json(coerced or value)
                    except Exception as ex:
                        raise AttributeError(f"Error validating section {key}: {ex}") from ex
                else:
                    final_config[key] = value
        else:
            final_config = config

        # If an external entity needs to approve this change.
        # Method throws if config is not valid according to external approval.
        keys = {key async for key in self.validation_db.keys()}
        parts = cfg_id.split(".")
        # A config with key foo.bla.bar can be validated by foo.bla.bar, foo.bla and foo
        # The longest key is the most specific validator and is used.
        validator = first(lambda x: x in keys, (".".join(parts[0:i]) for i in range(len(parts), 0, -1)))
        if validator:
            validation = await self.validation_db.get(validator)
            if validation and validation.external_validation and validate:
                await self.acknowledge_config_change(validator, cfg_id, final_config)

        # If we come here, everything is fine
        return final_config

    async def coerce_config(self, config: Json) -> Json:
        model = await self.get_configs_model()

        final_config = {}
        for key, value in config.items():
            if key in model:
                value_kind = model[key]
                coerced = value_kind.coerce(value)
                sorted_conf = value_kind.sort_json(coerced) if isinstance(coerced, dict) else coerced
                final_config[key] = sorted_conf
            else:
                final_config[key] = value
        return final_config

    def list_config_ids(self) -> AsyncIterator[ConfigId]:
        return self.cfg_db.keys()

    async def get_config(
        self, cfg_id: ConfigId, apply_overrides: bool = True, resolve_env_vars: bool = True
    ) -> Optional[ConfigEntity]:
        conf = await self.cfg_db.get(cfg_id)
        if conf is None:
            return None

        # apply overrides if they exist and we do not opt out
        # we do not want to apply overrides if the config is to be shown during editing
        overrides = self.override_service.get_override(cfg_id)
        updated_conf = cast(
            Json, merge_json_elements(conf.config, overrides) if overrides and apply_overrides else conf.config
        )

        # reslove env vars
        # we do not want to resolve env vars if the config is to be shown to the user when editing,
        # otherwise sensitive data might be exposed
        if resolve_env_vars:
            resolved_conf = {k: replace_env_vars(v, os.environ) for k, v in updated_conf.items()}
            coerced_conf = await self.coerce_config(resolved_conf)
            updated_conf = coerced_conf

        return attrs.evolve(conf, config=updated_conf)

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

    async def copy_config(self, from_cfg_id: ConfigId, to_cfg_id: ConfigId) -> Optional[ConfigEntity]:
        old = await self.cfg_db.get(from_cfg_id)
        if old is None:
            return None
        if await self.cfg_db.get(to_cfg_id) is not None:
            raise ValueError(f"Config with id {to_cfg_id} already exists")
        result = await self.cfg_db.update(ConfigEntity(to_cfg_id, old.config, old.revision))
        await self.message_bus.emit_event(
            CoreMessage.ConfigUpdated, dict(old=old.id, new=result.id, revision=result.revision)
        )
        await self.event_sender.core_event(CoreEvent.SystemConfigurationChanged, result.analytics())
        return result

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
        updated = model.update_kinds(kinds, check_overlap=False, replace=False)
        # store all updated kinds
        await self.model_db.update_many(kinds)
        return updated

    async def config_yaml(self, cfg_id: ConfigId, revision: bool = False) -> Optional[str]:
        config = await self.get_config(cfg_id, apply_overrides=False, resolve_env_vars=False)
        if config:
            model = await self.get_configs_model()

            # returns the overridden config with comments about the changes
            def overridden_parts(existing: JsonElement, update: JsonElement) -> JsonElement:
                if isinstance(update, dict):
                    return {
                        key: overridden_parts(
                            existing.get(key) if isinstance(existing, dict) else existing, update[key]
                        )
                        for key in set(update.keys())
                    }
                else:

                    def mkstr(val: Any) -> str:
                        if isinstance(val, list):
                            return f'[{", ".join(val)}]'
                        return str(val)

                    return mkstr(update)

            yaml_str = ""

            overrides = overridden_parts(config.config, self.override_service.get_override(cfg_id) or {})
            overrides_json = overrides if isinstance(overrides, dict) else {}

            for num, (key, value) in enumerate(config.config.items()):
                if num > 0:
                    yaml_str += "\n"
                maybe_kind = model.get(key)
                if isinstance(maybe_kind, ComplexKind):
                    part = maybe_kind.create_yaml(value, initial_level=1, overrides=overrides_json.get(key) or {})
                    yaml_str += key + ":" + part
                else:
                    yaml_str += yaml.dump({key: value}, sort_keys=False, allow_unicode=True).removesuffix("\n")
            yaml_str += "\n"

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

    async def acknowledge_config_change(self, validator: str, cfg_id: ConfigId, config: Json) -> None:
        """
        In case an external entity should acknowledge this config change.
        This method either return, which signals success or throws an exception.
        """
        future = asyncio.get_event_loop().create_future()
        task = WorkerTask(
            TaskId(uuid_str()),
            WorkerTaskName.validate_config,
            {"config_id": validator},
            {"task": WorkerTaskName.validate_config, "config": config, "config_id": cfg_id},
            future,
            timedelta(seconds=30),
        )
        # add task to queue - do not retry
        await self.task_queue.add_task(task)
        # In case the config is not valid or no worker is available
        # this future will throw an exception.
        # Do not handle it here and let the error bubble up.
        await future

    async def start(self) -> None:
        async def on_override_change(new_overrides: Dict[ConfigId, Json]) -> None:
            def updated_revision(conf: Json, override: Json) -> str:
                m = hashlib.sha1(usedforsecurity=False)
                m.update(yaml.dump(conf).encode("utf-8"))
                m.update(yaml.dump(override).encode("utf-8"))
                return m.hexdigest()

            diff = DeepDiff(self.old_overrides, new_overrides, ignore_order=True)
            if diff.affected_root_keys:
                affected_configs = diff.affected_root_keys

                for config_id in affected_configs:
                    # the new and updated version, since the override is already applied
                    config = await self.get_config(config_id)
                    if config:
                        new_revision = updated_revision(config.config, new_overrides.get(config_id) or {})
                        await self.message_bus.emit_event(
                            CoreMessage.ConfigUpdated, dict(id=config.id, revision=new_revision)
                        )
                        await self.event_sender.core_event(CoreEvent.SystemConfigurationChanged, config.analytics())

                self.old_overrides = new_overrides

        self.old_overrides = self.override_service.get_all_overrides()
        self.override_service.add_override_change_hook(on_override_change)
