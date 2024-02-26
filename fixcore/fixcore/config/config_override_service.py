from typing import List, Optional, Callable, Dict, Any, Awaitable, cast
from pathlib import Path
import yaml
import logging
from datetime import timedelta

from fixcore.core_config import config_model
from fixcore.model.typed_model import from_js
from fixcore.service import Service
from fixcore.types import Json
from fixcore.ids import ConfigId
from fixcore.util import Periodic
from fixcore.config import ConfigOverride
from fixcore.db.modeldb import ModelDb
from fixcore.model.model import Model, Kind
from fixlib.utils import merge_json_elements
from deepdiff import DeepDiff
import aiofiles.os as aos
import aiofiles
import jsons

log = logging.getLogger("config_override_service")


async def model_from_db(model_db: ModelDb) -> Model:
    kinds = [kind async for kind in model_db.all()]
    return Model.from_kinds(list(kinds))


class ConfigOverrideService(ConfigOverride, Service):
    def __init__(
        self, override_paths: List[Path], get_configs_model: Callable[[], Awaitable[Model]], sleep_time: float = 10.0
    ):
        super().__init__()
        self.override_paths = override_paths
        self._get_configs_model = get_configs_model

        self.overrides: Dict[ConfigId, Json] = {}
        self.override_change_hooks: List[Callable[[Dict[ConfigId, Json]], Awaitable[Any]]] = []
        self.watcher: Periodic = Periodic(
            "config_overrides_watcher", self.check_config_changes, timedelta(seconds=sleep_time)
        )
        self.mtime_hash: int = 0

    async def load(self) -> None:
        self.overrides = await self._get_overrides()

    def add_override_change_hook(self, hook: Callable[[Dict[ConfigId, Json]], Awaitable[Any]]) -> None:
        self.override_change_hooks.append(hook)

    def coerce_and_validate(self, config: Json, model: Model) -> Json:
        final_config = {}
        for key, value in config.items():
            if key in model:
                try:
                    value_kind = model[key]
                    coerced = value_kind.check_valid(value, normalize=False, config_context=True, ignore_missing=True)
                    final_config[key] = value_kind.sort_json(coerced or value)
                except Exception as ex:
                    raise AttributeError(f"Error validating section {key}: {ex}") from ex
            else:
                final_config[key] = value

        return final_config

    async def _get_overrides(self, silent: bool = False) -> Dict[ConfigId, Json]:
        if not self.override_paths:
            return {}

        # all config files that will be used
        config_files: List[Path] = []
        # collect them all
        for path in self.override_paths:
            if path.is_dir():
                config_files.extend(
                    [file for file in path.iterdir() if file.is_file() and file.suffix in (".yml", ".yaml", ".json")]
                )
            elif path.suffix in (".yml", ".yaml", ".json"):
                config_files.append(path.expanduser())
            else:
                log.warning(f"Config override path {path} is neither a directory nor a yaml/json file, skipping.")

        if config_files:
            log.info("Loading config overrides from: %s", ", ".join(str(file) for file in config_files))

        # json with all merged overrides for all components such as fixcore, fixworker, etc.
        overrides_json: Json = {}

        model = await self._get_configs_model()

        # merge all provided overrides into a single object, preferring the values from the last override
        for config_file in config_files:
            async with aiofiles.open(config_file) as f:
                try:

                    def is_yaml(path: Path) -> bool:
                        return path.suffix in (".yml", ".yaml")

                    content = await f.read()
                    raw_yaml = yaml.safe_load(content) if is_yaml(config_file) else jsons.loads(content, Json)
                    validated = self.coerce_and_validate(raw_yaml, model)
                    with_config_id = {config_file.stem: validated}
                    merged = merge_json_elements(overrides_json, with_config_id)
                    overrides_json = cast(Json, merged)
                except Exception as e:
                    log.warning(f"Can't load the config override {config_file}, skipping. Reason: {e}")

        def is_dict(config_id: str, obj: Any) -> bool:
            if not isinstance(obj, dict):
                if not silent:
                    log.warning(f"Config override with id {config_id} contains invalid data, skipping.")
                return False
            return True

        # dict with all overrides for all config ids, such as fix.core, fix.worker, etc.
        all_config_overrides: Dict[ConfigId, Json] = {
            ConfigId(k): v for k, v in overrides_json.items() if is_dict(k, v)
        }

        if all_config_overrides is None:
            if not silent:
                log.warning("No config overrides found.")
            return {}

        log.info("Loaded config overrides for: %s", ", ".join(str(config_id) for config_id in all_config_overrides))
        return all_config_overrides

    def get_override(self, config_id: ConfigId) -> Optional[Json]:
        return self.overrides.get(config_id)

    def get_all_overrides(self) -> Dict[ConfigId, Json]:
        return self.overrides

    async def check_config_changes(self) -> None:
        # all config files that needs to be checked for changes
        config_files: List[Path] = []
        # do a flatmap on directories
        for path in self.override_paths:
            if await aos.path.isdir(path):
                config_files.extend(
                    [
                        Path(entry.path)
                        for entry in await aos.scandir(path)  # scandir avoids extra syscalls
                        if entry.is_file() and Path(entry.path).suffix in (".yml", ".yaml")
                    ]
                )
            else:
                config_files.append(path)

        # a quick optimization to avoid reading the files if none has been changed
        mtime_hash = 0
        config_files = sorted(config_files)
        for file in config_files:
            mtime_hash = hash((mtime_hash, (await aos.stat(file)).st_mtime))

        if mtime_hash == self.mtime_hash:
            return
        self.mtime_hash = mtime_hash

        overrides = await self._get_overrides(silent=True)
        diff = DeepDiff(self.overrides, overrides, ignore_order=True)

        if diff:
            self.overrides = overrides
            for hook in self.override_change_hooks:
                await hook(self.overrides)

    async def start(self) -> None:
        await self.load()
        await self.watcher.start()

    async def stop(self) -> None:
        await self.watcher.stop()


async def override_config_for_startup(override_path: List[Path]) -> ConfigOverride:
    """
    Minimal version that is used only for bootstrapping the core
    """

    async def core_config_model() -> Model:
        return Model.from_kinds(from_js(config_model(), List[Kind]))

    config_override_service = ConfigOverrideService(override_path, core_config_model)
    await config_override_service.load()
    return config_override_service
