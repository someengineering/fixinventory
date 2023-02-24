from typing import List, Optional, Callable, Dict, Any, Awaitable
from pathlib import Path
from watchfiles import awatch
from resotocore.types import Json
from resotocore.ids import ConfigId
import yaml
from resotocore.util import deep_merge
import logging
import asyncio
from resotocore.config import ConfigOverride

log = logging.getLogger("config_override_service")


class ConfigOverrideService(ConfigOverride):
    def __init__(self, override_paths: List[Path]):
        self.override_paths = override_paths
        self.overrides: Dict[ConfigId, Json] = {}
        self.stop_watcher = asyncio.Event()
        self.override_change_hooks: List[Callable[[Dict[ConfigId, Json]], Awaitable[Any]]] = []
        self.watcher_task: Optional[asyncio.Task[Any]] = None

        self._load_overrides()

    def add_override_change_hook(self, hook: Callable[[Dict[ConfigId, Json]], Awaitable[Any]]) -> None:
        self.override_change_hooks.append(hook)

    def _load_overrides(self) -> None:
        if not self.override_paths:
            return

        # all config files that will be used
        config_files: List[Path] = []
        # collect them all
        for path in self.override_paths:
            if path.is_dir():
                config_files.extend(
                    [file for file in path.iterdir() if file.is_file() and file.suffix in (".yml", ".yaml")]
                )
            else:
                config_files.append(path)

        # json with all merged overrides for all components such as resotocore, resotoworker, etc.
        overrides_json: Json = {}
        # merge all provided overrides into a single object, preferring the values from the last override
        for config_file in config_files:
            with config_file.open() as f:
                try:
                    raw_yaml = yaml.safe_load(f)
                    merged = deep_merge(overrides_json, raw_yaml)
                    overrides_json = merged
                except Exception as e:
                    log.warning(f"Can't read the config override {config_file}, skipping. Reason: {e}")

        def is_dict(config_id: str, obj: Any) -> bool:
            if not isinstance(obj, dict):
                log.warning(f"Config override with id {config_id} contains invalid data, skipping.")
                return False
            return True

        # dict with all overrides for all config ids, such as resoto.core, resoto.worker, etc.
        all_config_overrides: Dict[ConfigId, Json] = {
            ConfigId(k): v for k, v in overrides_json.items() if is_dict(k, v)
        }

        if all_config_overrides is None:
            log.info("No config overrides found")
            return

        self.overrides = all_config_overrides

    def get_override(self, config_id: ConfigId) -> Optional[Json]:
        return self.overrides.get(config_id)

    def get_all_overrides(self) -> Dict[ConfigId, Json]:
        return self.overrides

    def watch_for_changes(self) -> None:
        async def watcher() -> None:
            for path in self.override_paths:
                async for _ in awatch(path, stop_event=self.stop_watcher):
                    self._load_overrides()
                    for hook in self.override_change_hooks:
                        await hook(self.overrides or {})

        # watcher is already running
        if self.watcher_task:
            return

        self.stop_watcher.clear()
        self.watcher_task = asyncio.create_task(watcher())

    def stop(self) -> None:
        self.stop_watcher.set()
        self.watcher_task = None
