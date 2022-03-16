import jsons
import json
import threading
from urllib.parse import urlparse
from resotolib.logging import log
from resotolib.args import ArgumentParser
from resotolib.graph.export import dataclasses_to_resotocore_model
from resotolib.core.config import (
    get_config,
    set_config,
    ConfigNotFoundError,
    update_config_model,
)
from resotolib.core.events import CoreEvents
from typing import Dict, Any, List


class Config:
    _config: Dict[str, Any] = {}
    _config_revision: str = ""
    _config_classes: Dict[str, object] = {}

    def __init__(self, config_name: str, resotocore_uri: str = None) -> None:
        self.config_added = threading.Event()
        self._config_lock = threading.Lock()
        self.config_name = config_name
        self._initial_load = True
        if resotocore_uri is None:
            resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri", None)
        if resotocore_uri is None:
            raise ValueError("resotocore_uri is required")
        self.resotocore_uri = f"http://{urlparse(resotocore_uri).netloc}"
        self._ce = CoreEvents(
            f"ws://{urlparse(self.resotocore_uri).netloc}",
            events={"config-updated"},
            message_processor=self.on_config_event,
        )

    def __getattr__(self, name):
        if name in self._config:
            return self._config[name]
        else:
            raise ConfigNotFoundError(f"No such config {name}")

    def add_config(self, config: object) -> None:
        if hasattr(config, "kind"):
            self._config_classes[config.kind] = config
            self.config_added.set()
        else:
            raise RuntimeError("Config must have a 'kind' attribute")

    def load_config(self) -> None:
        if not self.config_added.is_set():
            raise RuntimeError("No config added")
        with self._config_lock:
            try:
                config, new_config_revision = get_config(
                    self.config_name, self.resotocore_uri
                )
            except ConfigNotFoundError:
                for config_id, config_data in self._config_classes.items():
                    self._config[config_id] = config_data()
            else:
                log.debug(
                    f"Loaded config {self.config_name} revision {new_config_revision}"
                )
                new_config = {}
                for config_id, config_data in config.items():
                    if config_id in self._config_classes:
                        new_config[config_id] = jsons.loads(
                            json.dumps(config_data), self._config_classes[config_id]
                        )
                    else:
                        log.warning(f"Unknown config {config_id}")
                self._config = new_config
                self._config_revision = new_config_revision
            if self._initial_load:
                self.save_config()
            self._initial_load = False
            if not self._ce.is_alive():
                log.debug(f"Starting config event listener")
                self._ce.start()

    def save_config(self) -> None:
        update_config_model(self.model, resotocore_uri=self.resotocore_uri)
        config = jsons.dump(self._config, strip_attr="kind", strip_properties=True)
        stored_config_revision = set_config(
            self.config_name, config, self.resotocore_uri
        )
        if stored_config_revision != self._config_revision:
            self._config_revision = stored_config_revision
            log.debug(
                f"Saved config {self.config_name} revision {self._config_revision}"
            )
        else:
            log.debug(f"Config {self.config_name} unchanged")

    def on_config_event(self, message: Dict[str, Any]) -> None:
        if (
            message.get("message_type") == "config-updated"
            and message.get("data", {}).get("id") == self.config_name
            and message.get("data", {}).get("revision") != self._config_revision
        ):
            try:
                log.debug(f"Config {self.config_name} has changed - reloading")
                self.load_config()
            except Exception:
                log.exception("Failed to reload config")

    @property
    def model(self) -> List:
        """Return the config dataclass model in resotocore format"""
        classes = set(self._config_classes.values())
        return dataclasses_to_resotocore_model(classes)
