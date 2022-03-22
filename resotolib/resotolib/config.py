import jsons
import json
import threading
from urllib.parse import urlparse
from resotolib.logging import log
from resotolib.args import ArgumentParser, convert
from resotolib.graph.export import dataclasses_to_resotocore_model, optional_origin
from resotolib.core import ResotocoreURI
from resotolib.core.config import (
    get_config,
    set_config,
    ConfigNotFoundError,
    update_config_model,
)
from resotolib.core.events import CoreEvents
from typing import Dict, Any, List
from dataclasses import fields


class RunningConfig:
    def __init__(self) -> None:
        """Initialize the global config."""
        self.data: Dict[str, Any] = {}
        self.revision: str = ""
        self.classes: Dict[str, object] = {}
        self.types: Dict[str, Dict[str, type]] = {}

    def apply(self, other: "RunningConfig") -> None:
        """Apply another config to this one.

        Only updates references, does not create a copy of the data.
        """
        if isinstance(other, RunningConfig):
            self.data = other.data
            self.revision = other.revision
            self.classes = other.classes
            self.types = other.types
        else:
            raise TypeError(f"Cannot apply {type(other)} to RunningConfig")


_config = RunningConfig()


class MetaConfig(type):
    def __getattr__(cls, name):
        if name in _config.data:
            return _config.data[name]
        else:
            raise ConfigNotFoundError(f"No such config {name}")


class Config(metaclass=MetaConfig):
    def __init__(self, config_name: str, resotocore_uri: str = None) -> None:
        self._config_lock = threading.Lock()
        self.config_name = config_name
        self._initial_load = True
        resotocore = ResotocoreURI(resotocore_uri)
        self.resotocore_uri = resotocore.http_uri
        self._ce = CoreEvents(
            resotocore.ws_uri,
            events={"config-updated"},
            message_processor=self.on_config_event,
        )

    def __getattr__(self, name):
        if name in _config.data:
            return _config.data[name]
        else:
            raise ConfigNotFoundError(f"No such config {name}")

    def shutdown(self) -> None:
        self._ce.stop()

    def add_config(self, config: object) -> None:
        if hasattr(config, "kind"):
            _config.classes[config.kind] = config
            _config.types[config.kind] = {}
            for field in fields(config):
                if hasattr(field, "type"):
                    _config.types[config.kind][field.name] = optional_origin(field.type)
        else:
            raise RuntimeError("Config must have a 'kind' attribute")

    def load_config(self) -> None:
        if len(_config.classes) == 0:
            raise RuntimeError("No config added")
        with self._config_lock:
            try:
                config, new_config_revision = get_config(
                    self.config_name, self.resotocore_uri
                )
                if len(config) == 0:
                    if self._initial_load:
                        raise ConfigNotFoundError(
                            "Empty config returned - loading defaults"
                        )
                    else:
                        raise ValueError("Empty config returned")
            except ConfigNotFoundError:
                for config_id, config_data in _config.classes.items():
                    _config.data[config_id] = config_data()
            else:
                log.debug(
                    f"Loaded config {self.config_name} revision {new_config_revision}"
                )
                new_config = {}
                for config_id, config_data in config.items():
                    if config_id in _config.classes:
                        new_config[config_id] = jsons.loads(
                            json.dumps(config_data), _config.classes[config_id]
                        )
                    else:
                        log.warning(f"Unknown config {config_id}")
                _config.data = new_config
                _config.revision = new_config_revision
            if self._initial_load:
                self.save_config()
            self.override_config()
            self._initial_load = False
            if not self._ce.is_alive():
                log.debug("Starting config event listener")
                self._ce.start()

    def override_config(self) -> None:
        for override in getattr(ArgumentParser.args, "config_override", []):
            try:
                config_key, config_value = override.split("=", 1)
                if "." not in config_key:
                    log.error(f"Invalid config override {config_key}")
                    continue
                config_id, config_attr = config_key.split(".", 1)
                if config_id not in _config.types:
                    log.error(f"Override unknown config id {config_id}")
                    continue
                if config_attr not in _config.types[config_id]:
                    log.error(
                        f"Override unknown config attr {config_attr} for {config_id}"
                    )
                    continue
                target_type = _config.types[config_id][config_attr]
                config_value = convert(config_value, target_type)
                log.debug(
                    f"Overriding attr {config_attr} of {config_id} with value of type {target_type}"
                )
                setattr(_config.data[config_id], config_attr, config_value)

            except Exception:
                log.exception(f"Failed to override config {override}")

    def save_config(self) -> None:
        update_config_model(self.model, resotocore_uri=self.resotocore_uri)
        config = jsons.dump(_config.data, strip_attr="kind", strip_properties=True)
        stored_config_revision = set_config(
            self.config_name, config, self.resotocore_uri
        )
        if stored_config_revision != _config.revision:
            _config.revision = stored_config_revision
            log.debug(f"Saved config {self.config_name} revision {_config.revision}")
        else:
            log.debug(f"Config {self.config_name} unchanged")

    def on_config_event(self, message: Dict[str, Any]) -> None:
        if (
            message.get("message_type") == "config-updated"
            and message.get("data", {}).get("id") == self.config_name
            and message.get("data", {}).get("revision") != _config.revision
        ):
            try:
                log.debug(f"Config {self.config_name} has changed - reloading")
                self.load_config()
            except Exception:
                log.exception("Failed to reload config")

    @property
    def model(self) -> List:
        """Return the config dataclass model in resotocore format"""
        classes = set(_config.classes.values())
        return dataclasses_to_resotocore_model(classes)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--override",
            help="Override config attribute(s)",
            dest="config_override",
            type=str,
            default=[],
            nargs="+",
        )
