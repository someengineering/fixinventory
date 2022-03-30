import jsons
import threading
from resotolib.logging import log
from resotolib.args import ArgumentParser, convert
from resotolib.core.ca import TLSData
from resotolib.core.model_export import dataclasses_to_resotocore_model, optional_origin
from resotolib.core import ResotocoreURI
from resotolib.core.config import (
    get_config,
    set_config,
    ConfigNotFoundError,
    update_config_model,
)
from resotolib.core.events import CoreEvents
from typing import Dict, Any, List, Optional
from dataclasses import fields


class RunningConfig:
    def __init__(self) -> None:
        """Initialize the global config."""
        self.data: Dict[str, Any] = {}
        self.revision: str = ""
        self.classes: Dict[str, type] = {}
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
    running_config: RunningConfig = _config

    def __init__(
        self,
        config_name: str,
        resotocore_uri: str = None,
        tls_data: Optional[TLSData] = None,
    ) -> None:
        self._config_lock = threading.Lock()
        self.config_name = config_name
        self._initial_load = True
        resotocore = ResotocoreURI(resotocore_uri)
        self.resotocore_uri = resotocore.http_uri
        self.verify = None
        if tls_data:
            self.verify = tls_data.verify
        self._ce = CoreEvents(
            resotocore.ws_uri,
            events={"config-updated"},
            message_processor=self.on_config_event,
        )

    def __getattr__(self, name):
        if name in self.running_config.data:
            return self.running_config.data[name]
        else:
            raise ConfigNotFoundError(f"No such config {name}")

    def shutdown(self) -> None:
        self._ce.stop()

    @staticmethod
    def init_default_config() -> None:
        for config_id, config_data in Config.running_config.classes.items():
            if config_id not in Config.running_config.data:
                log.debug(f"Initializing defaults for config section {config_id}")
                Config.running_config.data[config_id] = config_data()

    @staticmethod
    def add_config(config: object) -> None:
        """Add a config to the config manager.

        Takes a dataclass as input and adds its fields to the config store.
        Dataclass must have a kind ClassVar which specifies the top level config name.
        """
        if hasattr(config, "kind"):
            Config.running_config.classes[config.kind] = config
            Config.running_config.types[config.kind] = {}
            for field in fields(config):
                if hasattr(field, "type"):
                    Config.running_config.types[config.kind][
                        field.name
                    ] = optional_origin(field.type)
        else:
            raise RuntimeError("Config must have a 'kind' attribute")

    def load_config(self) -> None:
        if len(Config.running_config.classes) == 0:
            raise RuntimeError("No config added")
        with self._config_lock:
            try:
                config, new_config_revision = get_config(
                    self.config_name, self.resotocore_uri, verify=self.verify
                )
                if len(config) == 0:
                    if self._initial_load:
                        raise ConfigNotFoundError(
                            "Empty config returned - loading defaults"
                        )
                    else:
                        raise ValueError("Empty config returned")
            except ConfigNotFoundError:
                pass
            else:
                log.info(
                    f"Loaded config {self.config_name} revision {new_config_revision}"
                )
                new_config = {}
                for config_id, config_data in config.items():
                    if config_id in Config.running_config.classes:
                        log.debug(f"Loading config section {config_id}")
                        new_config[config_id] = jsons.load(
                            config_data, Config.running_config.classes[config_id]
                        )
                    else:
                        log.warning(f"Unknown config section {config_id}")
                Config.running_config.data = new_config
                Config.running_config.revision = new_config_revision
            self.init_default_config()
            if self._initial_load:
                self.save_config()
            self.override_config()
            self._initial_load = False
            if not self._ce.is_alive():
                log.debug("Starting config event listener")
                self._ce.start()

    def override_config(self) -> None:
        if getattr(ArgumentParser.args, "config_override", None) is None:
            return
        for override in getattr(ArgumentParser.args, "config_override", []):
            try:
                config_key, config_value = override.split("=", 1)
                if "." not in config_key:
                    log.error(f"Invalid config override {config_key}")
                    continue
                config_id, config_attr = config_key.split(".", 1)
                if config_id not in Config.running_config.types:
                    log.error(f"Override unknown config id {config_id}")
                    continue
                if config_attr not in Config.running_config.types[config_id]:
                    log.error(
                        f"Override unknown config attr {config_attr} for {config_id}"
                    )
                    continue
                target_type = Config.running_config.types[config_id][config_attr]
                if target_type in (list, tuple, set):
                    config_value = target_type(config_value.split(","))
                config_value = convert(config_value, target_type)
                log.debug(
                    f"Overriding attr {config_attr} of {config_id} with value of type {target_type}"
                )
                setattr(
                    Config.running_config.data[config_id], config_attr, config_value
                )

            except Exception:
                log.exception(f"Failed to override config {override}")

    @staticmethod
    def dict() -> Dict:
        return jsons.dump(
            Config.running_config.data, strip_attr="kind", strip_properties=True
        )

    def save_config(self) -> None:
        update_config_model(
            self.model, resotocore_uri=self.resotocore_uri, verify=self.verify
        )
        stored_config_revision = set_config(
            self.config_name, self.dict(), self.resotocore_uri, verify=self.verify
        )
        if stored_config_revision != Config.running_config.revision:
            Config.running_config.revision = stored_config_revision
            log.debug(
                f"Saved config {self.config_name} revision {Config.running_config.revision}"
            )
        else:
            log.debug(f"Config {self.config_name} unchanged")

    def on_config_event(self, message: Dict[str, Any]) -> None:
        if (
            message.get("message_type") == "config-updated"
            and message.get("data", {}).get("id") == self.config_name
            and message.get("data", {}).get("revision")
            != Config.running_config.revision
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
