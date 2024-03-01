import threading
import os

from fixlib.json import from_json, to_json
from fixlib.logger import log
from fixlib.args import ArgumentParser, convert
from fixlib.core.ca import TLSData
from fixlib.proc import restart
from fixlib.core.model_export import dataclasses_to_fixcore_model, optional_origin
from fixlib.core import FixcoreURI
from fixlib.core.config import (
    get_config,
    set_config,
    ConfigNotFoundError,
    update_config_model,
)
from fixlib.core.events import CoreEvents
from fixlib.utils import replace_env_vars, merge_json_elements, drop_deleted_attributes
from fixlib.types import Json
from typing import Dict, Any, List, Optional, Type, cast
from attrs import fields


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
    def __getattr__(cls, name: str) -> Any:
        if name in _config.data:
            return _config.data[name]
        else:
            raise ConfigNotFoundError(f"No such config {name}")


class Config(metaclass=MetaConfig):
    running_config: RunningConfig = _config

    def __init__(
        self,
        config_name: str,
        fixcore_uri: Optional[str] = None,
        tls_data: Optional[TLSData] = None,
    ) -> None:
        self._config_lock = threading.Lock()
        self.config_name = config_name
        self._initial_load = True
        fixcore = FixcoreURI(fixcore_uri)
        self.fixcore_uri = fixcore.http_uri
        self.verify = None
        if tls_data:
            self.verify = tls_data.verify
        self._ce = CoreEvents(
            fixcore.ws_uri,
            events={"config-updated"},
            message_processor=self.on_config_event,
            tls_data=tls_data,
        )

    def __getattr__(self, name: str) -> Any:
        if name in self.running_config.data:
            return self.running_config.data[name]
        else:
            raise ConfigNotFoundError(f"No such config {name}")

    def connected(self) -> bool:
        return self._ce.connected()

    def shutdown(self) -> None:
        self._ce.shutdown()

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
            Config.running_config.classes[config.kind] = config  # type: ignore
            Config.running_config.types[config.kind] = {}
            for field in fields(config):  # type: ignore
                if hasattr(field, "type"):
                    Config.running_config.types[config.kind][field.name] = optional_origin(field.type)
        else:
            raise RuntimeError("Config must have a 'kind' attribute")

    def load_config(self, reload: bool = False) -> None:
        if len(Config.running_config.classes) == 0:
            raise RuntimeError("No config added")
        with self._config_lock:
            config_json = {}
            raw_config_json = {}
            new_config = None
            new_config_revision = None

            ############################################################
            # Load the config from the core, populate it with defaults
            # and send it back to fixcore
            ############################################################
            try:
                # We need two configs here: one with env_vars resolved and overrides applied
                # and one with the raw config as it was stored in the database
                config_response, new_config_revision = get_config(
                    self.config_name, self.fixcore_uri, verify=self.verify  # type: ignore
                )
                # config with env_vars resolved and overrides applied
                config_json = config_response["config"]
                config_json = {
                    k: replace_env_vars(v, os.environ, keep_unresolved=False) for k, v in config_json.items()
                }
                # raw config as it was stored in the database, to be sent to the core
                raw_config_json = config_response["raw_config"]

                if len(config_json) == 0:
                    if self._initial_load:
                        raise ConfigNotFoundError("Empty config returned - loading defaults")
                    else:
                        raise ValueError("Empty config returned")
            except ConfigNotFoundError:
                pass
            else:
                log.info(f"Loaded config {self.config_name} revision {new_config_revision}")
                new_config = Config.read_config(
                    config_json, reason="loading new config to check if restart is required"
                )
                # test if the config has changed using the most latest version
                # with overrides applied and env_vars resolved
                if reload and self.restart_required(new_config):
                    restart()

            # update the global config object with the confif from the core
            Config.running_config.data = self.with_default_config(raw_config_json)
            # if the raw_config was not empty, we need to set the revision too
            if new_config_revision:
                Config.running_config.revision = new_config_revision

            # now we're ready to send the raw config plus the new defaults to the core
            if self._initial_load:
                # Try to store the generated config. Handle failure gracefully.
                try:
                    # Send the raw_config + default values to fixcore
                    self.save_config()
                except RuntimeError as e:
                    log.error(f"Failed to save config: {e}")

            ############################################################
            # Once the core got the raw config, use the config with
            # overrides applied and env_vars resolved
            ############################################################
            # merge the config with overrides and env_vars into the default config
            self.init_default_config()
            default_config_dict = self.dict()

            config_with_defaults = cast(Json, merge_json_elements(default_config_dict, config_json))
            self.apply_path_overrides_resolve_env_vars(Config.running_config, config_with_defaults)
            self.override_config(Config.running_config)
            self._initial_load = False
            if not self._ce.is_alive():
                log.debug("Starting config event listener")
                self._ce.start()

    def with_default_config(self, raw_config_json: Json) -> Json:
        """
        Merges the raw config from the core with the default config and clean up deleted entries.
        """

        # init the default config for merging the raw config into it
        self.init_default_config()
        default_config_dict = self.dict()

        # default config that is updated by the raw config from the core
        raw_with_new_defaults = cast(
            Json,
            merge_json_elements(default_config_dict, raw_config_json),
        )

        # we also resolve the env var to construct a attrs class and not explode
        raw_with_resolved_env_vars = {
            k: replace_env_vars(v, os.environ, keep_unresolved=False) for k, v in raw_with_new_defaults.items()
        }

        # json with resolved env vars, defaults and dropped deleted attributes
        # this is the config that we will use to cleanup the raw_with_new_defaults
        reference_config_json = to_json(
            Config.read_config(raw_with_resolved_env_vars, reason="making reference config for cleanup"),
        )

        result = cast(Json, drop_deleted_attributes(raw_with_new_defaults, reference_config_json))
        return result

    @staticmethod
    def read_config(config: Json, read_as_json: bool = False, reason: Optional[str] = None) -> Dict[str, Any]:
        new_config = {}
        for config_id, config_data in config.items():
            if config_data is None:
                config_data = {}
            if config_id in Config.running_config.classes:
                message = f" reason: {reason}" if reason else ""
                log.debug(f"Loading config section {config_id}" + message)
                clazz: Type[Any] = Config.running_config.classes.get(config_id, Any) if not read_as_json else Any  # type: ignore # noqa: E501
                # use the from_json class from config, if available
                if loader := getattr(clazz, "from_json", None):
                    new_config[config_id] = loader(config_data)
                else:
                    new_config[config_id] = from_json(config_data, clazz)
            else:
                log.warning(f"Unknown config section {config_id}")
        return new_config

    @staticmethod
    def restart_required(new_config: Json) -> bool:
        for config_id, config_data in new_config.items():
            if config_id in Config.running_config.data:
                for field in fields(type(config_data)):
                    if field.metadata.get("restart_required", False):
                        old_value = getattr(Config.running_config.data[config_id], field.name, None)
                        new_value = getattr(config_data, field.name, None)
                        if new_value != old_value:
                            log.info(f"Changed config {config_id}.{field.name} requires restart")
                            return True
        return False

    @staticmethod
    def apply_path_overrides_resolve_env_vars(running_config: RunningConfig, config: Json) -> bool:
        # there was no config received from fixcore, keep defaults
        if not config:
            return False
        # resolve missing env_vars from the environment
        resolved_conf = {k: replace_env_vars(v, os.environ, keep_unresolved=False) for k, v in config.items()}

        running_config.data = Config.read_config(resolved_conf, reason="resolving env_vars on the final config")

        return True

    @staticmethod
    def override_config(running_config: RunningConfig) -> None:
        if getattr(ArgumentParser.args, "config_override", None) is None:
            return
        for override in getattr(ArgumentParser.args, "config_override", []):
            try:
                if "=" not in override:
                    log.error(f"Invalid config override {override}")
                    continue
                config_key, config_value = override.split("=", 1)
                if "." not in config_key:
                    log.error(f"Invalid config override {config_key}")
                    continue

                config_key = config_key.replace("resoto", "fix")  # backwards compatibility
                config_keys = config_key.split(".")
                num_keys = len(config_keys)
                config_part = running_config.data
                set_value = False

                # By default we cast the override value to the type of the current
                # value. This works for most cases including dictionary values.
                # Should the current value be None we see if there was a type specified
                # for the dataclass field and use it as a fallback.
                # This only works for dataclass fields.
                config_section = config_keys[0]
                top_config_key = config_keys[1]
                fallback_target_type = None
                if (
                    config_section in Config.running_config.types
                    and top_config_key in Config.running_config.types[config_section]
                ):
                    fallback_target_type = Config.running_config.types[config_section][top_config_key]

                for num_key, key in enumerate(config_keys):
                    if num_key == num_keys - 1:
                        set_value = True
                        log.debug(f"Overriding config key {config_key}")

                    if hasattr(config_part, key):
                        attr_value = getattr(config_part, key)
                        if set_value:
                            config_value = Config.cast_target_type(config_value, attr_value, fallback_target_type)
                            setattr(config_part, key, config_value)
                        else:
                            config_part = attr_value
                    elif isinstance(config_part, dict) and key in config_part:
                        attr_value = config_part[key]
                        if set_value:
                            config_value = Config.cast_target_type(config_value, attr_value, fallback_target_type)
                            config_part[key] = config_value
                        else:
                            config_part = attr_value
                    else:
                        log.error(f"Override key {config_key} is unknown - skipping")
                        break

                target_type = str
                if target_type in (list, tuple, set):
                    config_value = target_type(config_value.split(","))
                config_value = convert(config_value, target_type)

            except Exception:
                log.exception(f"Failed to override config {override}")

    @staticmethod
    def cast_target_type(config_value: Any, current_value: Any, fallback_target_type: Optional[type]) -> object:
        if current_value is None and fallback_target_type is not None:
            target_type = fallback_target_type
        else:
            target_type = type(current_value)
        if target_type in (list, tuple, set):
            config_value = target_type(config_value.split(","))
        else:
            config_value = convert(config_value, target_type)
        return config_value

    @staticmethod
    def dict() -> Json:
        return to_json(Config.running_config.data)

    def save_config(self) -> None:
        update_config_model(self.model, fixcore_uri=self.fixcore_uri, verify=self.verify)
        stored_config_revision = set_config(self.config_name, self.dict(), self.fixcore_uri, verify=self.verify)
        if stored_config_revision != Config.running_config.revision:
            Config.running_config.revision = stored_config_revision
            log.debug(f"Saved config {self.config_name} revision {Config.running_config.revision}")
        else:
            log.debug(f"Config {self.config_name} unchanged")

    def on_config_event(self, message: Dict[str, Any]) -> None:
        if (
            message.get("message_type") == "config-updated"
            and message.get("data", {}).get("id") == self.config_name
            and message.get("data", {}).get("revision") != Config.running_config.revision
        ):
            try:
                log.debug(f"Config {self.config_name} has changed - reloading")
                self.load_config(reload=True)
            except Exception:
                log.exception("Failed to reload config")

    # the __hash__ and the __eq__ below is a workaround to make sure the outdated config is not cached by
    # a lru_cache decoartor after the config performed a self-update. It serves no other purpose.
    def __hash__(self) -> int:
        return hash(self.running_config.revision)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Config):
            return self.running_config.__dict__ == other.running_config.__dict__
        return False

    @property
    def model(self) -> List[Json]:
        """Return the config dataclass model in fixcore format"""
        classes = set(_config.classes.values())
        return dataclasses_to_fixcore_model(classes, use_optional_as_required=True)

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


# Note: the config is mutable.
def current_config() -> Config:
    # metaclass makes it possible to use the class as instance.
    # use this accessor here to get a typed instance of the config
    return Config  # type: ignore
