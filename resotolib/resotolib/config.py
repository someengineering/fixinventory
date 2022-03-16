import jsons
import json
import threading
from urllib.parse import urlparse
from resotolib.logging import log
from resotolib.args import ArgumentParser
from resotolib.core.config import get_config, set_config, ConfigNotFoundError
from resotolib.core.events import CoreEvents
from typing import Dict, Any


class Config:
    _config: Dict[str, Any] = {}
    _config_revision: str = ""
    _config_classes: Dict[str, object] = {}

    def __init__(self, config_name: str, resotocore_uri: str = None) -> None:
        self.config_added = threading.Event()
        self.config_name = config_name
        if resotocore_uri is None:
            resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri", None)
        if resotocore_uri is None:
            raise ValueError("resotocore_uri is required")
        self.resotocore_uri = f"http://{urlparse(resotocore_uri).netloc}"
        self.ce = CoreEvents(
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
        try:
            config, self._config_revision = get_config(
                self.config_name, self.resotocore_uri
            )
        except ConfigNotFoundError:
            for config_id, config_data in self._config_classes.items():
                self._config[config_id] = config_data()
        else:
            log.debug(
                f"Loaded config {self.config_name} revision {self._config_revision}"
            )
            for config_id, config_data in config.items():
                if config_id in self._config_classes:
                    self._config[config_id] = jsons.loads(
                        json.dumps(config_data), self._config_classes[config_id]
                    )
                else:
                    log.error(f"Unknown config {config_id}")
        self.save_config()
        self.ce.start()

    def save_config(self) -> None:
        config = jsons.dump(self._config, strip_attr="kind", strip_properties=True)
        self._config_revision = set_config(
            self.config_name, config, self.resotocore_uri
        )
        log.debug(f"Saved config {self.config_name} revision {self._config_revision}")

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
                pass
