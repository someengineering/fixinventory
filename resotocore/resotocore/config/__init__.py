from __future__ import annotations

from abc import ABC, abstractmethod
from attrs import define
from typing import Any, Dict, Optional, AsyncIterator, List, cast

from jsons import set_deserializer, set_serializer
from resotocore.analytics import AnalyticsEventSender

from resotocore.model.model import Model, Kind
from resotocore.types import Json
from resotocore.ids import ConfigId
from resotocore.util import value_in_path


@define(order=True, hash=True, frozen=True)
class ConfigEntity:
    id: ConfigId
    config: Json
    revision: Optional[str] = None

    def analytics(self) -> Dict[str, Any]:
        analytics: Dict[str, Any] = {}
        if "resotoworker" not in self.config:
            return analytics

        # provider information
        collectors: List[str] = []
        # vault.tags = cast(Dict[str, Optional[str]], tags)

        collectors.extend(cast(List[str], value_in_path(self.config, ["resotoworker", "collector"])))
        if "example" in collectors:
            collectors.remove("example")
        analytics.update({"collectors": collectors})
        analytics.update({"how_many_providers": len(collectors)})

        # authentication information
        if "aws" in collectors:
            analytics.update({"aws_use_access_secret_key": False})
            analytics.update({"aws_use_role": False})
            analytics.update({"aws_use_profiles": False})
            analytics.update({"aws_use_accounts": False})
            analytics.update({"aws_use_scrape_org": False})
            if value_in_path(self.config, ["resotoworker", "aws", "access_key_id"]) and value_in_path(
                self.config, ["resotoworker", "aws", "secret_access_key"]
            ):
                analytics.update({"aws_use_access_secret_key": True})
            if value_in_path(self.config, ["resotoworker", "aws", "role"]):
                analytics.update({"aws_use_role": True})
            if value_in_path(self.config, ["resotoworker", "aws", "profiles"]):
                analytics.update({"aws_use_profiles": True})
            if value_in_path(self.config, ["resotoworker", "aws", "account"]):
                analytics.update({"aws_use_accounts": True})
            if value_in_path(self.config, ["resotoworker", "aws", "scrape_org"]):
                analytics.update({"aws_use_scrape_org": True})

        if "digitalocean" in collectors:
            analytics.update({"do_use_config": False})
            analytics.update({"do_use_env": False})
            if value_in_path(self.config, ["resotoworker", "digitalocean", "api_tokens"]):
                analytics.update({"do_use_config": True})
            else:
                analytics.update({"do_use_env": True})

        if "gcp" in collectors:
            analytics.update({"gcp_use_file": False})
            analytics.update({"gcp_use_auto_discovery": False})
            if value_in_path(self.config, ["resotoworker", "gcp", "service_account"]) == "":
                analytics.update({"gcp_use_auto_discovery": True})
            else:
                analytics.update({"gcp_use_file": True})

        if "k8s" in collectors:
            analytics.update({"k8s_use_kubeconfig": False})
            analytics.update({"k8s_use_manual": False})
            if value_in_path(self.config, ["resotoworker", "k8s", "config_files"]):
                analytics.update({"k8s_use_kubeconfig": True})
            if value_in_path(self.config, ["resotoworker", "k8s", "configs"]):
                analytics.update({"k8s_use_manual": True})

        return analytics

    # noinspection PyUnusedLocal
    @staticmethod
    def from_json(js: Json, _: type = object, **kwargs: object) -> ConfigEntity:
        if "id" in js and "config" in js:
            return ConfigEntity(js["id"], js["config"], js.get("_rev"))
        else:
            raise AttributeError(f"Can not parse a ConfigEntity from this json: {js}")

    # noinspection PyUnusedLocal
    @staticmethod
    def to_json(o: ConfigEntity, **kw_args: object) -> Json:
        return dict(id=o.id, config=o.config, _rev=o.revision)


@define(order=True, hash=True, frozen=True)
class ConfigValidation:
    id: str
    external_validation: bool = False


class ConfigHandler(ABC):
    event_sender: AnalyticsEventSender

    @abstractmethod
    def list_config_ids(self) -> AsyncIterator[ConfigId]:
        pass

    @abstractmethod
    async def get_config(self, cfg_id: ConfigId) -> Optional[ConfigEntity]:
        pass

    @abstractmethod
    async def put_config(self, cfg: ConfigEntity, validate: bool = True) -> ConfigEntity:
        pass

    @abstractmethod
    async def patch_config(self, cfg: ConfigEntity) -> ConfigEntity:
        pass

    @abstractmethod
    async def delete_config(self, cfg_id: ConfigId) -> None:
        pass

    @abstractmethod
    async def get_configs_model(self) -> Model:
        pass

    @abstractmethod
    async def update_configs_model(self, kinds: List[Kind]) -> Model:
        pass

    @abstractmethod
    def list_config_validation_ids(self) -> AsyncIterator[str]:
        pass

    @abstractmethod
    async def get_config_validation(self, cfg_id: str) -> Optional[ConfigValidation]:
        pass

    @abstractmethod
    async def put_config_validation(self, validation: ConfigValidation) -> ConfigValidation:
        pass

    @abstractmethod
    async def config_yaml(self, cfg_id: ConfigId, revision: bool = False) -> Optional[str]:
        pass


# register serializer for this class
set_deserializer(ConfigEntity.from_json, ConfigEntity)
set_serializer(ConfigEntity.to_json, ConfigEntity)
