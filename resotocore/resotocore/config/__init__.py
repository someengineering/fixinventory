from __future__ import annotations

from abc import ABC, abstractmethod
from attrs import define
from typing import Any, Dict, Optional, AsyncIterator, List, cast

from jsons import set_deserializer, set_serializer

from resotocore.model.model import Model, Kind
from resotocore.types import Json
from resotocore.ids import ConfigId
from resotocore.util import value_in_path, value_in_path_get


@define(order=True, hash=True, frozen=True)
class ConfigEntity:
    id: ConfigId
    config: Json
    revision: Optional[str] = None

    def analytics(self) -> Dict[str, Any]:
        analytics: Dict[str, Any] = {"config_id": self.id}
        if "resotoworker" not in self.config:
            return analytics

        # provider information
        collectors: List[str] = []
        collectors.extend(cast(List[str], value_in_path(self.config, ["resotoworker", "collector"])))
        if "example" in collectors:
            collectors.remove("example")
        analytics["how_many_providers"] = len(collectors)

        # authentication information
        if "aws" in collectors:
            aws_use_access_secret_key = (
                value_in_path(self.config, ["resotoworker", "aws", "access_key_id"]) is not None
                and value_in_path(self.config, ["resotoworker", "aws", "secret_access_key"]) is not None
            )
            aws_use_role = value_in_path(self.config, ["resotoworker", "aws", "role"]) is not None
            aws_use_profiles = value_in_path(self.config, ["resotoworker", "aws", "profiles"]) is not None
            aws_use_accounts = value_in_path(self.config, ["resotoworker", "aws", "account"]) is not None
            aws_use_scrape_org = value_in_path(self.config, ["resotoworker", "aws", "scrape_org"])
            analytics["aws"] = True
            analytics["aws_use_access_secret_key"] = aws_use_access_secret_key
            analytics["aws_use_role"] = aws_use_role
            analytics["aws_use_profiles"] = aws_use_profiles
            analytics["aws_use_accounts"] = aws_use_accounts
            analytics["aws_use_scrape_org"] = aws_use_scrape_org

        if "digitalocean" in collectors:
            do_has_tokens = bool(value_in_path_get(self.config, ["resotoworker", "digitalocean", "api_tokens"], []))
            analytics["digitalocean"] = True
            analytics["do_use_config"] = do_has_tokens

        if "gcp" in collectors:
            gcp_service_accounts: List[str] = value_in_path_get(
                self.config, ["resotoworker", "gcp", "service_account"], []
            )
            gcp_auto_discovery = any(s == "" for s in gcp_service_accounts)
            gcp_use_file = any(s != "" for s in gcp_service_accounts)
            analytics["gcp"] = True
            analytics["gcp_use_auto_discovery"] = gcp_auto_discovery
            analytics["gcp_use_file"] = gcp_use_file

        if "k8s" in collectors:
            k8s_has_cfg_files = bool(value_in_path_get(self.config, ["resotoworker", "k8s", "config_files"], []))
            k8s_has_cfgs = bool(value_in_path_get(self.config, ["resotoworker", "k8s", "configs"], []))
            analytics["k8s"] = True
            analytics["k8s_use_kubeconfig"] = k8s_has_cfg_files
            analytics["k8s_use_manual"] = k8s_has_cfgs

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
    @abstractmethod
    def list_config_ids(self) -> AsyncIterator[ConfigId]:
        pass

    @abstractmethod
    async def get_config(self, cfg_id: ConfigId) -> Optional[ConfigEntity]:
        pass

    @abstractmethod
    async def put_config(self, cfg: ConfigEntity, *, validate: bool = True, dry_run: bool = False) -> ConfigEntity:
        pass

    @abstractmethod
    async def patch_config(self, cfg: ConfigEntity, *, validate: bool = True, dry_run: bool = False) -> ConfigEntity:
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
