from __future__ import annotations

import logging
from typing import Optional, Any, List

from resoto_plugin_aws.config import AwsConfig
from resotolib.json import to_json
from resotolib.types import Json, JsonElement

log = logging.getLogger("resoto.plugins.aws")


class AwsClient:
    def __init__(
        self,
        config: AwsConfig,
        account_id: str,
        account_role: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        self.config = config
        self.account_id = account_id
        self.account_role = account_role
        self.region = region

    def call(self, service: str, action: str, result_name: str, **kwargs: Any) -> JsonElement:
        py_action = action.replace("-", "_")
        session = self.config.sessions().session(self.account_id, self.account_role)
        client = session.client(service, region_name=self.region)
        if client.can_paginate(py_action):
            paginator = client.get_paginator(py_action)
            result: List[Json] = []
            for page in paginator.paginate(**kwargs):
                result.extend(to_json(page).get(result_name, []))
            return result
        else:
            result = getattr(client, py_action)(**kwargs)
            return to_json(result).get(result_name)

    def list(self, service: str, action: str, result_name: str, **kwargs: Any) -> List[Any]:
        return self.call(service, action, result_name, **kwargs) or []  # type: ignore

    def get(self, service: str, action: str, result_name: str, **kwargs: Any) -> Optional[Json]:
        return self.call(service, action, result_name, **kwargs)  # type: ignore

    def for_region(self, region: str) -> AwsClient:
        return AwsClient(self.config, self.account_id, self.account_role, region)
