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

    def call(self, service: str, action: str, result_name: Optional[str], **kwargs: Any) -> JsonElement:
        py_action = action.replace("-", "_")
        session = self.config.sessions().session(self.account_id, self.account_role)
        client = session.client(service, region_name=self.region)
        if client.can_paginate(py_action):
            paginator = client.get_paginator(py_action)
            result: List[Json] = []
            for page in paginator.paginate(**kwargs):
                next_page = to_json(page)
                if result_name is None:
                    # the whole object is appended
                    result.append(next_page)
                elif isinstance(list_result := next_page.get(result_name, []), list):
                    # extend the list with the list result under given key
                    result.extend(list_result)
                else:
                    raise AttributeError("Expected list result under key '{}'".format(result_name))
            return result
        else:
            result = getattr(client, py_action)(**kwargs)
            single = to_json(result)
            return single.get(result_name) if result_name else [single]

    def list(self, service: str, action: str, result_name: Optional[str], **kwargs: Any) -> List[Any]:
        return self.call(service, action, result_name, **kwargs) or []  # type: ignore

    def get(self, service: str, action: str, result_name: Optional[str], **kwargs: Any) -> Optional[Json]:
        return self.call(service, action, result_name, **kwargs)  # type: ignore

    def for_region(self, region: str) -> AwsClient:
        return AwsClient(self.config, self.account_id, self.account_role, region)
