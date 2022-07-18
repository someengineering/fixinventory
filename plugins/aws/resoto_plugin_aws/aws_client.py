from __future__ import annotations

import logging
from datetime import datetime
from functools import cached_property
from typing import Optional, Any, List

from resoto_plugin_aws.config import AwsConfig
from resotolib.types import Json, JsonElement
from resotolib.utils import utc_str

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

    def __to_json(self, node: Any, **kwargs: Any) -> JsonElement:
        if node is None or isinstance(node, (str, int, float, bool)):
            return node
        elif isinstance(node, list):
            return [self.__to_json(item, **kwargs) for item in node]
        elif isinstance(node, dict):
            return {key: self.__to_json(value, **kwargs) for key, value in node.items()}
        elif isinstance(node, datetime):
            return utc_str(node)
        else:
            raise AttributeError(f"Unsupported type: {type(node)}")

    def call(self, service: str, action: str, result_name: Optional[str], **kwargs: Any) -> JsonElement:
        log.info(f"[Aws] call service={service} action={action} with_args={kwargs}")
        py_action = action.replace("-", "_")
        session = self.config.sessions().session(self.account_id, self.account_role)
        client = session.client(service, region_name=self.region)
        if client.can_paginate(py_action):
            paginator = client.get_paginator(py_action)
            result: List[Json] = []
            for page in paginator.paginate(**kwargs):
                next_page: Json = self.__to_json(page)  # type: ignore
                if result_name is None:
                    # the whole object is appended
                    result.append(next_page)
                elif isinstance(list_result := next_page.get(result_name, []), list):
                    # extend the list with the list result under given key
                    result.extend(list_result)
                else:
                    raise AttributeError("Expected list result under key '{}'".format(result_name))
            log.info(f"[Aws] call service={service} action={action} with_args={kwargs}: {len(result)} results.")
            return result
        else:
            result = getattr(client, py_action)(**kwargs)
            single: Json = self.__to_json(result)  # type: ignore
            log.info(f"[Aws] call service={service} action={action} with_args={kwargs}: single result")
            return single.get(result_name) if result_name else [single]

    def list(self, service: str, action: str, result_name: Optional[str], **kwargs: Any) -> List[Any]:
        return self.call(service, action, result_name, **kwargs) or []  # type: ignore

    def get(self, service: str, action: str, result_name: Optional[str], **kwargs: Any) -> Optional[Json]:
        return self.call(service, action, result_name, **kwargs)  # type: ignore

    def for_region(self, region: str) -> AwsClient:
        return AwsClient(self.config, self.account_id, self.account_role, region)

    @cached_property
    def global_region(self) -> AwsClient:
        """
        AWS serves some APIs only from one region: us-east-1.
        We call it the global region in this collector.
        """
        return self.for_region("us-east-1")
