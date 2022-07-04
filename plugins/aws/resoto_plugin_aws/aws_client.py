from __future__ import annotations

import logging
from typing import Optional, Any, List

from resoto_plugin_aws.config import AwsConfig
from resotolib.json import to_json
from resotolib.types import Json

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

    def call(self, service: str, action: str, **kwargs: Any) -> Json:
        session = self.config.sessions.session(self.account_id, self.account_role)
        client = session.client(service, region_name=self.region)
        result = getattr(client, action.replace("-", "_"))(**kwargs)
        return to_json(result)

    def list(self, service: str, action: str, result_name: str, **kwargs: Any) -> List[Any]:
        response = self.call(service, action, **kwargs)
        return response.get(result_name, [])

    def get(self, service: str, action: str, result_name: str, **kwargs: Any) -> Optional[Json]:
        response = self.call(service, action, **kwargs)
        return response.get(result_name)

    def for_region(self, region: str) -> AwsClient:
        return AwsClient(self.config, self.account_id, self.account_role, region)
