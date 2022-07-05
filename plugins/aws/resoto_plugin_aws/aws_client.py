from __future__ import annotations

import logging
from typing import Optional, Any

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

    def call(self, service: str, action: str, *args: Any) -> Json:
        session = self.config.sessions.session(self.account_id, self.account_role)
        client = session.client(service, region_name=self.region)
        result = getattr(client, action.replace("-", "_"))(*args)
        return to_json(result)

    def for_region(self, region: str) -> AwsClient:
        return AwsClient(self.config, self.account_id, self.account_role, region)
