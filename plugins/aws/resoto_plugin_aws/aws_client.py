from __future__ import annotations

import logging
from datetime import datetime
from functools import cached_property
from typing import Optional, Any, List
from retrying import retry

from botocore.exceptions import ClientError
from botocore.config import Config

from resoto_plugin_aws.config import AwsConfig
from resotolib.types import Json, JsonElement
from resotolib.utils import utc_str, log_runtime

log = logging.getLogger("resoto.plugins.aws")

RetryableErrors = ("RequestLimitExceeded", "Throttling", "TooManyRequestsException")


def is_retryable_exception(e: Exception) -> bool:
    if isinstance(e, ClientError):
        if e.response["Error"]["Code"] in RetryableErrors:
            log.debug("AWS API request limit exceeded or throttling, retrying with exponential backoff")
            return True
    return False


class AwsClient:
    def __init__(
        self,
        config: AwsConfig,
        account_id: str,
        *,
        role: Optional[str] = None,
        profile: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        self.config = config
        self.account_id = account_id
        self.role = role
        self.profile = profile
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

    @retry(  # type: ignore
        stop_max_attempt_number=10,
        wait_exponential_multiplier=3000,
        wait_exponential_max=300000,
        retry_on_exception=is_retryable_exception,
    )
    @log_runtime
    def call(self, aws_service: str, action: str, result_name: Optional[str], **kwargs: Any) -> JsonElement:
        arg_info = ""
        if kwargs:
            arg_info += " with args " + ", ".join([f"{key}={value}" for key, value in kwargs.items()])
        log.debug(f"[Aws] calling service={aws_service} action={action}{arg_info}")
        py_action = action.replace("-", "_")
        # 5 attempts is the default, and the adaptive mode allows automated client-side throttling
        config = Config(retries={"max_attempts": 5, "mode": "adaptive"})
        session = self.config.sessions().session(self.account_id, self.role, self.profile)
        client = session.client(aws_service, region_name=self.region, config=config)
        if client.can_paginate(py_action):
            paginator = client.get_paginator(py_action)
            result: List[Json] = []
            for page in paginator.paginate(**kwargs):
                log.debug(f"[Aws] Get next page for service={aws_service} action={action}{arg_info}")
                next_page: Json = self.__to_json(page)  # type: ignore
                if result_name is None:
                    # the whole object is appended
                    result.append(next_page)
                elif isinstance(list_result := next_page.get(result_name, []), list):
                    # extend the list with the list result under given key
                    result.extend(list_result)
                else:
                    raise AttributeError(f"Expected list result under key '{result_name}'")
            log.debug(f"[Aws] called service={aws_service} action={action}{arg_info}: {len(result)} results.")
            return result
        else:
            result = getattr(client, py_action)(**kwargs)
            single: Json = self.__to_json(result)  # type: ignore
            log.debug(f"[Aws] called service={aws_service} action={action}{arg_info}: single result")
            return single.get(result_name) if result_name else [single]

    def call_handle(self, aws_service: str, action: str, result_name: Optional[str], **kwargs: Any) -> JsonElement:
        try:
            return self.call(aws_service, action, result_name, **kwargs)  # type: ignore
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDenied":
                log.error(f"Access denied to collect resources in account {self.account_id} region {self.region}")
                return None
            elif code == "UnauthorizedOperation":
                raise  # not allowed to collect in account/region
            elif code in RetryableErrors:
                raise  # already have been retried, give up here
            else:
                log.exception(
                    (
                        f"An AWS API error {code} occurred during resource collection of {aws_service} action {action} in "  # noqa: E501
                        f"account {self.account_id} region {self.region} - skipping resources"
                    )
                )
                return None

    def list(self, aws_service: str, action: str, result_name: Optional[str], **kwargs: Any) -> List[Any]:
        return self.call_handle(aws_service, action, result_name, **kwargs) or []  # type: ignore

    def get(self, aws_service: str, action: str, result_name: Optional[str], **kwargs: Any) -> Optional[Json]:
        return self.call_handle(aws_service, action, result_name, **kwargs)  # type: ignore

    def for_region(self, region: str) -> AwsClient:
        return AwsClient(self.config, self.account_id, role=self.role, profile=self.profile, region=region)

    @cached_property
    def global_region(self) -> AwsClient:
        """
        AWS serves some APIs only from one region: us-east-1.
        We call it the global region in this collector.
        """
        return self.for_region("us-east-1")
