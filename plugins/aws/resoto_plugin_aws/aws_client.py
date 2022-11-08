from __future__ import annotations

import logging
from datetime import datetime
from functools import cached_property
from typing import Optional, Any, List

from botocore.model import ServiceModel
from retrying import retry

from botocore.exceptions import ClientError
from botocore.config import Config

from resoto_plugin_aws.configuration import AwsConfig
from resotolib.core.actions import CoreFeedback
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
        core_feedback: Optional[CoreFeedback] = None,
    ) -> None:
        self.config = config
        self.account_id = account_id
        self.role = role
        self.profile = profile
        self.region = region
        self.core_feedback = core_feedback

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

    def service_model(self, aws_service: str) -> ServiceModel:
        session = self.config.sessions().session(self.account_id, self.role, self.profile)
        client = session.client(aws_service, region_name=self.region)
        return client.meta.service_model

    def call_single(
        self, aws_service: str, action: str, result_name: Optional[str] = None, max_attempts: int = 1, **kwargs: Any
    ) -> JsonElement:
        arg_info = ""
        if kwargs:
            arg_info += " with args " + ", ".join([f"{key}={value}" for key, value in kwargs.items()])
        log.debug(f"[Aws] calling service={aws_service} action={action}{arg_info}")
        py_action = action.replace("-", "_")
        # adaptive mode allows automated client-side throttling
        config = Config(retries={"max_attempts": max_attempts, "mode": "adaptive"})
        session = self.config.sessions().session(self.account_id, self.role, self.profile)
        client = session.client(aws_service, region_name=self.region, config=config)
        if client.can_paginate(py_action):
            paginator = client.get_paginator(py_action)
            result: List[Json] = []
            for page in paginator.paginate(**kwargs):
                log.debug2(f"[Aws] Get next page for service={aws_service} action={action}{arg_info}")  # type: ignore
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

    @retry(  # type: ignore
        stop_max_attempt_number=10,
        wait_exponential_multiplier=3000,
        wait_exponential_max=300000,
        retry_on_exception=is_retryable_exception,
    )
    @log_runtime
    def call(
        self,
        aws_service: str,
        action: str,
        result_name: Optional[str],
        expected_errors: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> JsonElement:
        def log_error(message: str, as_warning: bool = False) -> None:
            if as_warning:
                log.warning(message)
                if self.core_feedback:
                    self.core_feedback.info(message)
            else:
                log.error(message)
                if self.core_feedback:
                    self.core_feedback.error(message)

        try:
            # 5 attempts is the default
            return self.call_single(aws_service, action, result_name, max_attempts=5, **kwargs)
        except ClientError as e:
            expected_errors = expected_errors or []
            code = e.response["Error"]["Code"] or "Unknown Code"
            if code in expected_errors:
                log.debug(f"Expected error: {code}")
                return None
            if code.lower().startswith("accessdenied"):
                # report access denied errors as warnings
                log_error(
                    f"Access denied to call service {aws_service} with action {action} code {code} "
                    f"in account {self.account_id} region {self.region}",
                    as_warning=True,
                )
                return None
            elif code == "UnauthorizedOperation":
                log_error(
                    f"Call to {aws_service} action {action} in account {self.account_id} region {self.region}"
                    " is not authorized! Give up."
                )
                raise  # not allowed to collect in account/region
            elif code in RetryableErrors:
                log_error(f"Call to {aws_service} action {action} has been retried too many times. Give up.")
                raise  # already have been retried, give up here
            else:
                log_error(
                    f"An AWS API error {code} occurred during resource collection of {aws_service} action {action} in "  # noqa: E501
                    f"account {self.account_id} region {self.region} - skipping resources"
                )
                return None

    def list(
        self,
        aws_service: str,
        action: str,
        result_name: Optional[str],
        expected_errors: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[Any]:
        return self.call(aws_service, action, result_name, expected_errors, **kwargs) or []

    def get(
        self,
        aws_service: str,
        action: str,
        result_name: Optional[str],
        expected_errors: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> Optional[Json]:
        return self.call(aws_service, action, result_name, expected_errors, **kwargs)  # type: ignore

    def for_region(self, region: str) -> AwsClient:
        return AwsClient(
            self.config,
            self.account_id,
            role=self.role,
            profile=self.profile,
            region=region,
            core_feedback=self.core_feedback,
        )

    @cached_property
    def global_region(self) -> AwsClient:
        """
        AWS serves some APIs only from one region: us-east-1.
        We call it the global region in this collector.
        """
        return self.for_region("us-east-1")
