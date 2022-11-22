from __future__ import annotations

import logging
from datetime import datetime
from functools import cached_property
from typing import Optional, Any, List, TypeVar, Callable

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
T = TypeVar("T")


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

    def with_resource(self, aws_service: str, fn: Callable[[Any], T]) -> Optional[T]:
        """
        Create a boto service resource model and call the given function with it.
        The service model is created dynamically in boto3, so we can not give it a proper type, hence Any.
        Advantage: the scope of the resource is defined by this function, exceptions are handled in the client.
        :param aws_service: the service to use.
        :param fn: loan pattern: the function is handed the resource and the result is returned.
        :return: the result of the function.
        """
        session = self.config.sessions().session(self.account_id, self.role, self.profile)
        resource = session.resource(aws_service, region_name=self.region)
        try:
            return fn(resource)
        except ClientError as e:
            self.__handle_client_error(e, aws_service, "service_resource")  # might reraise the exception
            return None

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
                else:
                    child = next_page.get(result_name)
                    if isinstance(child, list):
                        result.extend(child)
                    elif child is not None:
                        result.append(child)
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
        try:
            # 5 attempts is the default
            return self.call_single(aws_service, action, result_name, max_attempts=5, **kwargs)
        except ClientError as e:
            self.__handle_client_error(e, aws_service, action, expected_errors)  # might reraise the exception
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

    def __handle_client_error(
        self, e: ClientError, aws_service: str, action: str, expected_errors: Optional[List[str]] = None
    ) -> None:
        def log_error(message: str, as_warning: bool = False) -> None:
            if as_warning:
                log.warning(message)
                if self.core_feedback:
                    self.core_feedback.info(message)
            else:
                log.error(message)
                if self.core_feedback:
                    self.core_feedback.error(message)

        expected_errors = expected_errors or []
        code = e.response["Error"]["Code"] or "Unknown Code"
        if code in expected_errors:
            log.debug(f"Expected error: {code}")
        elif code.lower().startswith("accessdenied"):
            log_error(
                f"Access denied to call service {aws_service} with action {action} code {code} "
                f"in account {self.account_id} region {self.region}.",
                as_warning=True,
            )
        elif code == "UnauthorizedOperation":
            log_error(
                f"Call to {aws_service} action {action} in account {self.account_id} region {self.region}"
                " is not authorized! Giving up."
            )
            raise e  # not allowed to collect in account/region
        elif code in RetryableErrors:
            log_error(f"Call to {aws_service} action {action} has been retried too many times. Giving up.")
            raise e  # already have been retried, give up here
        else:
            log_error(
                f"An AWS API error {code} occurred during resource collection of {aws_service} action {action} in "  # noqa: E501
                f"account {self.account_id} region {self.region} - skipping resources."
            )

    @cached_property
    def global_region(self) -> AwsClient:
        """
        AWS serves some APIs only from one region: us-east-1.
        We call it the global region in this collector.
        """
        return self.for_region("us-east-1")
