from __future__ import annotations

import logging
from datetime import datetime
from functools import cached_property
from itertools import islice
from typing import Optional, Any, List, TypeVar, Callable, Dict, Set

from attr import define, field
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.model import ServiceModel
from retrying import retry

from resoto_plugin_aws.configuration import AwsConfig
from resotolib.core.actions import CoreFeedback
from resotolib.json import value_in_path
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


@define
class ErrorSummary:
    error: str
    message: str
    info: bool
    region: Optional[str] = None
    service_actions: Dict[str, Set[str]] = field(factory=dict)


class ErrorAccumulator:
    def __init__(self) -> None:
        self.regional_errors: Dict[Optional[str], Dict[str, ErrorSummary]] = {}

    def add_error(
        self,
        as_info: bool,
        error_kind: str,
        service: str,
        action: str,
        message: str,
        region: Optional[str],
    ) -> None:
        if region not in self.regional_errors:
            self.regional_errors[region] = {}
        regional_errors = self.regional_errors[region]

        key = f"{error_kind}:{message}:{as_info}"
        if key not in regional_errors:
            regional_errors[key] = ErrorSummary(error_kind, message, as_info, region, {service: {action}})
        else:
            summary = regional_errors[key]
            if service not in summary.service_actions:
                summary.service_actions[service] = {action}
            else:
                summary.service_actions[service].add(action)

    def report_region(self, core_feedback: CoreFeedback, region: Optional[str]) -> None:
        if regional_errors := self.regional_errors.get(region):
            # reset errors for this region
            self.regional_errors[region] = {}
            # add region as context
            feedback = core_feedback.child_context(region) if region else core_feedback
            # send to core
            for err in regional_errors.values():
                srv_acts = []
                for aws_service, actions in islice(err.service_actions.items(), 10):
                    suffix = " and more" if len(actions) > 3 else ""
                    srv_acts.append(aws_service + ": " + ", ".join(islice(actions, 3)) + suffix)
                message = f"[{err.error}] {err.message} Services and actions affected: {', '.join(srv_acts)}"
                if len(err.service_actions) > 10:
                    message += " and more..."
                if err.info:
                    feedback.info(message)
                else:
                    feedback.error(message)

    def report_all(self, core_feedback: CoreFeedback) -> None:
        for region in self.regional_errors.keys():
            self.report_region(core_feedback, region)


class AwsClient:
    def __init__(
        self,
        config: AwsConfig,
        account_id: str,
        *,
        role: Optional[str] = None,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        error_accumulator: Optional[ErrorAccumulator] = None,
    ) -> None:
        self.config = config
        self.account_id = account_id
        self.role = role
        self.profile = profile
        self.region = region
        self.error_accumulator = error_accumulator

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
        except EndpointConnectionError as e:
            log.debug(f"The Aws endpoint does not exist in this region. Skipping. {e}")
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
                    child = value_in_path(next_page, result_name)
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
            return value_in_path(single, result_name) if result_name else single

    @retry(  # type: ignore
        stop_max_attempt_number=10,
        wait_exponential_multiplier=3000,
        wait_exponential_max=300000,
        retry_on_exception=is_retryable_exception,
    )
    @log_runtime
    def get_with_retry(
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
        except EndpointConnectionError as e:
            log.debug(f"The Aws endpoint does not exist in this region. Skipping. {e}")
            return None

    @log_runtime
    def call(
        self,
        aws_service: str,
        action: str,
        result_name: Optional[str],
        expected_errors: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> JsonElement:
        return self.call_single(aws_service, action, result_name, max_attempts=1, **kwargs)

    def list(
        self,
        aws_service: str,
        action: str,
        result_name: Optional[str],
        expected_errors: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[Any]:
        res = self.get_with_retry(aws_service, action, result_name, expected_errors, **kwargs)
        if res is None:
            return []
        elif isinstance(res, list):
            return res
        else:
            return [res]

    def get(
        self,
        aws_service: str,
        action: str,
        result_name: Optional[str],
        expected_errors: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> Optional[Json]:
        return self.get_with_retry(aws_service, action, result_name, expected_errors, **kwargs)  # type: ignore

    def for_region(self, region: str) -> AwsClient:
        return AwsClient(
            self.config,
            self.account_id,
            role=self.role,
            profile=self.profile,
            region=region,
            error_accumulator=self.error_accumulator,
        )

    def __handle_client_error(
        self, e: ClientError, aws_service: str, action: str, expected_errors: Optional[List[str]] = None
    ) -> None:
        def accumulate(error_kind: str, message: str, as_info: bool = False) -> None:
            if self.error_accumulator:
                self.error_accumulator.add_error(as_info, error_kind, aws_service, action, message, self.region)

        expected_errors = expected_errors or []
        code = e.response["Error"]["Code"] or "Unknown Code"
        if code in expected_errors:
            log.debug(f"Expected error: {code}")
        elif code.lower().startswith("accessdenied"):
            log.warning(
                f"Access denied to call service {aws_service} with action {action} code {code} "
                f"in account {self.account_id} region {self.region}: {e}"
            )
            accumulate("AccessDenied", "Access denied to call service.", as_info=True)
        elif code == "UnauthorizedOperation":
            log.error(
                f"Call to {aws_service} action {action} in account {self.account_id} region {self.region}"
                f" is not authorized! Giving up: {e}"
            )
            accumulate("UnauthorizedOperation", "Call to AWS API is not authorized!")
            raise e  # not allowed to collect in account/region
        elif code in RetryableErrors:
            log.error(f"Call to {aws_service} action {action} has been retried too many times. Giving up: {e}")
            accumulate("TooManyRetries", "Call has been retried too often.")
            raise e  # already have been retried, give up here
        else:
            log.error(
                f"An AWS API error {code} occurred during resource collection of {aws_service} action {action} in "  # noqa: E501
                f"account {self.account_id} region {self.region} - skipping resources: {e}"
            )
            accumulate(code, f"An AWS API error occurred during resource collection: {code}. Skipping resources.")

    @cached_property
    def global_region(self) -> AwsClient:
        """
        AWS serves some APIs only from one region: us-east-1.
        We call it the global region in this collector.
        """
        return self.for_region("us-east-1")
