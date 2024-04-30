from __future__ import annotations

import logging
from datetime import datetime
from functools import cached_property
from typing import Any, Callable, List, Optional, TypeVar

from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.model import ServiceModel
from retrying import retry

from fix_plugin_aws.configuration import AwsConfig
from fixlib.core.actions import ErrorAccumulator
from fixlib.json import value_in_path
from fixlib.types import Json, JsonElement
from fixlib.utils import log_runtime, utc_str
from .utils import global_region_by_partition

log = logging.getLogger("fix.plugins.aws")

ThrottlingErrors = {
    "EC2ThrottledException",
    "RequestThrottled",
    "RequestThrottledException",
    "ThrottledException",
    "Throttling",
    "ThrottlingException",
}
RetryableErrors = ThrottlingErrors | {
    "LimitExceededException",
    "RequestLimitExceeded",
    "RequestTimeout",
    "RequestTimeoutException",
    "TooManyRequestsException",
}
AuthErrors = {"AuthorizationError", "AuthFailure", "AuthFailureException"}
SessionErrors = {"UnrecognizedClientException", "InvalidClientTokenId"}
T = TypeVar("T")


def is_retryable_exception(e: Exception) -> bool:
    if isinstance(e, ClientError) and e.response["Error"]["Code"] in RetryableErrors:
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
        partition: Optional[str] = None,
        error_accumulator: Optional[ErrorAccumulator] = None,
    ) -> None:
        self.config = config
        self.account_id = account_id
        self.role = role
        self.profile = profile
        self.region = region
        if partition is None:
            partition = "aws"
        self.partition = partition
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
        elif isinstance(node, bytes):
            return node.decode("utf-8")
        else:
            raise AttributeError(f"Unsupported type: {type(node)}")

    def service_model(self, aws_service: str) -> ServiceModel:
        client = self.config.sessions().client(
            aws_account=self.account_id,
            aws_role=self.role,
            aws_profile=self.profile,
            aws_service=aws_service,
            region_name=self.region,
            aws_partition=self.partition,
        )
        model = client.meta.service_model
        client.close()
        return model

    def with_resource(self, aws_service: str, fn: Callable[[Any], T]) -> Optional[T]:
        """
        Create a boto service resource model and call the given function with it.
        The service model is created dynamically in boto3, so we can not give it a proper type, hence Any.
        Advantage: the scope of the resource is defined by this function, exceptions are handled in the client.
        :param aws_service: the service to use.
        :param fn: loan pattern: the function is handed the resource and the result is returned.
        :return: the result of the function.
        """
        resource = self.config.sessions().resource(
            aws_account=self.account_id,
            aws_role=self.role,
            aws_profile=self.profile,
            aws_service=aws_service,
            region_name=self.region,
            aws_partition=self.partition,
        )
        try:
            return fn(resource)
        except ClientError as e:
            self.__handle_client_error(e, aws_service, "service_resource")  # might reraise the exception
            return None
        except EndpointConnectionError as e:
            log.debug(f"The Aws endpoint does not exist in this region. Skipping. {e}")
            return None
        except Exception as e:
            log.warning(f"[Aws] called service={aws_service} with resource: hit unexpected error: {e}")
            raise

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
        client = self.config.sessions().client(
            aws_account=self.account_id,
            aws_role=self.role,
            aws_profile=self.profile,
            aws_service=aws_service,
            region_name=self.region,
            config=config,
            aws_partition=self.partition,
        )

        try:
            if client.can_paginate(py_action):
                paginator = client.get_paginator(py_action)
                result: List[Json] = []
                for page in paginator.paginate(**kwargs):
                    log.debug(f"[Aws] Next page for service={aws_service} action={action}{arg_info}")
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
        finally:
            client.close()

    @retry(  # type: ignore
        stop_max_attempt_number=10,  # 10 attempts: 1000 max 60000: max wait time is 5 minutes
        wait_exponential_multiplier=1000,
        wait_exponential_max=60000,
        retry_on_exception=is_retryable_exception,
    )
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
        except Exception as e:
            log.warning(f"[Aws] called service={aws_service} action={action}: hit unexpected error: {e}", exc_info=e)
            if self.config.discard_account_on_resource_error:
                raise
            return None

    @log_runtime
    def call(
        self,
        aws_service: str,
        action: str,
        result_name: Optional[str] = None,
        expected_errors: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> JsonElement:
        try:
            return self.call_single(aws_service, action, result_name, max_attempts=1, **kwargs)
        except ClientError as e:
            expected_errors = expected_errors or []
            code = e.response["Error"]["Code"] or "Unknown Code"
            if code in expected_errors:
                log.debug(f"Expected error: {code}")
                return None
            else:
                raise

    def list(
        self,
        aws_service: str,
        action: str,
        result_name: Optional[str] = None,
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
        result_name: Optional[str] = None,
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
            partition=self.partition,
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
        elif code in AuthErrors or code.lower().startswith("accessdenied"):
            # if disabled explicitly: log as info, otherwise as warnings
            log_line = log.info if "explicit deny in a service control policy" in str(e) else log.warning
            log_line(
                f"Access denied to call service {aws_service} with action {action} code {code} "
                f"in account {self.account_id} region {self.region}: {e}"
            )
            accumulate("AccessDenied", "Access denied to call service.", as_info=True)
        elif code == "UnauthorizedOperation":
            log.warning(
                f"Call to {aws_service} action {action} in account {self.account_id} region {self.region}"
                f" is not authorized! Giving up: {e}"
            )
            accumulate("UnauthorizedOperation", "Call to AWS API is not authorized!")
        elif code in SessionErrors and "security token included in the request is invalid" in str(e):
            # The session is valid for 1h and we refresh it every 10 minutes.
            # There is nothing we can do here - log as warning and give up.
            log.warning(f"Call to {aws_service} action {action} failed: {e}.")
            accumulate(code, f"{aws_service} action {action}: {e}")
        elif code in RetryableErrors and not self.retry_for(aws_service, code):
            log.info(
                f"Call to {aws_service} action {action} failed and is interpreted as unavailable "
                f"in region {self.region}."
            )
            accumulate("RetryableUnavailable", "AWS API is considered unavailable.")
        elif code in RetryableErrors:
            log.warning(f"Call to {aws_service} action {action} failed and will be retried eventually. Error: {e}")
            accumulate("FailedAndRetried", f"Retryable call has failed: {code}.")
            if self.config.discard_account_on_resource_error:
                raise e  # already have been retried, give up here
        else:
            log.warning(
                f"An AWS API error {code} occurred during resource collection of {aws_service} action {action} in "  # noqa: E501
                f"account {self.account_id} region {self.region} - skipping single resource: {e}"
            )
            accumulate(code, f"An AWS API error occurred during resource collection: {code}. Skipping resources.")

    def retry_for(self, aws_service: str, code: str) -> bool:
        """
        This method is called for retryable errors to determine whether we should retry the call or not, based on
        the partition, region, account and service name.

        This is required, since AWS decided to respond with a ThrottlingError for services in the China partition,
        that are not available.
        Since we can not distinguish, whether the service is unavailable or the call was throttled, we have a hard
        coded list of services, that are partially not available in the China partition (API is not covered 100%).
        This list needs to be maintained!
        """
        if self.partition == "aws-cn" and code in ThrottlingErrors:
            # See https://www.amazonaws.cn/en/about-aws/regional-product-services/
            return aws_service not in [
                "cloudfront",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/cloudfront.html
                "cloudtrail",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/cloudtrail.html
                "cognito-idp",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/cognito.html
                "ec2",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/ec2.html
                "iam",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/iam.html
                "kms",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/kms.html
                "lambda",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/lambda.html
                "route53",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/route53.html
                "sagemaker",  # https://docs.amazonaws.cn/en_us/aws/latest/userguide/sagemaker.html
            ]
        return True

    @cached_property
    def global_region(self) -> AwsClient:
        """
        AWS serves some APIs only from a global region.
        """
        return self.for_region(global_region_by_partition(self.partition))
