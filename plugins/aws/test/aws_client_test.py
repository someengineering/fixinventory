from typing import Tuple

from botocore.exceptions import ClientError

from fix_plugin_aws.aws_client import AwsClient, is_retryable_exception
from fix_plugin_aws.configuration import AwsConfig
from fixlib.core.actions import ErrorAccumulator
from test.resources import BotoFileBasedSession, BotoErrorSession


def test_region() -> None:
    client = AwsClient(AwsConfig(), "test", role="test")
    east1 = client.for_region("us-east-1")
    assert client.account_id == east1.account_id
    assert client.role == east1.role
    assert client.config == east1.config
    assert client.region is None
    assert east1.region == "us-east-1"


def test_call() -> None:
    config = AwsConfig(access_key_id="foo", secret_access_key="bar")
    config.sessions().session_class_factory = BotoFileBasedSession
    client = AwsClient(config, "test")
    instances = client.list("ec2", "describe-instances", "Reservations")
    assert len(instances) == 3


def test_retry_for() -> None:
    config = AwsConfig(access_key_id="foo", secret_access_key="bar")
    config.sessions().session_class_factory = BotoFileBasedSession
    aws_cn = AwsClient(config, "test", partition="aws-cn")
    aws = AwsClient(config, "test", partition="aws")
    throttled = "ThrottlingException"
    timeout = "RequestTimeout"

    # ec2 is not fully covered in aws-cn, but is in aws
    assert aws_cn.retry_for("ec2", throttled) is False
    assert aws.retry_for("ec2", throttled) is True

    # timeout errors are retryable everywhere
    assert aws_cn.retry_for("ec2", timeout) is True
    assert aws.retry_for("ec2", timeout) is True

    # s3 is fully covered everywhere
    assert aws_cn.retry_for("s3", throttled) is True
    assert aws.retry_for("s3", throttled) is True


def test_error_handling() -> None:
    def with_error(code: str, message: str) -> Tuple[AwsClient, ErrorAccumulator]:
        config = AwsConfig()
        config.sessions().session_class_factory = BotoErrorSession(
            ClientError({"Error": {"Code": code, "Message": message}}, "foo")
        )
        error_accumulator = ErrorAccumulator()
        return AwsClient(config, "test", error_accumulator=error_accumulator), error_accumulator

    unauthorized_client, accu_unauthorized = with_error("UnauthorizedOperation", "Err!")
    # this error is raised for the operation
    unauthorized_client.list("ec2", "foo", None)
    assert len(accu_unauthorized.regional_errors) == 1
    # we can silent this error by passing the expected error code
    assert unauthorized_client.list("ec2", "foo", None, ["UnauthorizedOperation"]) == []
    assert unauthorized_client.get("ec2", "foo", None, ["UnauthorizedOperation"]) is None
    assert len(accu_unauthorized.regional_errors) == 1

    access_denied_client, queue_access_denied = with_error("AccessDenied", "Err!")
    # this error is only logged
    assert access_denied_client.list("ec2", "foo", None) == []
    assert access_denied_client.get("ec2", "foo", None) is None
    assert len(queue_access_denied.regional_errors) == 1
    # no additional error is logged
    assert access_denied_client.list("ec2", "foo", None, ["AccessDenied"]) == []
    assert access_denied_client.get("ec2", "foo", None, ["AccessDenied"]) is None
    assert len(queue_access_denied.regional_errors) == 1

    some_error_client, queue_some_error = with_error("some_error", "Err!")
    # this error is only logged
    assert some_error_client.list("ec2", "foo", None) == []
    assert some_error_client.get("ec2", "foo", None) is None
    assert len(queue_some_error.regional_errors) == 1
    # no additional error is logged
    assert some_error_client.list("ec2", "foo", None, ["some_error"]) == []
    assert some_error_client.get("ec2", "foo", None, ["some_error"]) is None
    assert len(queue_some_error.regional_errors) == 1


def test_is_retryable() -> None:
    def check_code(code: str, expected: bool) -> None:
        assert is_retryable_exception(ClientError({"Error": {"Code": code, "Message": "eff"}}, "foo")) is expected

    check_code("ThrottlingException", True)
    check_code("RequestLimitExceeded", True)
    check_code("AccessDenied", False)
    check_code("UnauthorizedOperation", False)
