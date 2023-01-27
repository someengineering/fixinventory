from typing import Tuple

import pytest
from botocore.exceptions import ClientError

from resoto_plugin_aws.aws_client import AwsClient, ErrorAccumulator
from resoto_plugin_aws.configuration import AwsConfig
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
    with pytest.raises(ClientError) as ex:
        unauthorized_client.list("ec2", "foo", None)
    assert str(ex.value) == "An error occurred (UnauthorizedOperation) when calling the foo operation: Err!"
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
