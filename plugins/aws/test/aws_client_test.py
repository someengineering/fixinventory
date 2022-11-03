from queue import Queue
from typing import Tuple

import pytest
from botocore.exceptions import ClientError

from resoto_plugin_aws.configuration import AwsConfig
from resoto_plugin_aws.aws_client import AwsClient
from resotolib.core.actions import CoreFeedback
from resotolib.types import Json
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
    def with_error(code: str, message: str) -> Tuple[AwsClient, Queue[Json]]:
        config = AwsConfig()
        config.sessions().session_class_factory = BotoErrorSession(
            ClientError({"Error": {"Code": code, "Message": message}}, "foo")
        )
        error_queue: Queue[Json] = Queue()
        return AwsClient(config, "test", core_feedback=CoreFeedback("test", "test", "test", error_queue)), error_queue

    unauthorized_client, queue_unauthorized = with_error("UnauthorizedOperation", "Err!")
    # this error is raised for the operation
    with pytest.raises(ClientError) as ex:
        unauthorized_client.list("ec2", "foo", None)
    assert str(ex.value) == "An error occurred (UnauthorizedOperation) when calling the foo operation: Err!"
    assert queue_unauthorized.qsize() == 1
    # we can silent this error by passing the expected error code
    assert unauthorized_client.list("ec2", "foo", None, ["UnauthorizedOperation"]) == []
    assert unauthorized_client.get("ec2", "foo", None, ["UnauthorizedOperation"]) is None
    assert queue_unauthorized.qsize() == 1

    access_denied_client, queue_access_denied = with_error("AccessDenied", "Err!")
    # this error is only logged
    assert access_denied_client.list("ec2", "foo", None) == []
    assert access_denied_client.get("ec2", "foo", None) is None
    assert queue_access_denied.qsize() == 2
    # no additional error is logged
    assert access_denied_client.list("ec2", "foo", None, ["AccessDenied"]) == []
    assert access_denied_client.get("ec2", "foo", None, ["AccessDenied"]) is None
    assert queue_access_denied.qsize() == 2

    some_error_client, queue_some_error = with_error("some_error", "Err!")
    # this error is only logged
    assert some_error_client.list("ec2", "foo", None) == []
    assert some_error_client.get("ec2", "foo", None) is None
    assert queue_some_error.qsize() == 2
    # no additional error is logged
    assert some_error_client.list("ec2", "foo", None, ["some_error"]) == []
    assert some_error_client.get("ec2", "foo", None, ["some_error"]) is None
    assert queue_some_error.qsize() == 2
