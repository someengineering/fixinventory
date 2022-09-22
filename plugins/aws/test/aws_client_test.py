from resoto_plugin_aws.configuration import AwsConfig
from resoto_plugin_aws.aws_client import AwsClient
from test.resources import BotoFileBasedSession


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
