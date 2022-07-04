from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.aws_client import AwsClient
from test.resource import BotoFileBasedSession


def test_region() -> None:
    client = AwsClient(AwsConfig(), "test", "test")
    east1 = client.for_region("us-east-1")
    assert client.account_id == east1.account_id
    assert client.account_role == east1.account_role
    assert client.config == east1.config
    assert client.region is None
    assert east1.region == "us-east-1"


def test_call() -> None:
    config = AwsConfig(access_key_id="foo", secret_access_key="bar")
    config.sessions.session_class_factory = BotoFileBasedSession
    client = AwsClient(config, "test")
    reservations = client.call("ec2", "describe-instances")
    instances = reservations.get("Reservations", [])
    assert len(instances) == 2
