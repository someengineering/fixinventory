from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.collector import AwsAccountCollector
from resoto_plugin_aws.resource.base import AWSAccount, AWSResource
from resotolib.baseresources import Cloud
from test.resource import BotoFileBasedSession


def test_collect() -> None:
    config = AwsConfig("test", "test", "test")
    config.sessions.session_class_factory = BotoFileBasedSession
    account = AWSAccount("123")
    collector = AwsAccountCollector(config, Cloud("aws"), account, ["us-east-1"])
    collector.collect()
    for node in collector.graph.nodes:
        assert isinstance(node, AWSResource)
    assert len(collector.graph.nodes) == 20
    assert len(collector.graph.edges) == 32
