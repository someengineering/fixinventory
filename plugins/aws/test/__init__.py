from pytest import fixture

from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsAccount, AwsRegion, GraphBuilder
from resotolib.baseresources import Cloud
from resotolib.graph import Graph
from test.resources import BotoFileBasedSession


@fixture
def aws_client() -> AwsClient:
    config = AwsConfig()
    config.sessions().session_class_factory = BotoFileBasedSession
    return AwsClient(config, "test", None, "us-east-1")


@fixture
def builder(aws_client: AwsClient) -> GraphBuilder:
    return GraphBuilder(Graph(), Cloud("aws"), AwsAccount("test"), AwsRegion("us-east-1"), aws_client)
