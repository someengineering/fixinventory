from queue import Queue

from pytest import fixture

from resoto_plugin_aws.collector import AwsAccountCollector
from resoto_plugin_aws.configuration import AwsConfig
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsAccount, AwsRegion, GraphBuilder, ExecutorQueue
from resotolib.baseresources import Cloud
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph
from test.resources import BotoFileBasedSession, DummyExecutor


@fixture
def aws_config() -> AwsConfig:
    config = AwsConfig()
    config.sessions().session_class_factory = BotoFileBasedSession
    return config


@fixture
def aws_client(aws_config: AwsConfig) -> AwsClient:
    return AwsClient(aws_config, "test", region="us-east-1")


@fixture
def builder(aws_client: AwsClient, no_feedback: CoreFeedback) -> GraphBuilder:
    queue = ExecutorQueue(DummyExecutor(), "dummy")
    return GraphBuilder(
        Graph(), Cloud(id="aws"), AwsAccount(id="test"), AwsRegion(id="us-east-1"), aws_client, queue, no_feedback
    )


@fixture
def no_feedback() -> CoreFeedback:
    return CoreFeedback("123", "step1", "collect", Queue())


@fixture
def account_collector(aws_config: AwsConfig, no_feedback: CoreFeedback) -> AwsAccountCollector:
    account = AwsAccount(id="123")
    return AwsAccountCollector(aws_config, Cloud(id="aws"), account, ["us-east-1"], no_feedback)
