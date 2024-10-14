from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from typing import Iterator

from pytest import fixture

from fix_plugin_aws.collector import AwsAccountCollector
from fix_plugin_aws.configuration import AwsConfig
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsAccount, AwsRegion, GraphBuilder
from fixlib.baseresources import Cloud
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph
from fixlib.threading import ExecutorQueue
from test.resources import BotoFileBasedSession


@fixture
def aws_config() -> AwsConfig:
    config = AwsConfig(discard_account_on_resource_error=True, collect_access_edges=False)
    config.sessions().session_class_factory = BotoFileBasedSession
    return config


@fixture
def aws_client(aws_config: AwsConfig) -> AwsClient:
    return AwsClient(aws_config, "test", region="us-east-1")


@fixture
def builder(aws_client: AwsClient, no_feedback: CoreFeedback) -> Iterator[GraphBuilder]:
    with ThreadPoolExecutor(1) as executor:
        queue = ExecutorQueue(executor, "dummy", lambda _: 1)
        regions = [AwsRegion(id="us-east-1"), AwsRegion(id="eu-central-1")]
        yield GraphBuilder(
            Graph(),
            Cloud(id="aws"),
            AwsAccount(id="test", arn="arn:aws:organizations::123456789012:account/o-exampleorgid/123456789012"),
            regions[0],
            {r.id: r for r in regions},
            aws_client,
            queue,
            no_feedback,
        )


@fixture
def no_feedback() -> CoreFeedback:
    return CoreFeedback("123", "step1", "collect", Queue())


@fixture
def account_collector(aws_config: AwsConfig, no_feedback: CoreFeedback) -> AwsAccountCollector:
    account = AwsAccount(id="test", arn="arn:aws:organizations::123456789012:account/o-exampleorgid/123456789012")
    return AwsAccountCollector(aws_config, Cloud(id="aws"), account, ["us-east-1"], no_feedback, {})
