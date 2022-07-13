from typing import Type

from resoto_plugin_aws.collector import AwsAccountCollector, all_resources
from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.resource.base import AwsAccount, AwsResource
from resotolib.baseresources import Cloud
from test.resources import BotoFileBasedSession


def test_collect() -> None:
    config = AwsConfig("test", "test", "test")
    config.sessions().session_class_factory = BotoFileBasedSession
    account = AwsAccount(id="123")
    ac = AwsAccountCollector(config, Cloud(id="aws"), account, ["us-east-1"])
    ac.collect()

    def count_kind(clazz: Type[AwsResource]) -> int:
        count = 0
        for node in ac.graph.nodes:
            if isinstance(node, clazz):
                count += 1
        return count

    assert len(ac.graph.edges) == 205
    assert count_kind(AwsResource) == 86
    for resource in all_resources:
        assert count_kind(resource) > 0, "No instances of {} found".format(resource.__name__)
