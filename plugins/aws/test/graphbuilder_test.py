from typing import List

from resoto_plugin_aws.resource.base import GraphBuilder, AwsRegion
from resoto_plugin_aws.resource.ec2 import AwsEc2InstanceType

from test import builder, aws_client, aws_config, no_feedback  # noqa: F401


def test_instance_type(builder: GraphBuilder) -> None:
    builder.global_instance_types["m4.large"] = AwsEc2InstanceType(id="m4.large")
    m4l: AwsEc2InstanceType = builder.instance_type("m4.large")  # type: ignore
    assert m4l == builder.instance_type("m4.large")
    assert m4l.ondemand_cost == 0.051
    eu_builder = builder.for_region(AwsRegion(id="eu-central-1"))
    m4l_eu: AwsEc2InstanceType = eu_builder.instance_type("m4.large")  # type: ignore
    assert m4l != m4l_eu
    assert m4l_eu == eu_builder.instance_type("m4.large")
    assert m4l_eu.ondemand_cost == 0.12


def test_executor(builder: GraphBuilder) -> None:
    result: List[int] = []

    def do_something(key: int) -> None:
        result.append(key)

    for idx in range(0, 100):
        builder.submit_work(do_something, idx)

    builder.executor.wait_for_submitted_work()
    assert result == list(range(0, 100))
