from typing import List

from fixlib.json import value_in_path
from fix_plugin_aws.resource.base import GraphBuilder, AwsRegion
from fix_plugin_aws.resource.ec2 import AwsEc2InstanceType
from fixinventorydata.cloud import instances as cloud_instance_data

from test import builder, aws_client, aws_config, no_feedback  # noqa: F401


def test_instance_type(builder: GraphBuilder) -> None:
    instance_type = "m4.large"
    builder.global_instance_types[instance_type] = AwsEc2InstanceType(id=instance_type)
    m4l: AwsEc2InstanceType = builder.instance_type(builder.region, instance_type)  # type: ignore
    assert m4l == builder.instance_type(builder.region, instance_type)  # type: ignore
    assert m4l.ondemand_cost == value_in_path(
        cloud_instance_data, ["aws", instance_type, "pricing", builder.region.id, "linux", "ondemand"]
    )
    eu_builder = builder.for_region(AwsRegion(id="eu-central-1"))
    m4l_eu: AwsEc2InstanceType = eu_builder.instance_type(eu_builder.region, instance_type)  # type: ignore
    assert m4l != m4l_eu
    assert m4l_eu == eu_builder.instance_type(eu_builder.region, instance_type)  # type: ignore
    assert m4l_eu.ondemand_cost == value_in_path(
        cloud_instance_data, ["aws", instance_type, "pricing", eu_builder.region.id, "linux", "ondemand"]
    )


def test_executor(builder: GraphBuilder) -> None:
    result: List[int] = []

    def do_something(key: int) -> None:
        result.append(key)

    for idx in range(0, 100):
        builder.submit_work("test", do_something, idx)

    builder.executor.wait_for_submitted_work()
    assert result == list(range(0, 100))
