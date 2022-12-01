from types import SimpleNamespace
from typing import cast, Any

from attr import evolve

from resoto_plugin_aws.resource.base import AwsResource
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import GraphBuilder, AwsRegion
from resoto_plugin_aws.resource.ec2 import AwsEc2InstanceType, AwsEc2Vpc
from resoto_plugin_aws.resource.elbv2 import AwsAlb
from resoto_plugin_aws.resource.iam import AwsIamServerCertificate
from resoto_plugin_aws.resource.service_quotas import AwsServiceQuota, RegionalQuotas
from resotolib.baseresources import EdgeType
from test.resources import round_trip_for, build_graph


def test_service_quotas() -> None:
    first, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type")
    assert len(builder.resources_of(AwsServiceQuota)) >= 13


def test_instance_type_quotas() -> None:
    _, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type")
    AwsEc2InstanceType.collect_resources(builder)
    for _, it in builder.global_instance_types.items():
        builder.add_node(it, {})
    expect_quotas(builder, 3)


def test_volume_type_quotas() -> None:
    _, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type")
    for vt in ["gp2", "gp3", "standard", "io1", "io2", "sc1", "st1"]:
        builder.add_node(builder.volume_type(vt), {})  # type: ignore
    expect_quotas(builder, 7)


def test_vpc_quotas() -> None:
    _, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type")
    AwsEc2Vpc.collect_resources(builder)
    expect_quotas(builder, 3)


def test_alb_quotas() -> None:
    _, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type")
    AwsAlb.collect_resources(builder)
    expect_quotas(builder, 2)


def test_iam_server_certificate_quotas() -> None:
    _, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type", region_name="global")
    assert len(builder.resources_of(AwsServiceQuota)) == 1
    AwsIamServerCertificate.collect_resources(builder)
    expect_quotas(builder, 2)


def test_regional_matcher() -> None:
    builder = build_graph(AwsResource)
    assert len(builder.resources_of(AwsResource)) == 0  # empty graph

    # create 2 regions
    region1 = builder.add_node(AwsRegion(id="eu-central-1", tags={}, name="eu-central-1"))
    region2 = builder.add_node(AwsRegion(id="us-east-1", tags={}, name="us-east-1"))
    # add instance types
    t1 = builder.add_node(AwsEc2InstanceType(id="t1", name="t1"))
    t2 = builder.add_node(AwsEc2InstanceType(id="t2", name="t2"))
    t1._region = region1
    t2._region = region2
    # add service quotas
    sq1 = builder.add_node(AwsServiceQuota(quota=1, id="q1"))
    sq2 = builder.add_node(AwsServiceQuota(quota=2, id="q2"))
    sq1._region = region1
    sq2._region = region2

    # connect both quotas in graph
    sq1.connect_in_graph(builder, {"matcher": evolve(RegionalQuotas["ec2"][0], region=region1)})
    sq2.connect_in_graph(builder, {"matcher": evolve(RegionalQuotas["ec2"][0], region=region2)})

    # sq1 is only connected to t1
    assert list(builder.graph.successors(sq1, EdgeType.default)) == [t1]
    # sq2 is only connected to t2
    assert list(builder.graph.successors(sq2, EdgeType.default)) == [t2]


def expect_quotas(builder: GraphBuilder, quotas: int) -> None:
    for node, data in builder.graph.nodes(data=True):
        if isinstance(node, AwsServiceQuota):
            node.connect_in_graph(builder, data.get("source", {}))
    # make sure edges have been created
    assert builder.graph.number_of_edges() == quotas


def test_tagging() -> None:
    quota, _ = round_trip_for(AwsServiceQuota, "usage", "quota_type")

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-resource"
        assert kwargs["ResourceARN"] == quota.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-resource"
        assert kwargs["ResourceARN"] == quota.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    quota.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    quota.delete_resource_tag(client, "foo")
