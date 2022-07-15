from resoto_plugin_aws.resource.ec2 import AwsEc2InstanceType, AwsEc2Vpc
from test.resources import round_trip_for

from resoto_plugin_aws.resource.service_quotas import AwsServiceQuota

NrOfQuotas = 11


def test_instance_type_quotas() -> None:
    first, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type")
    assert len(builder.resources_of(AwsServiceQuota)) == NrOfQuotas

    # load instance types (they are normally only added for instances of this type)
    AwsEc2InstanceType.collect_resources(builder)
    for _, it in builder.global_instance_types.items():
        builder.add_node(it, {})

    # no edge has been created
    assert builder.graph.number_of_edges() == 0

    # connect all service quotas
    for node, data in builder.graph.nodes(data=True):
        if isinstance(node, AwsServiceQuota):
            node.connect_in_graph(builder, data.get("source", {}))

    # make sure edges have been created
    assert builder.graph.number_of_edges() == 3


def test_volume_type_quotas() -> None:
    first, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type")
    assert len(builder.resources_of(AwsServiceQuota)) == NrOfQuotas

    # define volume type
    AwsEc2InstanceType.collect_resources(builder)
    for vt in ["gp2", "gp3", "standard", "io1", "io2", "sc1", "st1"]:
        builder.add_node(builder.volume_type(vt), {})  # type: ignore

    # no edge has been created
    assert builder.graph.number_of_edges() == 0

    # connect all service quotas
    for node, data in builder.graph.nodes(data=True):
        if isinstance(node, AwsServiceQuota):
            node.connect_in_graph(builder, data.get("source", {}))

    # make sure edges have been created
    assert builder.graph.number_of_edges() == 7


def test_vpc_quotas() -> None:
    first, builder = round_trip_for(AwsServiceQuota, "usage", "quota_type")
    assert len(builder.resources_of(AwsServiceQuota)) == NrOfQuotas

    # collect vpc's
    AwsEc2Vpc.collect_resources(builder)

    # no edge has been created
    assert builder.graph.number_of_edges() == 0

    # connect all service quotas
    for node, data in builder.graph.nodes(data=True):
        if isinstance(node, AwsServiceQuota):
            node.connect_in_graph(builder, data.get("source", {}))

    # make sure edges have been created
    assert builder.graph.number_of_edges() == 3
