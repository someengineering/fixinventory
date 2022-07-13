from resoto_plugin_aws.resource.ec2 import (
    AwsEc2Instance,
    AwsEc2KeyPair,
    AwsEc2Volume,
    AwsEc2NetworkAcl,
    AwsEc2InstanceType,
    AwsEc2ReservedInstances,
    AwsEc2ElasticIp,
    AwsEc2NetworkInterface,
    AwsEc2Vpc,
)
from test.resources import round_trip_for, build_from_file, check_single_node


def test_instance_types() -> None:
    api = AwsEc2InstanceType.api_spec
    builder = build_from_file(f"{api.service}/{api.api_action}.json", AwsEc2InstanceType, api.result_property)
    for it in builder.global_instance_types.values():
        it.connect_in_graph(builder, {})
        check_single_node(it)


def test_reserved_instances() -> None:
    round_trip_for(AwsEc2ReservedInstances)


def test_volumes() -> None:
    round_trip_for(AwsEc2Volume)


def test_keypair() -> None:
    round_trip_for(AwsEc2KeyPair)


def test_instance() -> None:
    round_trip_for(AwsEc2Instance)


def test_network_acl() -> None:
    round_trip_for(AwsEc2NetworkAcl)


def test_elastic_ips() -> None:
    round_trip_for(AwsEc2ElasticIp)


def test_network_interfaces() -> None:
    round_trip_for(AwsEc2NetworkInterface)


def test_vpcs() -> None:
    round_trip_for(AwsEc2Vpc)
