from resoto_plugin_aws.resource.ec2 import (
    AwsEc2Instance,
    AwsEc2KeyPair,
    AwsEc2Volume,
    AwsEc2NetworkAcl,
    AwsEc2InstanceType,
    AwsEc2ReservedInstances,
)
from test.resources import round_trip_for


def test_instance_types() -> None:
    round_trip_for(AwsEc2InstanceType, "quota", "quota_type", "reservations", "usage", "ondemand_cost")


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
