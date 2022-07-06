from resoto_plugin_aws.resource.ec2 import AwsEc2Instance, AwsEc2KeyPair, AwsEc2Volume, AwsEc2NetworkAcl
from test.resource import round_trip


def test_volumes() -> None:
    round_trip("ec2/describe-volumes.json", AwsEc2Volume, "Volumes")


def test_keypair() -> None:
    round_trip("ec2/describe-key-pairs.json", AwsEc2KeyPair, "KeyPairs")


def test_instance() -> None:
    round_trip("ec2/describe-instances.json", AwsEc2Instance, "Reservations")


def test_network_acl() -> None:
    round_trip("ec2/describe-network-acls.json", AwsEc2NetworkAcl, "NetworkAcls")
