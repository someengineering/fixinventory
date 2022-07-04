from resoto_plugin_aws.resource.ec2 import AwsEC2Instance, AwsEC2KeyPair, AwsEC2Volume, AwsEC2NetworkAcl
from test.resource import round_trip


def test_volumes() -> None:
    round_trip("ec2/describe-volumes.json", AwsEC2Volume, "Volumes")


def test_keypair() -> None:
    round_trip("ec2/describe-key-pairs.json", AwsEC2KeyPair, "KeyPairs")


def test_instance() -> None:
    round_trip("ec2/describe-instances.json", AwsEC2Instance, "Reservations")


def test_network_acl() -> None:
    round_trip("ec2/describe-network-acls.json", AwsEC2NetworkAcl, "NetworkAcls")
