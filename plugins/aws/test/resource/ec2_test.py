from resoto_plugin_aws.resource.ec2 import AWSEC2Instance, AWSEC2KeyPair, AWSEC2Volume, AWSEC2NetworkAcl
from test.resource import round_trip


def test_volumes() -> None:
    round_trip("ec2/volumes.json", AWSEC2Volume, "Volumes")


def test_keypair() -> None:
    round_trip("ec2/keypairs.json", AWSEC2KeyPair, "KeyPairs")


def test_instance() -> None:
    round_trip("ec2/instances.json", AWSEC2Instance, "Reservations")


def test_network_acl() -> None:
    round_trip("ec2/network_acls.json", AWSEC2NetworkAcl, "NetworkAcls")
