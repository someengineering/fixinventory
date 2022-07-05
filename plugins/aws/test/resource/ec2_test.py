from resoto_plugin_aws.resource.ec2 import AWSEC2Instance, AWSEC2KeyPair, AWSEC2Volume, AWSEC2NetworkAcl
from test.resource import round_trip


def test_volumes() -> None:
    round_trip("ec2/describe-volumes.json", AWSEC2Volume, "Volumes")


def test_keypair() -> None:
    round_trip("ec2/describe-key-pairs.json", AWSEC2KeyPair, "KeyPairs")


def test_instance() -> None:
    round_trip("ec2/describe-instances.json", AWSEC2Instance, "Reservations")


def test_network_acl() -> None:
    round_trip("ec2/describe-network-acls.json", AWSEC2NetworkAcl, "NetworkAcls")
