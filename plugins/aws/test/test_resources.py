import json
from typing import Type

from resoto_plugin_aws.base import GraphBuilder, AWSResource
from resoto_plugin_aws.resources2 import AWSEC2Instance, AWSEC2KeyPair, AWSEC2Volume
from resotolib.graph import Graph


def test_volumes() -> None:
    round_trip("/Users/matthias/d2iq/volumes.json", AWSEC2Volume, "Volumes")


def test_ec2_keypair() -> None:
    round_trip("/Users/matthias/d2iq/keypairs.json", AWSEC2KeyPair, "KeyPairs")


def test_ec2_instance() -> None:
    round_trip("/Users/matthias/d2iq/ec2.json", AWSEC2Instance, "Reservations")


def round_trip(file: str, cls: Type[AWSResource], root: str) -> None:
    builder = GraphBuilder(Graph(), None, None, None)  # type: ignore
    with open(file) as f:
        js = json.load(f)
        cls.collect(js[root], builder)
    assert len(builder.graph.nodes) > 0
    for node in builder.graph.nodes:
        assert isinstance(node, cls)
        as_js = node.to_json()
        again = cls.from_json(as_js)
        assert again.to_json() == as_js
