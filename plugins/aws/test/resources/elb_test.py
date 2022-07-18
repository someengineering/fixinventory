from resoto_plugin_aws.resource.elb import AwsElb
from test.resources import round_trip_for


def test_elbs() -> None:
    first, graph = round_trip_for(AwsElb, "public_ip_address")
    assert len(first.tags) == 2
