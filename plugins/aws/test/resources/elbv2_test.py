from resoto_plugin_aws.resource.elbv2 import AwsAlb, AwsAlbTargetGroup
from test.resources import round_trip_for


def test_albs() -> None:
    first, graph = round_trip_for(AwsAlb)
    assert len(first.alb_listener) == 2
    assert len(first.tags) == 4


def test_alb_target_groups() -> None:
    first, graph = round_trip_for(AwsAlbTargetGroup)
    assert len(first.tags) == 4
