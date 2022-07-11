from resoto_plugin_aws.resource.autoscaling import AwsAutoScalingGroup
from test.resources import round_trip_for


def test_autoscaling_groups() -> None:
    round_trip_for(AwsAutoScalingGroup)
