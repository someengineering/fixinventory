from resoto_plugin_aws.resource.autoscaling import AwsAutoScalingGroup
from test.resources import round_trip


def test_autoscaling_groups() -> None:
    round_trip("autoscaling/describe-auto-scaling-groups.json", AwsAutoScalingGroup, "AutoScalingGroups")
