from resoto_plugin_aws.resource.cloudformation import AwsCloudFormationStack
from test.resources import round_trip_for


def test_cloud_formation_stacks() -> None:
    round_trip_for(AwsCloudFormationStack)


def test_cloud_formation_stack_sets() -> None:
    round_trip_for(AwsCloudFormationStack)
