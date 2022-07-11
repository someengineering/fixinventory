from resoto_plugin_aws.resource.cloudformation import AwsCloudFormationStack
from test.resources import round_trip


def test_cloud_formation_stacks() -> None:
    round_trip("cloudformation/describe-stacks.json", AwsCloudFormationStack, "Stacks")
