from resoto_plugin_aws.resource.ssm import AwsSSMInstanceInformation
from test.resources import round_trip_for


def test_queues() -> None:
    first, builder = round_trip_for(AwsSSMInstanceInformation)
    assert len(builder.resources_of(AwsSSMInstanceInformation)) == 2
