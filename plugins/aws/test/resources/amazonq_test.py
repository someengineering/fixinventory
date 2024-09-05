from fix_plugin_aws.resource.amazonq import AwsQBusinessApplication
from test.resources import round_trip_for


def test_applications() -> None:
    round_trip_for(AwsQBusinessApplication)
