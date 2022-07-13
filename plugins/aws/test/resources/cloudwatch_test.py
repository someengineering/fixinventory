from test.resources import round_trip_for

from resoto_plugin_aws.resource.cloudwatch import AwsCloudwatchAlarm


def test_alarms() -> None:
    first, builder = round_trip_for(AwsCloudwatchAlarm)
    assert len(builder.resources_of(AwsCloudwatchAlarm)) == 2
