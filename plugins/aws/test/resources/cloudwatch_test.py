from datetime import timedelta, datetime, timezone

from test.resources import round_trip_for

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.cloudwatch import AwsCloudwatchAlarm, AwsCloudwatchMetricData, AwsCloudwatchQuery
from test import aws_client  # noqa: F401


def test_alarms() -> None:
    first, builder = round_trip_for(AwsCloudwatchAlarm)
    assert len(builder.resources_of(AwsCloudwatchAlarm)) == 2


def test_metric(aws_client: AwsClient) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    read = AwsCloudwatchQuery.create("VolumeReadOps", "AWS/EBS", timedelta(hours=1), "vol-123", VolumeId="vol-123")
    write = AwsCloudwatchQuery.create("VolumeWriteOps", "AWS/EBS", timedelta(hours=1), "vol-123", VolumeId="vol-123")
    result = AwsCloudwatchMetricData.query_for(aws_client, [read, write], earlier, now)
    assert result[read].first_non_zero() == (datetime(2020, 1, 18, 17, 40, tzinfo=timezone.utc), 15.0)
    assert result[write].first_non_zero() == (datetime(2020, 1, 18, 18, 40, tzinfo=timezone.utc), 12861.0)
