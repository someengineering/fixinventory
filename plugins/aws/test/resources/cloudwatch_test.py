from datetime import timedelta, datetime, timezone
from typing import cast, Any
from types import SimpleNamespace
from test.resources import round_trip_for

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.cloudwatch import AwsCloudwatchAlarm, AwsCloudwatchMetricData, AwsCloudwatchQuery
from test import aws_client, aws_config  # noqa: F401


def test_alarms() -> None:
    first, builder = round_trip_for(AwsCloudwatchAlarm)
    assert len(builder.resources_of(AwsCloudwatchAlarm)) == 2
    assert len(first.tags) == 1


def test_metric(aws_client: AwsClient) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    read = AwsCloudwatchQuery.create("VolumeReadOps", "AWS/EBS", timedelta(hours=1), "vol-123", VolumeId="vol-123")
    write = AwsCloudwatchQuery.create("VolumeWriteOps", "AWS/EBS", timedelta(hours=1), "vol-123", VolumeId="vol-123")
    result = AwsCloudwatchMetricData.query_for(aws_client, [read, write], earlier, now)
    assert result[read].first_non_zero() == (datetime(2020, 1, 18, 17, 40, tzinfo=timezone.utc), 15.0)
    assert result[write].first_non_zero() == (datetime(2020, 1, 18, 18, 40, tzinfo=timezone.utc), 12861.0)


def test_tagging() -> None:
    alarm, _ = round_trip_for(AwsCloudwatchAlarm)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-resource"
        assert kwargs["ResourceARN"] == alarm.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-resource"
        assert kwargs["ResourceARN"] == alarm.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    alarm.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    alarm.delete_resource_tag(client, "foo")


def test_deletion() -> None:
    alarm, _ = round_trip_for(AwsCloudwatchAlarm)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-alarms"
        assert kwargs["AlarmNames"] == [alarm.name]

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    alarm.delete_resource(client)
