from datetime import timedelta, datetime, timezone
from typing import cast, Any
from types import SimpleNamespace

from fixlib.graph import Graph

from test.resources import round_trip_for
from test import aws_config, builder, no_feedback, aws_client  # noqa: F401

from fix_plugin_aws.resource.cloudwatch import (
    AwsCloudwatchAlarm,
    AwsCloudwatchMetricData,
    AwsCloudwatchQuery,
    AwsCloudwatchLogGroup,
    AwsCloudwatchMetricFilter,
)
from fix_plugin_aws.resource.base import GraphBuilder
from fix_plugin_aws.aws_client import AwsClient


def test_alarms() -> None:
    first, aws_builder = round_trip_for(AwsCloudwatchAlarm)
    assert len(aws_builder.resources_of(AwsCloudwatchAlarm)) == 2
    assert len(first.tags) == 1


def test_log_groups() -> None:
    round_trip_for(AwsCloudwatchLogGroup)


def test_metrics_filter() -> None:
    first, aws_builder = round_trip_for(AwsCloudwatchMetricFilter)
    # test connection to log group
    AwsCloudwatchLogGroup.collect_resources(aws_builder)
    first.connect_in_graph(aws_builder, aws_builder.graph.nodes(data=True)[first]["source"])
    assert len(aws_builder.edges_of(AwsCloudwatchLogGroup, AwsCloudwatchMetricFilter)) == 1


def test_metric(builder: GraphBuilder) -> None:
    now = datetime(2020, 3, 1, tzinfo=timezone.utc)
    earlier = now - timedelta(days=60)
    read = AwsCloudwatchQuery.create("VolumeReadOps", "AWS/EBS", timedelta(hours=1), "vol-123", VolumeId="vol-123")
    write = AwsCloudwatchQuery.create("VolumeWriteOps", "AWS/EBS", timedelta(hours=1), "vol-123", VolumeId="vol-123")
    result = AwsCloudwatchMetricData.query_for(builder, [read, write], earlier, now)
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
    alarm.delete_resource(client, Graph())
