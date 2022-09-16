from types import SimpleNamespace
from typing import Any, cast
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.sns import AwsSnsTopic
from test.resources import round_trip_for


def test_topics() -> None:
    first, builder = round_trip_for(AwsSnsTopic)
    assert len(builder.resources_of(AwsSnsTopic)) == 1
    assert len(first.tags) == 1


def test_tagging_topics() -> None:
    topic, _ = round_trip_for(AwsSnsTopic)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "tag-resource":
            assert kwargs["ResourceArn"] == topic.arn
            assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "untag-resource":
            assert kwargs["ResourceArn"] == topic.arn
            assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    topic.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    topic.delete_resource_tag(client, "foo")


def test_delete_topics() -> None:
    topic, _ = round_trip_for(AwsSnsTopic)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-topic"
        assert kwargs["TopicArn"] == topic.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    topic.delete_resource(client)
