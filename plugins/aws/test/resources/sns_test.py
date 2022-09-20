from collections import defaultdict
from types import SimpleNamespace
from typing import Any, Dict, cast
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.sns import AwsSnsTopic, AwsSnsSubscription, AwsSnsPlatformApplication
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


def test_subs() -> None:
    first, builder = round_trip_for(AwsSnsSubscription)
    assert len(builder.resources_of(AwsSnsSubscription)) == 1
    assert first.subscription_confirmation_was_authenticated is False
    assert first.subscription_raw_message_delivery is True


def test_delete_subs() -> None:
    sub, _ = round_trip_for(AwsSnsSubscription)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "unsubscribe"
        assert kwargs["SubscriptionArn"] == sub.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    sub.delete_resource(client)


def test_apps() -> None:
    first, builder = round_trip_for(AwsSnsPlatformApplication)
    assert len(builder.resources_of(AwsSnsPlatformApplication)) == 1
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_sns_endpoint"] == 1


def test_delete_apps() -> None:
    app, _ = round_trip_for(AwsSnsPlatformApplication)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-platform-application"
        assert kwargs["PlatformApplicationArn"] == app.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    app.delete_resource(client)
