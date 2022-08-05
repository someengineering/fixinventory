from types import SimpleNamespace
from typing import Any, cast
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.sqs import AwsSqsQueue
from test.resources import round_trip_for


def test_queues() -> None:
    first, builder = round_trip_for(AwsSqsQueue)
    assert len(builder.resources_of(AwsSqsQueue)) == 1
    assert len(first.tags) == 2


def test_tagging_queues() -> None:
    queue, _ = round_trip_for(AwsSqsQueue)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "tag-queue":
            assert kwargs["QueueUrl"] == queue.sqs_queue_url
            assert kwargs["Tags"] == {"foo": "bar"}

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "untag-queue":
            assert kwargs["QueueUrl"] == queue.sqs_queue_url
            assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    queue.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    queue.delete_resource_tag(client, "foo")


def test_delete_queues() -> None:
    queue, _ = round_trip_for(AwsSqsQueue)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-queue"
        assert kwargs["QueueUrl"] == queue.sqs_queue_url

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    queue.delete_resource(client)
