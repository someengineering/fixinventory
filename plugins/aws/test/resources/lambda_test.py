from resoto_plugin_aws.resource.lambda_ import AwsLambdaFunction
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_lambda() -> None:
    first, graph = round_trip_for(AwsLambdaFunction)
    assert len(graph.resources_of(AwsLambdaFunction)) == 2


def test_tagging() -> None:
    res, _ = round_trip_for(AwsLambdaFunction)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag_resource"
        assert kwargs["Tags"] == {"foo": "bar"}
        assert kwargs["Resource"] == res.arn

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag_resource"
        assert kwargs["TagKeys"] == ["foo"]
        assert kwargs["Resource"] == res.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    res.delete_resource_tag(client, "foo")
