from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction, AwsLambdaPolicy
from fixlib.graph import Graph
from fixlib.json import from_json
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from fix_plugin_aws.aws_client import AwsClient


def test_regression_lamda_get_policy() -> None:
    value_to_read = {
        "policy": {
            "id": "default",
            "version": "2012-10-17",
            "statement": [
                {
                    "sid": "StackSet-AWSControlTower-ALCD-LZ-resource-owner-tag",
                    "effect": "Allow",
                    "principal": {"Service": "events.amazonaws.com"},
                    "action": "lambda:InvokeFunction",
                    "resource": "arn:aws:lambda:eu-central-1:test:function:aws-controltower-owner-tagging-func",
                    "condition": None,
                }
            ],
        },
        "policy_revision_id": "b3f179eb-569b-4ea2-8ec4-4324609b0694",
    }
    from_json(value_to_read, AwsLambdaPolicy)


def test_lambda() -> None:
    first, graph = round_trip_for(AwsLambdaFunction)
    assert len(graph.resources_of(AwsLambdaFunction)) == 2
    assert len(first.tags) == 1


def test_tagging() -> None:
    res, _ = round_trip_for(AwsLambdaFunction)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-resource"
        assert kwargs["Tags"] == {"foo": "bar"}
        assert kwargs["Resource"] == res.arn

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-resource"
        assert kwargs["TagKeys"] == ["foo"]
        assert kwargs["Resource"] == res.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    res.delete_resource_tag(client, "foo")


def test_deletion() -> None:
    res, _ = round_trip_for(AwsLambdaFunction)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-function"
        assert kwargs["FunctionName"] == res.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    res.delete_resource(client, Graph())
