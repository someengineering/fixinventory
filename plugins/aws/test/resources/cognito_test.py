from collections import defaultdict
from types import SimpleNamespace
from typing import Any, Dict, cast
from resoto_plugin_aws.aws_client import AwsClient
from test.resources import round_trip_for
from resoto_plugin_aws.resource.cognito import AwsCognitoUserPool


def test_user_pools() -> None:
    first, builder = round_trip_for(AwsCognitoUserPool)
    assert len(builder.resources_of(AwsCognitoUserPool)) == 1
    assert first.arn == "arn:aws:cognito-idp:eu-central-1:test:userpool/123"
    assert first.tags["model"] == "santorini pro"
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_cognito_user"] == 1
    assert type_count["aws_cognito_group"] == 1


def test_tagging_pools() -> None:
    pool, _ = round_trip_for(AwsCognitoUserPool)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "tag-resource":
            assert kwargs["ResourceArn"] == pool.arn
            assert kwargs["Tags"] == {"foo": "bar"}

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "untag-resource":
            assert kwargs["ResourceArn"] == pool.arn
            assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    pool.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    pool.delete_resource_tag(client, "foo")


def test_delete_pools() -> None:
    pool, _ = round_trip_for(AwsCognitoUserPool)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-user-pool"
        assert kwargs["UserPoolId"] == pool.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    pool.delete_resource(client)
