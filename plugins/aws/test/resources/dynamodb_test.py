from test.resources import round_trip_for
from types import SimpleNamespace
from typing import cast, Any
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.dynamodb import AwsDynamoDbTable, AwsDynamoDbGlobalTable


def test_tables() -> None:
    first, builder = round_trip_for(AwsDynamoDbTable)
    assert len(builder.resources_of(AwsDynamoDbTable)) == 1
    assert len(first.tags) == 1


def test_tagging_tables() -> None:
    table, _ = round_trip_for(AwsDynamoDbTable)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "list-tags-of-resource":
            assert kwargs["ResourceArn"] == table.arn
            return [{"Key": "foo", "Value": "bar"}]

        if kwargs["action"] == "tag-resource":
            assert kwargs["ResourceArn"] == table.arn
            assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "untag-resource":
            assert kwargs["ResourceArn"] == table.arn
            assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    table.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    table.delete_resource_tag(client, "foo")


def test_delete_tables() -> None:
    table, _ = round_trip_for(AwsDynamoDbTable)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-table"
        assert kwargs["TableName"] == table.name

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    table.delete_resource(client)


def test_global_tables() -> None:
    first, builder = round_trip_for(AwsDynamoDbGlobalTable)
    assert len(builder.resources_of(AwsDynamoDbGlobalTable)) == 1


def test_tagging_global_tables() -> None:
    table, _ = round_trip_for(AwsDynamoDbGlobalTable)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "list-tags-of-resource":
            assert kwargs["ResourceArn"] == table.arn
            return [{"Key": "foo", "Value": "bar"}]

        if kwargs["action"] == "tag-resource":
            assert kwargs["ResourceArn"] == table.arn
            assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "untag-resource":
            assert kwargs["ResourceArn"] == table.arn
            assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    table.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    table.delete_resource_tag(client, "foo")


def test_delete_global_tables() -> None:
    table, _ = round_trip_for(AwsDynamoDbGlobalTable)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-table"
        assert kwargs["TableName"] == table.name

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    table.delete_resource(client)
