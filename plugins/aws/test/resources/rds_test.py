from test.resources import round_trip_for
from types import SimpleNamespace
from typing import cast, Any
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.rds import AwsRdsInstance


def test_rds_instances() -> None:
    first, builder = round_trip_for(AwsRdsInstance)
    assert len(builder.resources_of(AwsRdsInstance)) == 2
    assert len(first.tags) == 1


def test_tagging() -> None:
    instance, _ = round_trip_for(AwsRdsInstance)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "add-tags-to-resource"
        assert kwargs["ResourceName"] == instance.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "remove-tags-from-resource"
        assert kwargs["ResourceName"] == instance.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    instance.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource_tag(client, "foo")


def test_deletion() -> None:
    instance, _ = round_trip_for(AwsRdsInstance)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-db-instance"
        assert kwargs["DBInstanceIdentifier"] == instance.name
        assert kwargs["SkipFinalSnapshot"] is True

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource(client)
