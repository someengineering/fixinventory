from test.resources import round_trip_for
from types import SimpleNamespace
from typing import cast, Any
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.rds import AwsRdsInstance


def test_rds_instances() -> None:
    first, builder = round_trip_for(AwsRdsInstance)
    assert len(builder.resources_of(AwsRdsInstance)) == 2


def test_tagging() -> None:
    instance, _ = round_trip_for(AwsRdsInstance)

    def validate_update_args(**kwargs: Any):
        assert kwargs["action"] == "add_tags_to_resource"
        assert kwargs["ResourceName"] == instance.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any):
        assert kwargs["action"] == "remove_tags_from_resource"
        assert kwargs["ResourceName"] == instance.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    instance.update_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_tag(client, "foo")
