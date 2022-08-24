from typing import cast, Any
from types import SimpleNamespace
from test.resources import round_trip_for

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.kms import AwsKmsKey


def test_keys() -> None:
    first, builder = round_trip_for(AwsKmsKey)
    assert len(builder.resources_of(AwsKmsKey)) == 2
    assert len(first.tags) == 1


def test_tagging_keys() -> None:
    key, _ = round_trip_for(AwsKmsKey)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "tag-resource":
            assert kwargs["KeyId"] == key.id
            assert kwargs["Tags"] == [{"TagKey": "foo", "TagValue": "bar"}]

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "untag-resource":
            assert kwargs["KeyId"] == key.id
            assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    key.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    key.delete_resource_tag(client, "foo")


def test_disable_keys() -> None:
    key, _ = round_trip_for(AwsKmsKey)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "disable-key"
        assert kwargs["KeyId"] == key.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    key.delete_resource(client)


def test_delete_keys() -> None:
    key, _ = round_trip_for(AwsKmsKey)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "disable-key"
        assert kwargs["KeyId"] == key.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    key.delete_resource(client)


def test_normalise_keys() -> None:
    assert AwsKmsKey.normalise_id("arn:aws:kms:us-west-2:test:key/kms-1") == "kms-1"
    assert AwsKmsKey.normalise_id("kms-1") == "kms-1"
