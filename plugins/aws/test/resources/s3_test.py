from test.resources import round_trip_for
from types import SimpleNamespace
from typing import cast, Any, Callable
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.s3 import AwsS3Bucket


def test_buckets() -> None:
    first, builder = round_trip_for(AwsS3Bucket)
    assert len(builder.resources_of(AwsS3Bucket)) == 3
    assert first.arn == "arn:aws:s3:::bucket-1"
    assert len(first.tags) == 1


def test_tagging() -> None:
    bucket, _ = round_trip_for(AwsS3Bucket)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "get-bucket-tagging":
            assert kwargs["Bucket"] == bucket.name
            return [{"Key": "foo", "Value": "bar"}]

        if kwargs["action"] == "put-bucket-tagging":
            assert kwargs["Bucket"] == bucket.name
            assert kwargs["Tagging"] == {"TagSet": [{"Key": "foo", "Value": "bar"}]}

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "get-bucket-tagging":
            assert kwargs["Bucket"] == bucket.name
            return [{"Key": "foo", "Value": "bar"}]

        if kwargs["action"] == "put-bucket-tagging":
            assert kwargs["Bucket"] == bucket.name
            assert kwargs["Tagging"] == {"TagSet": []}

    client = cast(AwsClient, SimpleNamespace(list=validate_update_args, call=validate_update_args))
    bucket.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(list=validate_delete_args, call=validate_delete_args))
    bucket.delete_resource_tag(client, "foo")


def test_deletion() -> None:
    bucket, _ = round_trip_for(AwsS3Bucket)

    def validate_delete_args(aws_service: str, fn: Callable[[Any], None]) -> Any:
        assert aws_service == "s3"

    client = cast(AwsClient, SimpleNamespace(with_resource=validate_delete_args))
    bucket.delete_resource(client)
