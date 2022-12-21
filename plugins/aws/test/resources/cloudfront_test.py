from typing import cast, Any
from types import SimpleNamespace
from test.resources import round_trip_for

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.cloudfront import (
    AwsCloudFrontDistribution,
    AwsCloudFrontFunction,
    AwsCloudFrontPublicKey,
    AwsCloudFrontRealtimeLogConfig,
    AwsCloudFrontResponseHeadersPolicy,
    AwsCloudFrontStreamingDistribution,
    AwsCloudFrontOriginAccessControl,
    AwsCloudFrontCachePolicy,
    AwsCloudFrontFieldLevelEncryptionConfig,
    AwsCloudFrontFieldLevelEncryptionProfile,
)
from test import aws_client, aws_config  # noqa: F401


def test_distributions() -> None:
    first, builder = round_trip_for(AwsCloudFrontDistribution)
    assert len(builder.resources_of(AwsCloudFrontDistribution)) == 1


def test_tagging() -> None:
    dist, _ = round_trip_for(AwsCloudFrontDistribution)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "tag-resource":
            assert kwargs["Resource"] == dist.arn
            assert kwargs["Tags"] == {"Items": [{"Key": "foo", "Value": "bar"}]}

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "untag-resource":
            assert kwargs["Resource"] == dist.arn
            assert kwargs["TagKeys"] == {"Items": ["foo"]}

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    dist.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    dist.delete_resource_tag(client, "foo")


def test_functions() -> None:
    first, builder = round_trip_for(AwsCloudFrontFunction)
    assert len(builder.resources_of(AwsCloudFrontFunction)) == 1
    assert len(first.tags) == 1
    assert first.arn == "arn"


def test_function_deletion() -> None:
    func, _ = round_trip_for(AwsCloudFrontFunction)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-function"
        assert kwargs["Name"] == func.name
        assert kwargs["IfMatch"] == "123"

    def mock_get(a: Any, b: Any, c: Any, d: Any, **kwargs: Any) -> Any:
        return {"ETag": "123"}

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args, get=mock_get))
    func.delete_resource(client)


def test_public_keys() -> None:
    first, builder = round_trip_for(AwsCloudFrontPublicKey)
    assert len(builder.resources_of(AwsCloudFrontPublicKey)) == 1


def test_public_key_deletion() -> None:
    key, _ = round_trip_for(AwsCloudFrontPublicKey)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-public-key"
        assert kwargs["Id"] == key.id
        assert kwargs["IfMatch"] == "123"

    def mock_get(a: Any, b: Any, c: Any, d: Any, **kwargs: Any) -> Any:
        return {"ETag": "123"}

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args, get=mock_get))
    key.delete_resource(client)


def test_realtime_log_configs() -> None:
    first, builder = round_trip_for(AwsCloudFrontRealtimeLogConfig)
    assert len(builder.resources_of(AwsCloudFrontRealtimeLogConfig)) == 2


def test_realtime_log_config_deletion() -> None:
    conf, _ = round_trip_for(AwsCloudFrontRealtimeLogConfig)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-realtime-log-config"
        assert kwargs["Name"] == conf.name

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    conf.delete_resource(client)


def test_response_headers_policies() -> None:
    first, builder = round_trip_for(AwsCloudFrontResponseHeadersPolicy)
    assert len(builder.resources_of(AwsCloudFrontResponseHeadersPolicy)) == 1


def test_streaming_distributions() -> None:
    first, builder = round_trip_for(AwsCloudFrontStreamingDistribution)
    assert len(builder.resources_of(AwsCloudFrontStreamingDistribution)) == 1


def test_origin_access_controls() -> None:
    first, builder = round_trip_for(AwsCloudFrontOriginAccessControl)
    assert len(builder.resources_of(AwsCloudFrontOriginAccessControl)) == 1


def test_cache_policies() -> None:
    first, builder = round_trip_for(AwsCloudFrontCachePolicy)
    assert len(builder.resources_of(AwsCloudFrontCachePolicy)) == 1


def test_field_level_encryption_configs() -> None:
    first, builder = round_trip_for(AwsCloudFrontFieldLevelEncryptionConfig)
    assert len(builder.resources_of(AwsCloudFrontFieldLevelEncryptionConfig)) == 1


def test_field_level_encryption_profiles() -> None:
    first, builder = round_trip_for(AwsCloudFrontFieldLevelEncryptionProfile)
    assert len(builder.resources_of(AwsCloudFrontFieldLevelEncryptionProfile)) == 1
