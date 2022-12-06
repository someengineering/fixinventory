from datetime import timedelta, datetime, timezone
from typing import cast, Any
from types import SimpleNamespace
from test.resources import round_trip_for

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.cloudfront import (
    AwsCloudFrontDistribution,
    AwsCloudFrontFunction,
    AwsCloudFrontInvalidation,
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
    # assert len(first.tags) == 1


def test_distribution_deletion() -> None:
    dist, _ = round_trip_for(AwsCloudFrontDistribution)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-distribution"
        assert kwargs["Id"] == dist.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    dist.delete_resource(client)


def test_functions() -> None:
    first, builder = round_trip_for(AwsCloudFrontFunction)
    assert len(builder.resources_of(AwsCloudFrontFunction)) == 1
    # assert len(first.tags) == 1


def test_invalidations() -> None:
    first, builder = round_trip_for(AwsCloudFrontInvalidation)
    assert len(builder.resources_of(AwsCloudFrontInvalidation)) == 1


def test_public_keys() -> None:
    first, builder = round_trip_for(AwsCloudFrontPublicKey)
    assert len(builder.resources_of(AwsCloudFrontPublicKey)) == 1


def test_public_key_deletion() -> None:
    key, _ = round_trip_for(AwsCloudFrontPublicKey)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-public-key"
        assert kwargs["Id"] == key.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
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


def test_response_headers_policy_deletion() -> None:
    policy, _ = round_trip_for(AwsCloudFrontResponseHeadersPolicy)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-response-headers-policy"
        assert kwargs["Id"] == policy.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    policy.delete_resource(client)


def test_streaming_distributions() -> None:
    first, builder = round_trip_for(AwsCloudFrontStreamingDistribution)
    assert len(builder.resources_of(AwsCloudFrontStreamingDistribution)) == 1


def test_origin_access_controls() -> None:
    first, builder = round_trip_for(AwsCloudFrontOriginAccessControl)
    assert len(builder.resources_of(AwsCloudFrontOriginAccessControl)) == 1


def test_oac_deletion() -> None:
    oac, _ = round_trip_for(AwsCloudFrontOriginAccessControl)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-origin-access-control"
        assert kwargs["Id"] == oac.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    oac.delete_resource(client)


def test_cache_policies() -> None:
    first, builder = round_trip_for(AwsCloudFrontCachePolicy)
    assert len(builder.resources_of(AwsCloudFrontCachePolicy)) == 1


def test_cache_policy_deletion() -> None:
    policy, _ = round_trip_for(AwsCloudFrontCachePolicy)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-cache-policy"
        assert kwargs["Id"] == policy.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    policy.delete_resource(client)


def test_field_level_encryption_configs() -> None:
    first, builder = round_trip_for(AwsCloudFrontFieldLevelEncryptionConfig)
    assert len(builder.resources_of(AwsCloudFrontFieldLevelEncryptionConfig)) == 1


def test_fl_config_deletion() -> None:
    conf, _ = round_trip_for(AwsCloudFrontFieldLevelEncryptionConfig)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-field-level-encryption-config"
        assert kwargs["Id"] == conf.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    conf.delete_resource(client)


def test_field_level_encryption_profiles() -> None:
    first, builder = round_trip_for(AwsCloudFrontFieldLevelEncryptionProfile)
    assert len(builder.resources_of(AwsCloudFrontFieldLevelEncryptionProfile)) == 1


def test_fl_profile_deletion() -> None:
    profile, _ = round_trip_for(AwsCloudFrontFieldLevelEncryptionProfile)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-field-level-encryption-profile"
        assert kwargs["Id"] == profile.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    profile.delete_resource(client)
