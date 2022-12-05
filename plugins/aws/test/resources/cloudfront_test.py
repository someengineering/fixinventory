from datetime import timedelta, datetime, timezone
from typing import cast, Any
from types import SimpleNamespace
from test.resources import round_trip_for

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.cloudfront import AwsCloudFrontDistribution, AwsCloudFrontFunction, AwsCloudFrontInvalidation, AwsCloudFrontPublicKey
from test import aws_client, aws_config  # noqa: F401


def test_distributions() -> None:
    first, builder = round_trip_for(AwsCloudFrontDistribution)
    assert len(builder.resources_of(AwsCloudFrontDistribution)) == 1
    # assert len(first.tags) == 1

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
