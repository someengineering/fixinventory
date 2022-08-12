from datetime import timedelta, datetime, timezone
from typing import cast, Any
from types import SimpleNamespace
from test.resources import round_trip_for

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.kms import AwsKmsKey



def test_keys() -> None:
    first, builder = round_trip_for(AwsKmsKey)
    assert len(builder.resources_of(AwsKmsKey)) == 2
    assert len(first.tags) == 1