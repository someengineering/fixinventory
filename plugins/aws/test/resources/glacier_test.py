from resoto_plugin_aws.resource.glacier import AwsGlacierVault
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_vaults() -> None:
    vault, builder = round_trip_for(AwsGlacierVault)
    assert len(builder.resources_of(AwsGlacierVault)) == 1
    assert len(vault.tags) == 1