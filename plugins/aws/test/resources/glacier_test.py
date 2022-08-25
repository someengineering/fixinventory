from collections import defaultdict
from resoto_plugin_aws.resource.glacier import AwsGlacierVault, AwsGlacierJob
from test.resources import round_trip_for
from typing import Any, Dict, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_vaults() -> None:
    vault, builder = round_trip_for(AwsGlacierVault)
    assert len(builder.resources_of(AwsGlacierVault)) == 1
    assert len(vault.tags) == 1
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_glacier_job"] == 1
