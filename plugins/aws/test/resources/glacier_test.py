from collections import defaultdict
from resoto_plugin_aws.resource.glacier import AwsGlacierVault
from test.resources import round_trip_for
from typing import Any, Dict, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_vaults_and_jobs() -> None:
    vault, builder = round_trip_for(AwsGlacierVault)
    assert len(builder.resources_of(AwsGlacierVault)) == 1
    assert len(vault.tags) == 1
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_glacier_job"] == 1


def test_tagging_vaults() -> None:
    vault, _ = round_trip_for(AwsGlacierVault)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "add-tags-to-vault":
            assert kwargs["vaultName"] == vault.name
            assert kwargs["Tags"] == {"foo": "bar"}

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "remove-tags-from-vault":
            assert kwargs["vaultName"] == vault.name
            assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    vault.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    vault.delete_resource_tag(client, "foo")


def test_delete_vaults() -> None:
    vault, _ = round_trip_for(AwsGlacierVault)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-vault"
        assert kwargs["vaultName"] == vault.name

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    vault.delete_resource(client)
