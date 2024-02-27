from types import SimpleNamespace
from typing import cast, Any

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.rds import AwsRdsInstance, AwsRdsCluster, AwsRdsSnapshot, AwsRdsClusterSnapshot
from fixlib.graph import Graph
from test.resources import round_trip_for


def test_rds_instances() -> None:
    first, builder = round_trip_for(AwsRdsInstance)
    assert len(builder.resources_of(AwsRdsInstance)) == 2
    assert len(first.tags) == 1


def test_rds_cluster() -> None:
    round_trip_for(AwsRdsCluster)


def test_rds_snapshots() -> None:
    first, _ = round_trip_for(AwsRdsSnapshot, "description", "volume_id", "owner_id", "owner_alias")
    first.rds_attributes = {"foo": ["foo", "foo", "foo"]}


def test_rds_cluster_snapshots() -> None:
    first, _ = round_trip_for(AwsRdsClusterSnapshot, "description", "volume_id", "owner_id", "owner_alias")
    first.rds_attributes = {"foo": ["foo", "foo", "foo"]}


def test_tagging() -> None:
    instance, _ = round_trip_for(AwsRdsInstance)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "add-tags-to-resource"
        assert kwargs["ResourceName"] == instance.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "remove-tags-from-resource"
        assert kwargs["ResourceName"] == instance.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    instance.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource_tag(client, "foo")


def test_deletion() -> None:
    instance, _ = round_trip_for(AwsRdsInstance)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-db-instance"
        assert kwargs["DBInstanceIdentifier"] == instance.name
        assert kwargs["SkipFinalSnapshot"] is True

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource(client, Graph())
