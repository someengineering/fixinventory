from resoto_plugin_aws.resource.redshift import AwsRedshiftCluster
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_redshift_cluster() -> None:
    res, builder = round_trip_for(AwsRedshiftCluster)
    assert len(builder.resources_of(AwsRedshiftCluster)) == 1
    assert len(res.tags) == 1
    assert res.arn == "arn:aws:redshift:eu-central-1:test:cluster:resoto-delete-me"


def test_tagging() -> None:
    cluster, _ = round_trip_for(AwsRedshiftCluster)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "create-tags"
        assert kwargs["ResourceName"] == cluster.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-tags"
        assert kwargs["ResourceName"] == cluster.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    cluster.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    cluster.delete_resource_tag(client, "foo")


def test_deletion() -> None:
    cluster, _ = round_trip_for(AwsRedshiftCluster)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-cluster"
        assert kwargs["ClusterIdentifier"] == cluster.id
        assert kwargs["SkipFinalClusterSnapshot"] is True

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    cluster.delete_resource(client)
