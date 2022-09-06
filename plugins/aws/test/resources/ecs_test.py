from types import SimpleNamespace
from typing import Any, cast
from resoto_plugin_aws.resource.ecs import AwsEcsCluster
from test.resources import round_trip_for
from resoto_plugin_aws.aws_client import AwsClient


def test_ecs_cluster() -> None:
    first, builder = round_trip_for(AwsEcsCluster)
    assert len(builder.resources_of(AwsEcsCluster)) == 1


def test_tagging() -> None:
    instance, _ = round_trip_for(AwsEcsCluster)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-resource"
        assert kwargs["resourceArn"] == instance.arn
        assert kwargs["tags"] == [{"key": "foo", "value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-resource"
        assert kwargs["resourceArn"] == instance.arn
        assert kwargs["tagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    instance.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource_tag(client, "foo")


def test_cluster_deletion() -> None:
    cluster, _ = round_trip_for(AwsEcsCluster)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-cluster"
        assert kwargs["cluster"] == cluster.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    cluster.delete_resource(client)
