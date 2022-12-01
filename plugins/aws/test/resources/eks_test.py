from resoto_plugin_aws.resource.eks import AwsEksCluster, AwsEksNodegroup
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_eks_nodegroup() -> None:
    first, builder = round_trip_for(AwsEksCluster)
    assert len(builder.resources_of(AwsEksCluster)) == 1
    assert len(builder.resources_of(AwsEksNodegroup)) == 1


def test_cluster_deletion() -> None:
    cluster, _ = round_trip_for(AwsEksCluster)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-cluster"
        assert kwargs["name"] == cluster.name

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    cluster.delete_resource(client)


def test_nodegroup_deletion() -> None:
    _, builder = round_trip_for(AwsEksCluster)
    nodegroup = builder.resources_of(AwsEksNodegroup)[0]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-nodegroup"
        assert kwargs["nodegroupName"] == nodegroup.name
        assert kwargs["clusterName"] == nodegroup.cluster_name

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    nodegroup.delete_resource(client)


def test_tagging() -> None:
    cluster, _ = round_trip_for(AwsEksCluster)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-resource"
        assert kwargs["resourceArn"] == cluster.arn
        assert kwargs["tags"] == {"foo": "bar"}

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-resource"
        assert kwargs["resourceArn"] == cluster.arn
        assert kwargs["tagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    cluster.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    cluster.delete_resource_tag(client, "foo")
