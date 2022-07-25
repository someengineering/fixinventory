from resoto_plugin_aws.resource.eks import AwsEksCluster, AwsEksNodegroup
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_eks_nodegroup() -> None:
    first, builder = round_trip_for(AwsEksCluster)
    assert len(builder.resources_of(AwsEksCluster)) == 1
    assert len(builder.resources_of(AwsEksNodegroup)) == 1


def test_tagging() -> None:
    cluster, _ = round_trip_for(AwsEksCluster)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag_resource"
        assert kwargs["resourceArn"] == cluster.arn
        assert kwargs["tags"] == [{"foo": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag_resource"
        assert kwargs["resourceArn"] == cluster.arn
        assert kwargs["tagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    cluster.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    cluster.delete_resource_tag(client, "foo")
