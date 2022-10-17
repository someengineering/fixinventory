from collections import defaultdict
from types import SimpleNamespace
from typing import Any, Dict, cast
from resoto_plugin_aws.resource.ecs import AwsEcsCluster, AwsEcsTaskDefinition
from test.resources import round_trip_for
from resoto_plugin_aws.aws_client import AwsClient


def test_ecs_cluster() -> None:
    first, builder = round_trip_for(AwsEcsCluster)
    assert len(builder.resources_of(AwsEcsCluster)) == 1
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_ecs_container_instance"] == 2
    assert type_count["aws_ecs_service"] == 1
    assert type_count["aws_ecs_task"] == 1
    assert type_count["aws_ecs_capacity_provider"] == 1


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


def test_ecs_task_definition() -> None:
    first, builder = round_trip_for(AwsEcsTaskDefinition)
    assert len(builder.resources_of(AwsEcsTaskDefinition)) == 1
    assert first.family == "nginx-sample-stack"
    assert first.revision == 1
    assert first.id == "nginx-sample-stack:1"
