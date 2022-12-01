from resoto_plugin_aws.resource.elasticache import (
    AwsElastiCacheReplicationGroup,
    AwsElastiCacheCacheCluster,
)
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_elasticache_replication_group() -> None:
    res, builder = round_trip_for(AwsElastiCacheReplicationGroup)
    assert len(builder.resources_of(AwsElastiCacheReplicationGroup)) == 1
    assert len(res.tags) == 2


def test_elasticache_cache_cluster() -> None:
    res, builder = round_trip_for(AwsElastiCacheCacheCluster)
    assert len(builder.resources_of(AwsElastiCacheCacheCluster)) == 1
    assert len(res.tags) == 2


def test_tagging() -> None:
    resource, _ = round_trip_for(AwsElastiCacheReplicationGroup)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "add-tags-to-resource"
        assert kwargs["ResourceName"] == resource.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "remove-tags-from-resource"
        assert kwargs["ResourceName"] == resource.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    resource.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    resource.delete_resource_tag(client, "foo")


def test_replication_group_deletion() -> None:
    group, _ = round_trip_for(AwsElastiCacheReplicationGroup)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-replication-group"
        assert kwargs["ReplicationGroupId"] == group.id
        assert kwargs["RetainPrimaryCluster"] is False

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    group.delete_resource(client)


def test_cluster_deletion() -> None:
    cluster, _ = round_trip_for(AwsElastiCacheCacheCluster)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-cache-cluster"
        assert kwargs["CacheClusterId"] == cluster.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    cluster.delete_resource(client)
