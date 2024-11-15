from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import cast, Any, Callable, List
from fix_plugin_aws.resource.base import AwsRegion, GraphBuilder
from fix_plugin_aws.resource.cloudwatch import update_resource_metrics, AwsCloudwatchMetricData, AwsCloudwatchQuery
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.s3 import AwsS3Bucket, AwsS3AccountSettings
from fixlib.threading import ExecutorQueue
from fixlib.graph import Graph
from test.resources import round_trip_for


def test_buckets() -> None:
    first, builder = round_trip_for(AwsS3Bucket, "bucket_lifecycle_policy")
    assert len(builder.resources_of(AwsS3Bucket)) == 4
    assert len(first.bucket_encryption_rules or []) == 1
    assert first.arn == "arn:aws:s3:::bucket-1"
    assert len(first.tags) == 1


def test_name_from_path() -> None:
    assert AwsS3Bucket.name_from_path("S3://mybucket/puppy.jpg") == "mybucket"
    assert AwsS3Bucket.name_from_path("https://s3.region-code.amazonaws.com/bucket-name/key-name") == "bucket-name"
    assert AwsS3Bucket.name_from_path("https://some-bucket.s3.region-code.amazonaws.com/key-name") == "some-bucket"


def test_s3_account_settings() -> None:
    round_trip_for(AwsS3AccountSettings)


def test_tagging() -> None:
    bucket, _ = round_trip_for(AwsS3Bucket, "bucket_lifecycle_policy")

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "get-bucket-tagging":
            assert kwargs["Bucket"] == bucket.name
            return [{"Key": "foo", "Value": "bar"}]

        if kwargs["action"] == "put-bucket-tagging":
            assert kwargs["Bucket"] == bucket.name
            assert kwargs["Tagging"] == {"TagSet": [{"Key": "foo", "Value": "bar"}]}

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "get-bucket-tagging":
            assert kwargs["Bucket"] == bucket.name
            return [{"Key": "foo", "Value": "bar"}]

        if kwargs["action"] == "put-bucket-tagging":
            assert kwargs["Bucket"] == bucket.name
            assert kwargs["Tagging"] == {"TagSet": []}

    client = cast(AwsClient, SimpleNamespace(list=validate_update_args, call=validate_update_args))
    bucket.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(list=validate_delete_args, call=validate_delete_args))
    bucket.delete_resource_tag(client, "foo")


def test_deletion() -> None:
    bucket, _ = round_trip_for(AwsS3Bucket, "bucket_lifecycle_policy")

    def validate_delete_args(aws_service: str, fn: Callable[[Any], None]) -> Any:
        assert aws_service == "s3"

    client = cast(AwsClient, SimpleNamespace(with_resource=validate_delete_args))
    bucket.delete_resource(client, Graph())


def test_s3_usage_metrics() -> None:
    bucket, builder = round_trip_for(AwsS3Bucket, "bucket_lifecycle_policy")
    builder.all_regions.update({"us-east-1": AwsRegion(id="us-east-1", name="us-east-1")})
    queries = bucket.collect_usage_metrics(builder)
    lookup_map = {}
    lookup_map[bucket.id] = bucket

    # simulates the `collect_usage_metrics` method found in `AwsAccountCollector`.
    def collect_and_set_metrics(start_at: datetime, region: AwsRegion, queries: List[AwsCloudwatchQuery]) -> None:
        with ThreadPoolExecutor(max_workers=1) as executor:
            queue = ExecutorQueue(executor, tasks_per_key=lambda _: 1, name="test")
            g_builder = GraphBuilder(
                builder.graph,
                builder.cloud,
                builder.account,
                region,
                {region.id: region},
                builder.client,
                queue,
                builder.core_feedback,
                last_run_started_at=builder.last_run_started_at,
            )
            result = AwsCloudwatchMetricData.query_for_multiple(
                g_builder, start_at, start_at + timedelta(hours=2), queries
            )
            update_resource_metrics(lookup_map, result)
            # compute bucket_size_bytes
            for after_collect in builder.after_collect_actions:
                after_collect()

    start = datetime(2020, 5, 30, 15, 45, 30)

    collect_and_set_metrics(start, AwsRegion(id="us-east-1", name="us-east-1"), queries)

    assert bucket._resource_usage["standard_storage_bucket_size_bytes"]["avg"] == 1.0
    assert bucket._resource_usage["intelligent_tiering_storage_bucket_size_bytes"]["avg"] == 2.0
    assert bucket._resource_usage["standard_ia_storage_bucket_size_bytes"]["avg"] == 3.0
    # This values is computed internally using the other values. If the number does not match, the logic is broken!
    assert bucket._resource_usage["bucket_size_bytes"]["avg"] == 6.0
