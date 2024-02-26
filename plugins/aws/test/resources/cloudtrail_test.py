from concurrent.futures import ThreadPoolExecutor

from fix_plugin_aws.resource.cloudtrail import AwsCloudTrail
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.s3 import AwsS3Bucket
from fix_plugin_aws.resource.sns import AwsSnsTopic
from fixlib.threading import ExecutorQueue
from test.resources import round_trip_for


def test_trails() -> None:
    first, builder = round_trip_for(AwsCloudTrail, region_name="us-east-1")
    with ThreadPoolExecutor(1) as executor:
        builder.executor = ExecutorQueue(executor, "dummy")
        AwsS3Bucket.collect_resources(builder)
        AwsKmsKey.collect_resources(builder)
        AwsSnsTopic.collect_resources(builder)
        builder.executor.wait_for_submitted_work()
        data = builder.graph.nodes(data=True)[first]
        first.connect_in_graph(builder, data["source"])
        assert len(builder.edges_of(AwsCloudTrail, AwsS3Bucket)) == 1
        assert len(builder.edges_of(AwsCloudTrail, AwsKmsKey)) == 1
        assert len(builder.edges_of(AwsCloudTrail, AwsSnsTopic)) == 1
