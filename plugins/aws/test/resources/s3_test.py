from collections import defaultdict
from typing import Dict

from resoto_plugin_aws.resource.s3 import AwsS3Bucket
from test.resources import round_trip


def test_buckets() -> None:
    first, builder = round_trip("s3/list-buckets.json", AwsS3Bucket, "Buckets")
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_s3_bucket"] == 3
