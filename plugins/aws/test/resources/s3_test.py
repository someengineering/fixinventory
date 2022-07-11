from test.resources import round_trip_for

from resoto_plugin_aws.resource.s3 import AwsS3Bucket


def test_buckets() -> None:
    first, builder = round_trip_for(AwsS3Bucket)
    assert len(builder.resources_of(AwsS3Bucket)) == 3
