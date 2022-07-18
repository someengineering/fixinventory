from test.resources import round_trip_for

from resoto_plugin_aws.resource.rds import AwsRdsInstance


def test_rds_instances() -> None:
    first, builder = round_trip_for(AwsRdsInstance)
    assert len(builder.resources_of(AwsRdsInstance)) == 2
