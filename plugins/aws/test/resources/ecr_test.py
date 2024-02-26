from fix_plugin_aws.resource.ecr import AwsEcrRepository
from test.resources import round_trip_for


def test_ecr_repositories() -> None:
    first, builder = round_trip_for(AwsEcrRepository)
    assert len(builder.resources_of(AwsEcrRepository)) == 3
