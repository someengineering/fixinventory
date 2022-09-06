from resoto_plugin_aws.resource.ecs import AwsEcsCluster
from test.resources import round_trip_for


def test_ecs_cluster() -> None:
    first, builder = round_trip_for(AwsEcsCluster)
    assert len(builder.resources_of(AwsEcsCluster)) == 1
