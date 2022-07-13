from resoto_plugin_aws.resource.eks import AwsEksCluster, AwsEksNodegroup
from test.resources import round_trip_for


def test_eks_nodegroup() -> None:
    first, builder = round_trip_for(AwsEksCluster)
    assert len(builder.resources_of(AwsEksCluster)) == 1
    assert len(builder.resources_of(AwsEksNodegroup)) == 1
