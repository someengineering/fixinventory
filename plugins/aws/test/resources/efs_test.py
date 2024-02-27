from fix_plugin_aws.resource.efs import AwsEfsFileSystem, AwsEfsMountTarget, AwsEfsAccessPoint
from test.resources import round_trip_for


def test_efs_filesystem() -> None:
    first, builder = round_trip_for(AwsEfsFileSystem, "share_iops")
    assert len(builder.resources_of(AwsEfsMountTarget)) == 2


def test_efs_access_points() -> None:
    round_trip_for(AwsEfsAccessPoint)
