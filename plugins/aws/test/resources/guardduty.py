from fix_plugin_aws.resource.guardduty import AwsGuardDutyFinding
from test.resources import round_trip_for


def test_notebooks() -> None:
    _, builder = round_trip_for(AwsGuardDutyFinding)
    assert len(builder.resources_of(AwsGuardDutyFinding)) == 1
