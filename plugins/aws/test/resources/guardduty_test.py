from fix_plugin_aws.resource.ec2 import AwsEc2Instance
from fix_plugin_aws.resource.guardduty import AwsGuardDutyFinding
from test.resources import round_trip_for


def test_guardduty_findings() -> None:
    collected, _ = round_trip_for(AwsEc2Instance, region_name="global", collect_also=[AwsGuardDutyFinding])
    assert len(collected._assessments) == 1
