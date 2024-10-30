from fix_plugin_aws.resource.inspector import AwsInspectorFinding
from fix_plugin_aws.resource.ec2 import AwsEc2Instance

from test.resources import round_trip_for


def test_inspector_findings() -> None:
    collected, _ = round_trip_for(AwsEc2Instance, region_name="global", collect_also=[AwsInspectorFinding])
    asseessments = collected._assessments
    assert asseessments[0].findings[0].title == "foo"
    assert asseessments[0].findings[0].description == "foo"
