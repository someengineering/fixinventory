from fix_plugin_aws.resource.inspector import AwsInspectorFinding
from test.resources import round_trip_for


def test_inspector_findings() -> None:
    round_trip_for(AwsInspectorFinding)
