from fix_plugin_aws.resource.waf import AwsWafWebACL
from test.resources import round_trip_for


def test_acls() -> None:
    round_trip_for(AwsWafWebACL)
