from fix_plugin_aws.resource.opensearch import AwsOpenSearchDomain
from test.resources import round_trip_for


def test_opensearch_domains() -> None:
    round_trip_for(AwsOpenSearchDomain)
