from fix_plugin_aws.resource.acm import AwsAcmCertificate
from test.resources import round_trip_for


def test_certificates() -> None:
    round_trip_for(AwsAcmCertificate)
