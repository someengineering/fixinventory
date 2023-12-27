from resoto_plugin_aws.resource.ssm import AwsSSMInstanceInformation, AwsSSMDocument
from test.resources import round_trip_for


def test_instances() -> None:
    first, builder = round_trip_for(AwsSSMInstanceInformation)
    assert len(builder.resources_of(AwsSSMInstanceInformation)) == 2


def test_documents() -> None:
    first, builder = round_trip_for(AwsSSMDocument)
    assert len(builder.resources_of(AwsSSMDocument)) == 1
