from resoto_plugin_aws.resource.ssm import AwsSSMInstanceInformation, AwsSSMDocument, AwsSSMAccountSharingInfo
from test.resources import round_trip_for


def test_instances() -> None:
    first, builder = round_trip_for(AwsSSMInstanceInformation)
    assert len(builder.resources_of(AwsSSMInstanceInformation)) == 2


def test_documents() -> None:
    first, builder = round_trip_for(AwsSSMDocument)
    assert len(builder.resources_of(AwsSSMDocument)) == 1
    first.document_shared_with_accounts = ["a", "b", "c"]
    first.document_sharing_info = [
        AwsSSMAccountSharingInfo("a", "v1"),
        AwsSSMAccountSharingInfo("b", "v1"),
        AwsSSMAccountSharingInfo("c", "v2"),
    ]
