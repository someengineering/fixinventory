from fix_plugin_aws.resource.ssm import (
    AwsSSMInstance,
    AwsSSMDocument,
    AwsSSMAccountSharingInfo,
    AwsSSMResourceCompliance,
)
from test.resources import round_trip_for


def test_instances() -> None:
    first, builder = round_trip_for(AwsSSMInstance)
    assert len(builder.resources_of(AwsSSMInstance)) == 2


def test_resource_compliance() -> None:
    round_trip_for(AwsSSMResourceCompliance)


def test_documents() -> None:
    first, builder = round_trip_for(AwsSSMDocument)
    assert len(builder.resources_of(AwsSSMDocument)) == 1
    first.document_shared_with_accounts = ["a", "b", "c"]
    first.document_sharing_info = [
        AwsSSMAccountSharingInfo("a", "v1"),
        AwsSSMAccountSharingInfo("b", "v1"),
        AwsSSMAccountSharingInfo("c", "v2"),
    ]
