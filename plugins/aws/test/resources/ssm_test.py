from fix_plugin_aws.resource.ec2 import AwsEc2Instance
from fix_plugin_aws.resource.ssm import (
    AwsSSMInstance,
    AwsSSMDocument,
    AwsSSMAccountSharingInfo,
    AwsSSMResourceCompliance,
)
from test.resources import round_trip_for

from fixlib.baseresources import Severity


def test_instances() -> None:
    first, builder = round_trip_for(AwsSSMInstance)
    assert len(builder.resources_of(AwsSSMInstance)) == 2


def test_resource_compliance() -> None:
    collected, _ = round_trip_for(AwsEc2Instance, region_name="global", collect_also=[AwsSSMResourceCompliance])
    asseessments = collected._assessments
    assert asseessments[0].findings[0].title == "State Manager Association Compliance"
    assert asseessments[0].findings[0].severity == Severity.high


def test_documents() -> None:
    first, builder = round_trip_for(AwsSSMDocument)
    assert len(builder.resources_of(AwsSSMDocument)) == 1
    first.document_shared_with_accounts = ["a", "b", "c"]
    first.document_sharing_info = [
        AwsSSMAccountSharingInfo("a", "v1"),
        AwsSSMAccountSharingInfo("b", "v1"),
        AwsSSMAccountSharingInfo("c", "v2"),
    ]
