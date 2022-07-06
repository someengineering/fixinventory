from resoto_plugin_aws.resource.iam import (
    AwsIamPolicy,
    AwsIamGroup,
    AwsIamServerCertificate,
    AwsIamRole,
    AwsIamUser,
    AwsIamAccessKey,
)
from test.resource import round_trip


def test_groups() -> None:
    first, _ = round_trip("iam/list-groups.json", AwsIamGroup, "Groups")
    assert first.group_policies == ["ExamplePolicy", "TestPolicy"]


def test_policies() -> None:
    round_trip("iam/list-policies.json", AwsIamPolicy, "Policies")


def test_server_certificates() -> None:
    round_trip(
        "iam/list-server-certificates.json",
        AwsIamServerCertificate,
        "ServerCertificateMetadataList",
        ignore_props={"dns_names", "sha1_fingerprint"},
    )


def test_roles() -> None:
    first, _ = round_trip("iam/list-roles.json", AwsIamRole, "Roles")
    assert first.role_policies == ["ExamplePolicy", "TestPolicy"]


def test_users() -> None:
    first, builder = round_trip("iam/list-users.json", AwsIamUser, "Users")
    assert first.user_policies == ["ExamplePolicy", "TestPolicy"]
    assert len(builder.graph.nodes) == 4
    # make sure access keys are created and connected as part of the user
    assert (test_user := builder.node(clazz=AwsIamUser, name="test_user")) is not None
    assert (ak_test := builder.node(clazz=AwsIamAccessKey, id="ak_test")) is not None
    assert builder.graph.has_edge(test_user, ak_test)
