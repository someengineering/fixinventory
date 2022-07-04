from resoto_plugin_aws.resource.iam import (
    AWSIAMPolicy,
    AWSIAMGroup,
    AWSIAMServerCertificate,
    AWSIAMRole,
    AWSIAMUser,
    AWSIAMAccessKey,
)
from test.resource import round_trip


def test_groups() -> None:
    first, _ = round_trip("iam/list-groups.json", AWSIAMGroup, "Groups")
    assert first.group_policies == ["ExamplePolicy", "TestPolicy"]


def test_policies() -> None:
    round_trip("iam/list-policies.json", AWSIAMPolicy, "Policies")


def test_server_certificates() -> None:
    round_trip(
        "iam/list-server-certificates.json",
        AWSIAMServerCertificate,
        "ServerCertificateMetadataList",
        ignore_props={"dns_names", "sha1_fingerprint"},
    )


def test_roles() -> None:
    first, _ = round_trip("iam/list-roles.json", AWSIAMRole, "Roles")
    assert first.role_policies == ["ExamplePolicy", "TestPolicy"]


def test_users() -> None:
    first, builder = round_trip("iam/list-users.json", AWSIAMUser, "Users")
    assert first.user_policies == ["ExamplePolicy", "TestPolicy"]
    assert len(builder.graph.nodes) == 4
    # make sure access keys are created and connected as part of the user
    assert (test_user := builder.node(clazz=AWSIAMUser, name="test_user")) is not None
    assert (ak_test := builder.node(clazz=AWSIAMAccessKey, id="ak_test")) is not None
    assert builder.graph.has_edge(test_user, ak_test)
