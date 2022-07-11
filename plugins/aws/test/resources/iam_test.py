from resoto_plugin_aws.resource.iam import (
    AwsIamPolicy,
    AwsIamGroup,
    AwsIamServerCertificate,
    AwsIamRole,
    AwsIamUser,
    AwsIamAccessKey,
)
from test.resources import round_trip_for


def test_server_certificates() -> None:
    round_trip_for(AwsIamServerCertificate, "dns_names", "sha1_fingerprint")


def test_user_roles_groups_policies_keys() -> None:
    _, builder = round_trip_for(AwsIamUser)

    # users ------------
    assert len(builder.resources_of(AwsIamUser)) == 3
    assert (test_user := builder.node(clazz=AwsIamUser, name="test_user")) is not None
    assert [p.policy_name for p in test_user.user_policies] == ["stsAssumeRole"]

    # keys ------------
    assert len(builder.resources_of(AwsIamAccessKey)) == 2
    assert (ak_test := builder.node(clazz=AwsIamAccessKey, id="ak_test")) is not None
    assert len(builder.graph.nodes) == 12
    # make sure access keys are created and connected as part of the user
    assert builder.graph.has_edge(test_user, ak_test)

    # groups ------------
    assert len(builder.resources_of(AwsIamGroup)) == 1
    assert (group := builder.node(clazz=AwsIamGroup, name="test_group")) is not None
    assert [p.policy_name for p in group.group_policies] == ["stsAssumeRole"]

    # policies ------------
    assert len(builder.resources_of(AwsIamPolicy)) == 4
    assert (policy := builder.node(clazz=AwsIamPolicy, name="master-elb")) is not None
    assert policy.policy_attachment_count == 1

    # roles
    assert len(builder.resources_of(AwsIamRole)) == 2
    assert (role := builder.node(clazz=AwsIamRole, name="role1")) is not None
    assert len(role.role_policies) == 1
