from resoto_plugin_aws.resource.iam import (
    AwsIamPolicy,
    AwsIamGroup,
    AwsIamServerCertificate,
    AwsIamRole,
    AwsIamUser,
    AwsIamAccessKey,
    AwsIamInstanceProfile,
)
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_server_certificates() -> None:
    round_trip_for(AwsIamServerCertificate, "dns_names", "sha1_fingerprint")


def test_instance_profiles() -> None:
    round_trip_for(AwsIamInstanceProfile)


def test_user_roles_groups_policies_keys() -> None:
    _, builder = round_trip_for(AwsIamUser)

    # users ------------
    assert len(builder.resources_of(AwsIamUser)) == 3
    assert (test_user := builder.node(clazz=AwsIamUser, name="test_user")) is not None
    assert test_user.atime is not None
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
    assert policy.policy_document is not None

    # roles
    assert len(builder.resources_of(AwsIamRole)) == 2
    assert (role := builder.node(clazz=AwsIamRole, name="role1")) is not None
    assert len(role.role_policies) == 1


def test_server_certificate_deletion() -> None:
    res, _ = round_trip_for(AwsIamServerCertificate, "dns_names", "sha1_fingerprint")

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-server-certificate"
        assert kwargs["ServerCertificateName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client)


def test_aws_iam_policy_deletion() -> None:
    _, builder = round_trip_for(AwsIamUser)
    res = builder.resources_of(AwsIamPolicy)[0]

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-policy"
        assert kwargs["PolicyArn"] == res.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client)


def test_aws_iam_group_deletion() -> None:
    _, builder = round_trip_for(AwsIamUser)
    res = builder.resources_of(AwsIamGroup)[0]

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-group"
        assert kwargs["GroupName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client)


def test_aws_iam_role_deletion() -> None:
    _, builder = round_trip_for(AwsIamUser)
    res = builder.resources_of(AwsIamRole)[0]

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-role"
        assert kwargs["RoleName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client)


def test_aws_iam_user_deletion() -> None:
    _, builder = round_trip_for(AwsIamUser)
    res = builder.resources_of(AwsIamUser)[0]

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-user"
        assert kwargs["UserName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client)


def test_aws_iam_instance_profile_deletion() -> None:
    res, _ = round_trip_for(AwsIamInstanceProfile)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-instance-profile"
        assert kwargs["InstanceProfileName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client)


def test_tagging() -> None:

    res, _ = round_trip_for(AwsIamServerCertificate, "dns_names", "sha1_fingerprint")

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-server-certificate"
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]
        assert kwargs["ServerCertificateName"] == res.name

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-server-certificate"
        assert kwargs["TagKeys"] == ["foo"]
        assert kwargs["ServerCertificateName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    res.delete_resource_tag(client, "foo")
