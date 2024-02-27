from datetime import datetime, timezone
from textwrap import dedent
from types import SimpleNamespace
from typing import Any, cast

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.iam import (
    AwsIamPolicy,
    AwsIamGroup,
    AwsIamServerCertificate,
    AwsIamRole,
    AwsIamUser,
    AwsIamAccessKey,
    AwsIamInstanceProfile,
    CredentialReportLine,
)
from fixlib.graph import Graph
from test.resources import round_trip_for


def test_credentials_report() -> None:
    csv = dedent(
        """
        user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
        a,arn:aws:iam::test:user/a,2021-05-06T08:23:17+00:00,true,2021-12-08T09:34:46+00:00,2021-05-06T08:30:03+00:00,N/A,true,true,2021-05-06T08:23:18+00:00,2023-01-25T10:11:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
        b,arn:aws:iam::test:user/b,2022-05-06T08:23:17+00:00,false,2022-12-08T09:34:46+00:00,2022-05-06T08:30:03+00:00,N/A,false,false,2022-05-06T08:23:18+00:00,2023-01-25T10:11:00+00:00,eu-central-1,s3,true,2023-01-25T10:11:00+00:00,2023-01-25T10:11:00+00:00,eu-central-3,iam,false,N/A,false,N/A
        c,arn:aws:iam::test:user/c,2022-05-06T08:23:17+00:00,false,no_information,2022-05-06T08:30:03+00:00,N/A,false,false,2022-05-06T08:23:18+00:00,2023-01-25T10:11:00+00:00,eu-central-1,s3,true,2023-01-25T10:11:00+00:00,2023-01-25T10:11:00+00:00,eu-central-3,iam,false,N/A,false,N/A
        """
    ).strip()
    lines = CredentialReportLine.from_str(csv)
    assert len(lines) == 3
    assert lines["a"].password_enabled() is True
    assert lines["a"].password_last_used() == datetime(2021, 12, 8, 9, 34, 46, tzinfo=timezone.utc)
    assert [a.access_key_last_used.service_name for a in lines["a"].access_keys() if a.access_key_last_used] == ["iam"]
    assert lines["b"].password_enabled() is False
    assert lines["b"].password_last_used() == datetime(2022, 12, 8, 9, 34, 46, tzinfo=timezone.utc)
    assert [b.access_key_last_used.service_name for b in lines["b"].access_keys() if b.access_key_last_used] == [
        "s3",
        "iam",
    ]


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
    assert len(builder.graph.nodes) == 13
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
    res.delete_resource(client, Graph())


def test_aws_iam_policy_deletion() -> None:
    _, builder = round_trip_for(AwsIamUser)
    res = builder.resources_of(AwsIamPolicy)[0]

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-policy"
        assert kwargs["PolicyArn"] == res.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client, Graph())


def test_aws_iam_group_deletion() -> None:
    _, builder = round_trip_for(AwsIamUser)
    res = builder.resources_of(AwsIamGroup)[0]

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-group"
        assert kwargs["GroupName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client, Graph())


def test_aws_iam_role_deletion() -> None:
    _, builder = round_trip_for(AwsIamUser)
    res = builder.resources_of(AwsIamRole)[0]

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-role"
        assert kwargs["RoleName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client, Graph())


def test_aws_iam_user_deletion() -> None:
    _, builder = round_trip_for(AwsIamUser)
    res = builder.resources_of(AwsIamUser)[0]

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-user"
        assert kwargs["UserName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client, Graph())


def test_aws_iam_instance_profile_deletion() -> None:
    res, _ = round_trip_for(AwsIamInstanceProfile)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-instance-profile"
        assert kwargs["InstanceProfileName"] == res.name

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.delete_resource(client, Graph())


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
