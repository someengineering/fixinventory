from cloudsplaining.scan.policy_document import PolicyDocument
from cloudsplaining.scan.statement_detail import StatementDetail

from fix_plugin_aws.resource.base import AwsResource
from fix_plugin_aws.resource.iam import AwsIamUser, AwsIamGroup, AwsIamRole
from typing import Any, Dict, List

import re
from fix_plugin_aws.access_edges import (
    find_allowed_action,
    make_resoruce_regex,
    check_statement_match,
    check_principal_match,
    IamRequestContext,
    check_explicit_deny,
    compute_permissions,
)

from fixlib.baseresources import PolicySourceKind, PolicySource, PermissionLevel
from fixlib.json import to_json_str


def test_find_allowed_action() -> None:
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::bucket/*"]},
            {"Effect": "Allow", "Action": ["s3:ListBuckets"], "Resource": ["*"]},
            {"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": ["*"]},
            {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["arn:aws:s3:::bucket/*"]},
        ],
    }

    allowed_actions = find_allowed_action(PolicyDocument(policy_document), "s3")

    assert allowed_actions == {"s3:GetObject", "s3:PutObject", "s3:ListBuckets"}


def test_make_resoruce_regex() -> None:
    # Test case 1: Wildcard with *
    wildcard = "arn:aws:s3:::my-bucket/*"
    regex = make_resoruce_regex(wildcard)
    assert isinstance(regex, re.Pattern)
    assert regex.match("arn:aws:s3:::my-bucket/my-object")
    assert not regex.match("arn:aws:s3:::other-bucket/my-object")

    # Test case 2: Wildcard with ?
    wildcard = "arn:aws:s3:::my-bucket/?"
    regex = make_resoruce_regex(wildcard)
    assert isinstance(regex, re.Pattern)
    assert regex.match("arn:aws:s3:::my-bucket/a")
    assert not regex.match("arn:aws:s3:::my-bucket/ab")

    # Test case 3: Wildcard with multiple *
    wildcard = "arn:aws:s3:::*/*"
    regex = make_resoruce_regex(wildcard)
    assert isinstance(regex, re.Pattern)
    assert regex.match("arn:aws:s3:::my-bucket/my-object")
    assert regex.match("arn:aws:s3:::other-bucket/another-object")

    # Test case 4: Wildcard with multiple ?
    wildcard = "arn:aws:s3:::my-bucket/??"
    regex = make_resoruce_regex(wildcard)
    assert isinstance(regex, re.Pattern)
    assert regex.match("arn:aws:s3:::my-bucket/ab")
    assert not regex.match("arn:aws:s3:::my-bucket/abc")


def test_check_statement_match1() -> None:
    allow_statement = {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example-bucket/*",
        "Principal": {"AWS": ["arn:aws:iam::123456789012:user/example-user"]},
    }
    statement = StatementDetail(allow_statement)
    resource = AwsResource(id="bucket", arn="arn:aws:s3:::example-bucket/object.txt")
    principal = AwsResource(id="principal", arn="arn:aws:iam::123456789012:user/example-user")

    # Test matching statement
    result, constraints = check_statement_match(statement, "Allow", "s3:GetObject", resource, principal)
    assert result is True
    assert constraints == ["arn:aws:s3:::example-bucket/*"]

    # Test wrong effect
    result, constraints = check_statement_match(statement, "Deny", "s3:GetObject", resource, principal)
    assert result is False
    assert constraints == []

    # wrong principal does not match
    result, constraints = check_statement_match(statement, "Allow", "s3:GetObject", resource, resource)
    assert result is False

    # Test statement with condition
    allow_statement["Condition"] = {"StringEquals": {"s3:prefix": "private/"}}
    statement = StatementDetail(allow_statement)
    result, constraints = check_statement_match(statement, "Allow", "s3:GetObject", resource, principal)
    assert result is True

    # not providing principaal works
    result, constraints = check_statement_match(statement, "Allow", "s3:GetObject", resource, principal=None)
    assert result is True

    # not providing effect works
    result, constraints = check_statement_match(
        statement, effect=None, action="s3:GetObject", resource=resource, principal=None
    )
    assert result is True

    result, constraints = check_statement_match(statement, "Allow", "s3:GetObject", resource, principal)
    assert result is True
    assert constraints == ["arn:aws:s3:::example-bucket/*"]

    deny_statement = {
        "Effect": "Deny",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example-bucket/*",
        "Principal": {"AWS": ["arn:aws:iam::123456789012:user/example-user"]},
    }

    statement = StatementDetail(deny_statement)
    result, constraints = check_statement_match(statement, "Deny", "s3:GetObject", resource, principal)
    assert result is True
    assert constraints == ["arn:aws:s3:::example-bucket/*"]

    # test not resource
    not_resource_statement = dict(allow_statement)
    del not_resource_statement["Resource"]
    not_resource_statement["NotResource"] = "arn:aws:s3:::example-bucket/private/*"
    statement = StatementDetail(not_resource_statement)
    result, constraints = check_statement_match(statement, "Allow", "s3:GetObject", resource, principal)
    assert result is True
    assert constraints == ["not arn:aws:s3:::example-bucket/private/*"]


def test_check_principal_match() -> None:
    principal = AwsIamUser(id="user-id", arn="arn:aws:iam::123456789012:user/user-name")
    aws_principal_list = ["*", "arn:aws:iam::123456789012:user/user-name", "user-id", "123456789012"]

    assert check_principal_match(principal, aws_principal_list) is True

    principal = AwsIamUser(id="user-id", arn="arn:aws:iam::123456789012:user/user-name")
    aws_principal_list = ["another-arn", "another-id"]

    assert check_principal_match(principal, aws_principal_list) is False

    principal = AwsIamUser(id="user-id", arn="arn:aws:iam::123456789012:user/user-name")
    aws_principal_list = ["*"]

    assert check_principal_match(principal, aws_principal_list) is True


def test_no_explicit_deny() -> None:
    """Test when there is no explicit deny in any policies, expect 'NextStep'."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=[],
        permission_boundaries=[],
        service_control_policy_levels=[],
    )

    resource = AwsResource(id="some-resource", arn="arn:aws:s3:::example-bucket")
    action = "s3:GetObject"

    result = check_explicit_deny(request_context, resource, action, resource_based_policies=[])
    assert result == "NextStep"


def test_explicit_deny_in_identity_policy() -> None:
    """Test when there is an explicit deny without condition in identity policy, expect 'Denied'."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")
    assert principal.arn

    policy_json: Dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-bucket/*"}],
    }
    policy_document = PolicyDocument(policy_json)
    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=principal.arn), policy_document)]
    permission_boundaries: List[PolicyDocument] = []
    service_control_policy_levels: List[List[PolicyDocument]] = []

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=identity_policies,
        permission_boundaries=permission_boundaries,
        service_control_policy_levels=service_control_policy_levels,
    )

    resource = AwsResource(id="some-resource", arn="arn:aws:s3:::example-bucket/object.txt")
    action = "s3:GetObject"

    result = check_explicit_deny(request_context, resource, action, resource_based_policies=[])
    assert result == "Denied"


def test_explicit_deny_with_condition_in_identity_policy() -> None:
    """Test when there is an explicit deny with condition in identity policy, expect list of conditions."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")
    assert principal.arn

    policy_json: Dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
                "Condition": {"StringNotEquals": {"aws:username": "test-user"}},
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)
    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=principal.arn), policy_document)]

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=identity_policies,
        permission_boundaries=[],
        service_control_policy_levels=[],
    )

    resource = AwsResource(id="some-resource", arn="arn:aws:s3:::example-bucket/object.txt")
    action = "s3:GetObject"

    result = check_explicit_deny(request_context, resource, action, resource_based_policies=[])
    expected_conditions = [policy_json["Statement"][0]["Condition"]]
    assert result == expected_conditions


def test_explicit_deny_in_scp() -> None:
    """Test when there is an explicit deny without condition in SCP, expect 'Denied'."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")

    scp_policy_json: Dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}],
    }
    scp_policy_document = PolicyDocument(scp_policy_json)
    service_control_policy_levels = [[scp_policy_document]]

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=[],
        permission_boundaries=[],
        service_control_policy_levels=service_control_policy_levels,
    )

    resource = AwsResource(id="some-resource", arn="arn:aws:s3:::example-bucket/object.txt")
    action = "s3:GetObject"

    result = check_explicit_deny(request_context, resource, action, resource_based_policies=[])
    assert result == "Denied"


def test_explicit_deny_with_condition_in_scp() -> None:
    """Test when there is an explicit deny with condition in SCP, expect list of conditions."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")

    scp_policy_json: Dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }
    scp_policy_document = PolicyDocument(scp_policy_json)
    service_control_policy_levels = [
        [
            scp_policy_document,
        ]
    ]

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=[],
        permission_boundaries=[],
        service_control_policy_levels=service_control_policy_levels,
    )

    resource = AwsResource(id="some-resource", arn="arn:aws:s3:::example-bucket/object.txt")
    action = "s3:GetObject"

    result = check_explicit_deny(request_context, resource, action, resource_based_policies=[])
    expected_conditions = [scp_policy_json["Statement"][0]["Condition"]]
    assert result == expected_conditions


def test_explicit_deny_in_resource_policy() -> None:
    """Test when there is an explicit deny without condition in resource-based policy, expect 'Denied'."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=[],
        permission_boundaries=[],
        service_control_policy_levels=[],
    )

    policy_json: Dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)
    resource_based_policies = [
        (PolicySource(kind=PolicySourceKind.resource, uri="arn:aws:s3:::example-bucket"), policy_document)
    ]

    resource = AwsResource(id="some-resource", arn="arn:aws:s3:::example-bucket/object.txt")
    action = "s3:GetObject"

    result = check_explicit_deny(request_context, resource, action, resource_based_policies)
    assert result == "Denied"


def test_explicit_deny_with_condition_in_resource_policy() -> None:
    """Test when there is an explicit deny with condition in resource-based policy, expect list of conditions."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=[],
        permission_boundaries=[],
        service_control_policy_levels=[],
    )

    policy_json: Dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
                "Condition": {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}},
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)
    resource_based_policies = [
        (PolicySource(kind=PolicySourceKind.resource, uri="arn:aws:s3:::example-bucket"), policy_document)
    ]

    resource = AwsResource(id="some-resource", arn="arn:aws:s3:::example-bucket/object.txt")
    action = "s3:GetObject"

    result = check_explicit_deny(request_context, resource, action, resource_based_policies)
    expected_conditions = [policy_json["Statement"][0]["Condition"]]
    assert result == expected_conditions


def test_compute_permissions_user_inline_policy_allow() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3GetObject",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)

    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), policy_document)]

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])
    assert len(permissions) == 1
    assert permissions[0].action == "s3:ListBucket"
    assert permissions[0].level == PermissionLevel.list
    assert len(permissions[0].scopes) == 1
    s = permissions[0].scopes[0]
    assert s.source.kind == PolicySourceKind.principal
    assert s.source.uri == user.arn
    assert s.constraints == ("arn:aws:s3:::my-test-bucket",)


def test_compute_permissions_user_inline_policy_allow_with_conditions() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    condition = {"IpAddress": {"aws:SourceIp": "1.1.1.1"}}

    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3GetObject",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
                "Condition": condition,
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)

    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), policy_document)]

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])
    assert len(permissions) == 1
    assert permissions[0].action == "s3:ListBucket"
    assert permissions[0].level == PermissionLevel.list
    assert len(permissions[0].scopes) == 1
    s = permissions[0].scopes[0]
    assert s.source.kind == PolicySourceKind.principal
    assert s.source.uri == user.arn
    assert s.constraints == ("arn:aws:s3:::my-test-bucket",)
    assert s.conditions
    assert s.conditions.allow == (to_json_str(condition),)


def test_compute_permissions_user_inline_policy_deny() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyS3PutObject",
                "Effect": "Deny",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-test-bucket/*",
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)

    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), policy_document)]

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 0


def test_compute_permissions_user_inline_policy_deny_with_condition() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    condition = {"IpAddress": {"aws:SourceIp": "1.1.1.1"}}

    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyS3PutObject",
                "Effect": "Deny",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-test-bucket/*",
                "Condition": condition,
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)

    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), policy_document)]

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    # deny does not grant any permissions by itself, even if the condition is met
    assert len(permissions) == 0


def test_deny_overrides_allow() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    deny_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyS3PutObject",
                "Effect": "Deny",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    deny_policy_document = PolicyDocument(deny_policy_json)

    allow_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3PutObject",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    allow_policy_document = PolicyDocument(allow_policy_json)

    identity_policies = [
        (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), deny_policy_document),
        (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), allow_policy_document),
    ]

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 0


def test_deny_different_action_does_not_override_allow() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    deny_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyS3PutObject",
                "Effect": "Deny",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    deny_policy_document = PolicyDocument(deny_policy_json)

    allow_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3PutObject",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    allow_policy_document = PolicyDocument(allow_policy_json)

    identity_policies = [
        (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), deny_policy_document),
        (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), allow_policy_document),
    ]

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 1


def test_deny_overrides_allow_with_condition() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    condition = {"IpAddress": {"aws:SourceIp": "1.1.1.1"}}

    deny_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyS3PutObject",
                "Effect": "Deny",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
                "Condition": condition,
            }
        ],
    }
    deny_policy_document = PolicyDocument(deny_policy_json)

    allow_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3PutObject",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    allow_policy_document = PolicyDocument(allow_policy_json)

    identity_policies = [
        (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), deny_policy_document),
        (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), allow_policy_document),
    ]

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 1
    p = permissions[0]
    assert p.action == "s3:ListBucket"
    assert p.level == PermissionLevel.list
    assert len(p.scopes) == 1
    s = p.scopes[0]
    assert s.source.kind == PolicySourceKind.principal
    assert s.source.uri == user.arn
    assert s.constraints == ("arn:aws:s3:::my-test-bucket",)
    assert s.conditions
    assert s.conditions.deny == (to_json_str(condition),)


def test_compute_permissions_resource_based_policy_allow() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::111122223333:user/test-user")

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")
    assert bucket.arn

    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountAccess",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:user/test-user"},
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)

    request_context = IamRequestContext(
        principal=user, identity_policies=[], permission_boundaries=[], service_control_policy_levels=[]
    )

    resource_based_policies = [(PolicySource(kind=PolicySourceKind.resource, uri=bucket.arn), policy_document)]

    permissions = compute_permissions(
        resource=bucket, iam_context=request_context, resource_based_policies=resource_based_policies
    )

    assert len(permissions) == 1
    p = permissions[0]
    assert p.action == "s3:ListBucket"
    assert p.level == PermissionLevel.list
    assert len(p.scopes) == 1
    s = p.scopes[0]
    assert s.source.kind == PolicySourceKind.resource
    assert s.source.uri == bucket.arn
    assert s.constraints == ("arn:aws:s3:::my-test-bucket",)


def test_compute_permissions_permission_boundary_restrict() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    identity_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3DeleteObject",
                "Effect": "Allow",
                "Action": "s3:DeleteBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            },
            {
                "Sid": "AllowS3GetObject",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            },
        ],
    }
    identity_policy_document = PolicyDocument(identity_policy_json)

    permission_boundary_json = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Boundary", "Effect": "Allow", "Action": ["s3:ListBucket", "s3:PutObject"], "Resource": "*"}
        ],
    }
    permission_boundary_document = PolicyDocument(permission_boundary_json)

    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), identity_policy_document)]

    permission_boundaries = [permission_boundary_document]

    request_context = IamRequestContext(
        principal=user,
        identity_policies=identity_policies,
        permission_boundaries=permission_boundaries,
        service_control_policy_levels=[],
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 1
    p = permissions[0]
    assert p.action == "s3:ListBucket"
    assert p.level == PermissionLevel.list
    assert len(p.scopes) == 1
    s = p.scopes[0]
    assert s.source.kind == PolicySourceKind.principal
    assert s.source.uri == user.arn
    assert s.constraints == ("arn:aws:s3:::my-test-bucket",)


def test_compute_permissions_scp_deny() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    ec2_instance = AwsResource(id="instance123", arn="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")

    identity_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowTerminateInstances",
                "Effect": "Allow",
                "Action": "ec2:TerminateInstances",
                "Resource": ec2_instance.arn,
            }
        ],
    }
    identity_policy_document = PolicyDocument(identity_policy_json)

    scp_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "DenyTerminateInstances", "Effect": "Deny", "Action": "ec2:TerminateInstances", "Resource": "*"}
        ],
    }
    scp_policy_document = PolicyDocument(scp_policy_json)

    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), identity_policy_document)]

    service_control_policy_levels = [[scp_policy_document]]

    request_context = IamRequestContext(
        principal=user,
        identity_policies=identity_policies,
        permission_boundaries=[],
        service_control_policy_levels=service_control_policy_levels,
    )

    permissions = compute_permissions(resource=ec2_instance, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 0


def test_compute_permissions_user_with_group_policies() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    group = AwsResource(id="group123", arn="arn:aws:iam::123456789012:group/test-group")
    assert group.arn

    group_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AllowS3ListBucket", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": bucket.arn}
        ],
    }
    group_policy_document = PolicyDocument(group_policy_json)

    identity_policies = []

    identity_policies.append((PolicySource(kind=PolicySourceKind.group, uri=group.arn), group_policy_document))

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 1
    p = permissions[0]
    assert p.action == "s3:ListBucket"
    assert p.level == PermissionLevel.list
    assert len(p.scopes) == 1
    s = p.scopes[0]
    assert s.source.kind == PolicySourceKind.group
    assert s.source.uri == group.arn
    assert s.constraints == (bucket.arn,)


def test_compute_permissions_implicit_deny() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    table = AwsResource(id="table123", arn="arn:aws:dynamodb:us-east-1:123456789012:table/my-table")

    request_context = IamRequestContext(
        principal=user, identity_policies=[], permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=table, iam_context=request_context, resource_based_policies=[])

    # Assert that permissions do not include any actions (implicit deny)
    assert len(permissions) == 0


def test_compute_permissions_group_inline_policy_allow() -> None:
    group = AwsIamGroup(id="group123", arn="arn:aws:iam::123456789012:group/test-group")
    assert group.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3ListBucket",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)

    identity_policies = [(PolicySource(kind=PolicySourceKind.group, uri=group.arn), policy_document)]

    request_context = IamRequestContext(
        principal=group, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 1
    assert permissions[0].action == "s3:ListBucket"
    assert permissions[0].level == PermissionLevel.list
    assert len(permissions[0].scopes) == 1
    s = permissions[0].scopes[0]
    assert s.source.kind == PolicySourceKind.group
    assert s.source.uri == group.arn
    assert s.constraints == ("arn:aws:s3:::my-test-bucket",)


def test_compute_permissions_role_inline_policy_allow() -> None:
    role = AwsIamRole(id="role123", arn="arn:aws:iam::123456789012:role/test-role")
    assert role.arn

    bucket = AwsResource(id="bucket123", arn="arn:aws:s3:::my-test-bucket")

    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3PutObject",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-test-bucket",
            }
        ],
    }
    policy_document = PolicyDocument(policy_json)

    identity_policies = [(PolicySource(kind=PolicySourceKind.principal, uri=role.arn), policy_document)]

    request_context = IamRequestContext(
        principal=role, identity_policies=identity_policies, permission_boundaries=[], service_control_policy_levels=[]
    )

    permissions = compute_permissions(resource=bucket, iam_context=request_context, resource_based_policies=[])

    assert len(permissions) == 1
    assert permissions[0].action == "s3:ListBucket"
    assert permissions[0].level == PermissionLevel.list
    assert len(permissions[0].scopes) == 1
    s = permissions[0].scopes[0]
    assert s.source.kind == PolicySourceKind.principal
    assert s.source.uri == role.arn
    assert s.constraints == ("arn:aws:s3:::my-test-bucket",)
