from cloudsplaining.scan.policy_document import PolicyDocument

from fix_plugin_aws.resource.base import AwsResource
from fix_plugin_aws.resource.iam import AwsIamUser, AwsIamGroup, AwsIamRole
from typing import Any, Dict
from policy_sentry.util.arns import ARN

import re
from fix_plugin_aws.access_edges.edge_builder import (
    find_allowed_action,
    make_resoruce_regex,
    check_statement_match,
    check_principal_match,
    IamRequestContext,
    check_explicit_deny,
    compute_permissions,
    ActionToCheck,
    get_actions_matching_arn,
)
from fix_plugin_aws.access_edges.types import FixPolicyDocument, FixStatementDetail, ArnResourceValueKind

from fix_plugin_aws.access_edges.arn_tree import ArnTree

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


def atc(action: str) -> ActionToCheck:
    splitted = action.split(":")
    return ActionToCheck(
        raw=action, raw_lower=action.lower(), service=splitted[0].lower(), action_name=splitted[1].lower()
    )


def test_check_statement_match1() -> None:
    allow_statement = {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example-bucket/*",
        "Principal": {"AWS": ["arn:aws:iam::123456789012:user/example-user"]},
    }
    statement = FixStatementDetail(allow_statement)
    resource_arn = ARN("arn:aws:s3:::example-bucket/object.txt")
    resource = AwsResource(id="bucket", arn=resource_arn.arn)
    principal = AwsResource(id="principal", arn="arn:aws:iam::123456789012:user/example-user")

    # Test matching statement
    match_fn = check_statement_match(statement, "Allow", atc("s3:GetObject"), principal)
    assert match_fn is not None
    constraints = match_fn(resource_arn)
    assert constraints == ["arn:aws:s3:::example-bucket/*"]

    # Test wrong effect
    match_fn = check_statement_match(statement, "Deny", atc("s3:GetObject"), principal)
    assert match_fn is None

    # wrong principal does not match
    match_fn = check_statement_match(statement, "Allow", atc("s3:GetObject"), resource)
    assert match_fn is None

    # Test statement with condition
    allow_statement["Condition"] = {"StringEquals": {"s3:prefix": "private/"}}
    statement = FixStatementDetail(allow_statement)
    match_fn = check_statement_match(statement, "Allow", atc("s3:GetObject"), principal)
    assert match_fn is not None
    result = match_fn(resource_arn)
    assert result is not None

    # not providing principal works
    match_fn = check_statement_match(statement, "Allow", atc("s3:GetObject"), principal=None)
    assert match_fn is not None
    result = match_fn(resource_arn)
    assert result is not None

    # not providing effect works
    match_fn = check_statement_match(statement, effect=None, action=atc("s3:GetObject"), principal=None)
    assert match_fn is not None
    result = match_fn(resource_arn)
    assert result is not None

    match_fn = check_statement_match(statement, "Allow", atc("s3:GetObject"), principal)
    assert match_fn is not None
    constraints = match_fn(resource_arn)
    assert constraints == ["arn:aws:s3:::example-bucket/*"]

    deny_statement = {
        "Effect": "Deny",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example-bucket/*",
        "Principal": {"AWS": ["arn:aws:iam::123456789012:user/example-user"]},
    }

    statement = FixStatementDetail(deny_statement)
    match_fn = check_statement_match(statement, "Deny", atc("s3:GetObject"), principal)
    assert match_fn is not None
    constraints = match_fn(resource_arn)
    assert constraints == ["arn:aws:s3:::example-bucket/*"]

    # test not resource
    not_resource_statement = dict(allow_statement)
    del not_resource_statement["Resource"]
    not_resource_statement["NotResource"] = "arn:aws:s3:::example-bucket/private/*"
    statement = FixStatementDetail(not_resource_statement)
    match_fn = check_statement_match(statement, "Allow", atc("s3:GetObject"), principal)
    assert match_fn is not None
    constraints = match_fn(resource_arn)
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
        identity_policies=(),
        permission_boundaries=(),
        service_control_policy_levels=(),
    )

    resource_arn = ARN("arn:aws:s3:::example-bucket")
    action = atc("s3:GetObject")

    result = check_explicit_deny(request_context, action, resource_based_policies=())(resource_arn)
    assert result == "NextStep"


def test_explicit_deny_in_identity_policy() -> None:
    """Test when there is an explicit deny without condition in identity policy, expect 'Denied'."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")
    assert principal.arn

    policy_json: Dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-bucket/*"}],
    }
    policy_document = FixPolicyDocument(policy_json)
    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=principal.arn), policy_document)])
    permission_boundaries: tuple[FixPolicyDocument, ...] = ()
    service_control_policy_levels: tuple[tuple[FixPolicyDocument, ...], ...] = ()

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=identity_policies,
        permission_boundaries=permission_boundaries,
        service_control_policy_levels=service_control_policy_levels,
    )

    resource_arn = ARN("arn:aws:s3:::example-bucket/object.txt")
    action = atc("s3:GetObject")

    result = check_explicit_deny(request_context, action, resource_based_policies=())(resource_arn)
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
    policy_document = FixPolicyDocument(policy_json)
    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=principal.arn), policy_document)])

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=identity_policies,
        permission_boundaries=(),
        service_control_policy_levels=(),
    )

    resource_arn = ARN("arn:aws:s3:::example-bucket/object.txt")
    action = atc("s3:GetObject")

    result = check_explicit_deny(request_context, action, resource_based_policies=())(resource_arn)
    expected_conditions = [policy_json["Statement"][0]["Condition"]]
    assert result == expected_conditions


def test_explicit_deny_in_scp() -> None:
    """Test when there is an explicit deny without condition in SCP, expect 'Denied'."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")

    scp_policy_json: Dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}],
    }
    scp_policy_document = FixPolicyDocument(scp_policy_json)
    service_control_policy_levels = tuple([tuple([scp_policy_document])])

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=(),
        permission_boundaries=(),
        service_control_policy_levels=service_control_policy_levels,
    )

    resource_arn = ARN("arn:aws:s3:::example-bucket/object.txt")
    action = atc("s3:GetObject")

    result = check_explicit_deny(request_context, action, resource_based_policies=())(resource_arn)
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
    scp_policy_document = FixPolicyDocument(scp_policy_json)
    service_control_policy_levels = tuple(
        [
            tuple(
                [
                    scp_policy_document,
                ]
            )
        ]
    )

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=(),
        permission_boundaries=(),
        service_control_policy_levels=service_control_policy_levels,
    )

    resource_arn = ARN("arn:aws:s3:::example-bucket/object.txt")
    action = atc("s3:GetObject")

    result = check_explicit_deny(request_context, action, resource_based_policies=())(resource_arn)
    expected_conditions = [scp_policy_json["Statement"][0]["Condition"]]
    assert result == expected_conditions


def test_explicit_deny_in_resource_policy() -> None:
    """Test when there is an explicit deny without condition in resource-based policy, expect 'Denied'."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=(),
        permission_boundaries=(),
        service_control_policy_levels=(),
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
    policy_document = FixPolicyDocument(policy_json)
    resource_based_policies = tuple(
        [(PolicySource(kind=PolicySourceKind.resource, uri="arn:aws:s3:::example-bucket"), policy_document)]
    )

    resource_arn = ARN("arn:aws:s3:::example-bucket/object.txt")
    action = atc("s3:GetObject")

    result = check_explicit_deny(request_context, action, resource_based_policies)(resource_arn)
    assert result == "Denied"


def test_explicit_deny_with_condition_in_resource_policy() -> None:
    """Test when there is an explicit deny with condition in resource-based policy, expect list of conditions."""
    principal = AwsIamUser(id="AID1234567890", arn="arn:aws:iam::123456789012:user/test-user")

    request_context = IamRequestContext(
        principal=principal,
        identity_policies=(),
        permission_boundaries=(),
        service_control_policy_levels=(),
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
    policy_document = FixPolicyDocument(policy_json)
    resource_based_policies = tuple(
        [(PolicySource(kind=PolicySourceKind.resource, uri="arn:aws:s3:::example-bucket"), policy_document)]
    )

    resource_arn = ARN("arn:aws:s3:::example-bucket/object.txt")
    action = atc("s3:GetObject")

    result = check_explicit_deny(request_context, action, resource_based_policies)(resource_arn)
    expected_conditions = [policy_json["Statement"][0]["Condition"]]
    assert result == expected_conditions


def test_compute_permissions_user_inline_policy_allow() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket_arn = ARN("arn:aws:s3:::my-test-bucket")

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
    policy_document = FixPolicyDocument(policy_json)

    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), policy_document)])

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket_arn,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket_arn.arn),
    )
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

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    policy_document = FixPolicyDocument(policy_json)

    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), policy_document)])

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )
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

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    policy_document = FixPolicyDocument(policy_json)

    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), policy_document)])

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )

    assert len(permissions) == 0


def test_compute_permissions_user_inline_policy_deny_with_condition() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    policy_document = FixPolicyDocument(policy_json)

    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), policy_document)])

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )

    # deny does not grant any permissions by itself, even if the condition is met
    assert len(permissions) == 0


def test_deny_overrides_allow() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    deny_policy_document = FixPolicyDocument(deny_policy_json)

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
    allow_policy_document = FixPolicyDocument(allow_policy_json)

    identity_policies = tuple(
        [
            (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), deny_policy_document),
            (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), allow_policy_document),
        ]
    )

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )

    assert len(permissions) == 0


def test_deny_different_action_does_not_override_allow() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    deny_policy_document = FixPolicyDocument(deny_policy_json)

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
    allow_policy_document = FixPolicyDocument(allow_policy_json)

    identity_policies = tuple(
        [
            (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), deny_policy_document),
            (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), allow_policy_document),
        ]
    )

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )

    assert len(permissions) == 1


def test_deny_overrides_allow_with_condition() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    assert user.arn

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    deny_policy_document = FixPolicyDocument(deny_policy_json)

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
    allow_policy_document = FixPolicyDocument(allow_policy_json)

    identity_policies = tuple(
        [
            (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), deny_policy_document),
            (PolicySource(kind=PolicySourceKind.principal, uri=user.arn), allow_policy_document),
        ]
    )

    request_context = IamRequestContext(
        principal=user, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )

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

    bucket = ARN("arn:aws:s3:::my-test-bucket")
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
    policy_document = FixPolicyDocument(policy_json)

    request_context = IamRequestContext(
        principal=user, identity_policies=(), permission_boundaries=(), service_control_policy_levels=()
    )

    resource_based_policies = tuple([(PolicySource(kind=PolicySourceKind.resource, uri=bucket.arn), policy_document)])

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=resource_based_policies,
        resource_actions=get_actions_matching_arn(bucket.arn),
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

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    identity_policy_document = FixPolicyDocument(identity_policy_json)

    permission_boundary_json = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Boundary", "Effect": "Allow", "Action": ["s3:ListBucket", "s3:PutObject"], "Resource": "*"}
        ],
    }
    permission_boundary_document = FixPolicyDocument(permission_boundary_json)

    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), identity_policy_document)])

    permission_boundaries = tuple([permission_boundary_document])

    request_context = IamRequestContext(
        principal=user,
        identity_policies=identity_policies,
        permission_boundaries=permission_boundaries,
        service_control_policy_levels=(),
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )

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

    ec2_instance = ARN("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")

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
    identity_policy_document = FixPolicyDocument(identity_policy_json)

    scp_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "DenyTerminateInstances", "Effect": "Deny", "Action": "ec2:TerminateInstances", "Resource": "*"}
        ],
    }
    scp_policy_document = FixPolicyDocument(scp_policy_json)

    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=user.arn), identity_policy_document)])

    service_control_policy_levels = ((scp_policy_document,),)

    request_context = IamRequestContext(
        principal=user,
        identity_policies=identity_policies,
        permission_boundaries=(),
        service_control_policy_levels=service_control_policy_levels,
    )

    permissions = compute_permissions(
        resource=ec2_instance,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(ec2_instance.arn),
    )

    assert len(permissions) == 0


def test_compute_permissions_user_with_group_policies() -> None:
    user = AwsIamUser(id="user123", arn="arn:aws:iam::123456789012:user/test-user")
    bucket = ARN("arn:aws:s3:::my-test-bucket")

    group = AwsResource(id="group123", arn="arn:aws:iam::123456789012:group/test-group")
    assert group.arn

    group_policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AllowS3ListBucket", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": bucket.arn}
        ],
    }
    group_policy_document = FixPolicyDocument(group_policy_json)

    identity_policies = []

    identity_policies.append((PolicySource(kind=PolicySourceKind.group, uri=group.arn), group_policy_document))

    request_context = IamRequestContext(
        principal=user,
        identity_policies=tuple(identity_policies),
        permission_boundaries=(),
        service_control_policy_levels=(),
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn or ""),
    )

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
    table = ARN("arn:aws:dynamodb:us-east-1:123456789012:table/my-table")

    request_context = IamRequestContext(
        principal=user, identity_policies=(), permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=table,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(table.arn),
    )

    # Assert that permissions do not include any actions (implicit deny)
    assert len(permissions) == 0


def test_compute_permissions_group_inline_policy_allow() -> None:
    group = AwsIamGroup(id="group123", arn="arn:aws:iam::123456789012:group/test-group")
    assert group.arn

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    policy_document = FixPolicyDocument(policy_json)

    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.group, uri=group.arn), policy_document)])

    request_context = IamRequestContext(
        principal=group, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )

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

    bucket = ARN("arn:aws:s3:::my-test-bucket")

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
    policy_document = FixPolicyDocument(policy_json)

    identity_policies = tuple([(PolicySource(kind=PolicySourceKind.principal, uri=role.arn), policy_document)])

    request_context = IamRequestContext(
        principal=role, identity_policies=identity_policies, permission_boundaries=(), service_control_policy_levels=()
    )

    permissions = compute_permissions(
        resource=bucket,
        iam_context=request_context,
        resource_based_policies=(),
        resource_actions=get_actions_matching_arn(bucket.arn),
    )

    assert len(permissions) == 1
    assert permissions[0].action == "s3:ListBucket"
    assert permissions[0].level == PermissionLevel.list
    assert len(permissions[0].scopes) == 1
    s = permissions[0].scopes[0]
    assert s.source.kind == PolicySourceKind.principal
    assert s.source.uri == role.arn
    assert s.constraints == ("arn:aws:s3:::my-test-bucket",)


def test_principal_tree_add_allow_all_wildcard() -> None:
    """Test adding wildcard (*) permission to the principal tree."""
    tree = ArnTree[str]()
    principal_arn = "arn:aws:iam::123456789012:user/test-user"

    tree._add_allow_all_wildcard(principal_arn)

    # Verify the wildcard partition exists
    assert len(tree.partitions) == 1
    partition = tree.partitions[0]
    assert partition.key == "*"
    assert partition.wildcard is True
    assert principal_arn in partition.values


def test_principal_tree_add_resource() -> None:
    """Test adding a resource ARN to the principal tree."""
    tree = ArnTree[str]()
    principal_arn = "arn:aws:iam::123456789012:user/test-user"
    resource_arn = "arn:aws:s3:::my-bucket/my-object"

    tree._add_resource(resource_arn, principal_arn)

    # Verify the partition structure
    assert len(tree.partitions) == 1
    partition = tree.partitions[0]
    assert partition.key == "aws"
    assert not partition.wildcard

    # Verify service level
    assert len(partition.children) == 1
    service = partition.children[0]
    assert service.key == "s3"

    # Verify region level
    assert len(service.children) == 1
    region = service.children[0]
    assert region.key == "*"
    assert region.wildcard

    # Verify account level
    assert len(region.children) == 1
    account = region.children[0]
    assert account.key == "*"
    assert account.wildcard

    # Verify resource level
    assert len(account.children) == 1
    resource = account.children[0]
    assert resource.key == "my-bucket/my-object"
    assert resource.kind == ArnResourceValueKind.Static
    assert principal_arn in resource.values
    assert not resource.not_resource


def test_principal_tree_add_resource_with_wildcard() -> None:
    """Test adding a resource ARN with wildcards to the principal tree."""
    tree = ArnTree[str]()
    principal_arn = "arn:aws:iam::123456789012:user/test-user"
    resource_arn = "arn:aws:s3:::my-bucket/*"

    tree._add_resource(resource_arn, principal_arn)

    # Verify the resource level has correct wildcard pattern
    partition = tree.partitions[0]
    service = partition.children[0]
    region = service.children[0]
    account = region.children[0]
    resource = account.children[0]

    assert resource.key == "my-bucket/*"
    assert resource.kind == ArnResourceValueKind.Pattern
    assert principal_arn in resource.values


def test_principal_tree_add_not_resource() -> None:
    """Test adding a NotResource ARN to the principal tree."""
    tree = ArnTree[str]()
    principal_arn = "arn:aws:iam::123456789012:user/test-user"
    resource_arn = "arn:aws:s3:::my-bucket/private/*"

    tree._add_resource(resource_arn, principal_arn, nr=True)

    # Verify the NotResource flag is set correctly through the tree
    partition = tree.partitions[0]
    service = partition.children[0]
    region = service.children[0]
    account = region.children[0]
    resource = account.children[0]
    assert resource.not_resource


def test_principal_tree_add_service() -> None:
    """Test adding a service to the principal tree."""
    tree = ArnTree[str]()
    principal_arn = "arn:aws:iam::123456789012:user/test-user"
    service_prefix = "s3"

    tree._add_service(service_prefix, principal_arn)

    # Verify service is added under wildcard partition
    assert len(tree.partitions) == 1
    partition = tree.partitions[0]
    assert partition.key == "*"

    assert len(partition.children) == 1
    service = partition.children[0]
    assert service.key == "s3"
    assert principal_arn in service.values


def test_principal_tree_add_principal_policy() -> None:
    """Test adding a principal with policy documents to the principal tree."""
    tree = ArnTree[str]()
    principal_arn = "arn:aws:iam::123456789012:user/test-user"

    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"},
            {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"},
        ],
    }

    policy_doc = FixPolicyDocument(policy_json)
    tree.add_element(principal_arn, [policy_doc])

    # Verify both the specific resource and wildcard permissions are added
    assert any(
        p.key == "aws"
        and any(
            s.key == "s3"
            and any(
                r.key == "*"
                and any(a.key == "*" and any(res.key == "my-bucket/*" for res in a.children) for a in r.children)
                for r in s.children
            )
            for s in p.children
        )
        for p in tree.partitions
    )


def test_principal_tree_list_principals() -> None:
    """Test listing principals that have access to a given ARN."""
    tree = ArnTree[str]()
    principal1 = "arn:aws:iam::123456789012:user/test-user1"
    principal2 = "arn:aws:iam::123456789012:user/test-user2"

    # Add different types of permissions
    policy_doc1 = FixPolicyDocument(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}],
        }
    )

    policy_doc2 = FixPolicyDocument(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"}],
        }
    )

    tree.add_element(principal1, [policy_doc1])
    tree.add_element(principal2, [policy_doc2])

    # Test specific resource access
    resource_arn = ARN("arn:aws:s3:::my-bucket/test.txt")
    matching_principals = tree.find_matching_values(resource_arn)

    assert principal1 in matching_principals  # Has specific access
    assert principal2 in matching_principals  # Has wildcard access


def test_principal_tree_add_multiple_statements() -> None:
    """Test adding multiple statements for the same principal."""
    tree = ArnTree[str]()
    principal_arn = "arn:aws:iam::123456789012:user/test-user"

    policy_doc = FixPolicyDocument(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket1/*"},
                {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::bucket2/*"},
            ],
        }
    )

    tree.add_element(principal_arn, [policy_doc])

    # Test access to both buckets
    bucket1_arn = ARN("arn:aws:s3:::bucket1/test.txt")
    bucket2_arn = ARN("arn:aws:s3:::bucket2/test.txt")

    assert principal_arn in tree.find_matching_values(bucket1_arn)
    assert principal_arn in tree.find_matching_values(bucket2_arn)


def test_principal_tree_not_resource() -> None:
    """Test NotResource handling in the principal tree."""
    tree = ArnTree[str]()
    principal_arn = "arn:aws:iam::123456789012:user/test-user"

    policy_doc = FixPolicyDocument(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "NotResource": ["arn:aws:s3:::private-bucket/*"]}
            ],
        }
    )

    tree.add_element(principal_arn, [policy_doc])

    # Test access is denied to private bucket
    private_arn = ARN("arn:aws:s3:::private-bucket/secret.txt")
    public_arn = ARN("arn:aws:s3:::public-bucket/public.txt")
    ec2 = ARN("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")

    matching_principals = tree.find_matching_values(private_arn)
    assert principal_arn not in matching_principals

    matching_principals = tree.find_matching_values(public_arn)
    assert principal_arn in matching_principals

    matching_principals = tree.find_matching_values(ec2)
    assert len(matching_principals) == 0
