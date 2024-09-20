from cloudsplaining.scan.policy_document import PolicyDocument
from cloudsplaining.scan.statement_detail import StatementDetail

from fix_plugin_aws.resource.base import AwsResource
from fix_plugin_aws.resource.iam import AwsIamUser
from typing import Any, Dict, List

import re
from fix_plugin_aws.access_edges import (
    find_allowed_action,
    make_resoruce_regex,
    check_statement_match,
    check_principal_match,
    IamRequestContext,
    check_explicit_deny,
)

from fix_plugin_aws.access_edges_utils import PolicySource, PolicySourceKind


def test_find_allowed_action() -> None:
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::bucket/*"]},
            {"Effect": "Allow", "Action": ["s3:ListBuckets"], "Resource": ["*"]},
            {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["arn:aws:s3:::bucket/*"]},
        ],
    }

    allowed_actions = find_allowed_action(PolicyDocument(policy_document))

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
    identity_policies = [(PolicySource(kind=PolicySourceKind.Principal, arn=principal.arn), policy_document)]
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
    identity_policies = [(PolicySource(kind=PolicySourceKind.Principal, arn=principal.arn), policy_document)]

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
        (PolicySource(kind=PolicySourceKind.Resource, arn="arn:aws:s3:::example-bucket"), policy_document)
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
        (PolicySource(kind=PolicySourceKind.Resource, arn="arn:aws:s3:::example-bucket"), policy_document)
    ]

    resource = AwsResource(id="some-resource", arn="arn:aws:s3:::example-bucket/object.txt")
    action = "s3:GetObject"

    result = check_explicit_deny(request_context, resource, action, resource_based_policies)
    expected_conditions = [policy_json["Statement"][0]["Condition"]]
    assert result == expected_conditions
