import fnmatch
import logging
import re
from functools import lru_cache
from typing import Callable, Dict, List, Literal, Optional, Pattern, Set, Tuple, Union

import networkx
from attr import frozen
from cloudsplaining.scan.statement_detail import StatementDetail
from fix_plugin_aws.access_edges.arn_tree import PrincipalTree
from fix_plugin_aws.access_edges.types import (
    ActionWildcardPattern,
    ArnResourceValueKind,
    FixPolicyDocument,
    FixStatementDetail,
    ResourceWildcardPattern,
    WildcardKind,
)
from fix_plugin_aws.resource.base import AwsAccount, AwsResource, GraphBuilder
from fix_plugin_aws.resource.iam import AwsIamGroup, AwsIamPolicy, AwsIamRole, AwsIamUser
from networkx.algorithms.dag import is_directed_acyclic_graph
from policy_sentry.querying.actions import get_action_data, get_actions_for_service
from policy_sentry.querying.all import get_all_actions
from policy_sentry.querying.arns import get_matching_raw_arns, get_resource_type_name_with_raw_arn
from policy_sentry.shared.iam_data import get_service_prefix_data
from policy_sentry.util.arns import ARN, get_service_from_arn

from fixlib.baseresources import (
    AccessPermission,
    EdgeType,
    HasResourcePolicy,
    PermissionCondition,
    PermissionLevel,
    PermissionScope,
    PolicySource,
    PolicySourceKind,
    ResourceConstraint,
)
from fixlib.graph import EdgeKey
from fixlib.json import to_json, to_json_str
from fixlib.types import Json

log = logging.getLogger("fix.plugins.aws")


ALL_ACTIONS = get_all_actions()


@frozen(slots=True)
class ActionToCheck:
    raw: str
    raw_lower: str
    service: str
    action_name: str


@frozen(slots=True)
class IamRequestContext:
    principal: AwsResource
    identity_policies: Tuple[Tuple[PolicySource, FixPolicyDocument], ...]
    permission_boundaries: Tuple[FixPolicyDocument, ...]  # todo: use them too
    # all service control policies applicable to the principal,
    # starting from the root, then all org units, then the account
    service_control_policy_levels: Tuple[Tuple[FixPolicyDocument, ...], ...]

    def all_policies(
        self, resource_based_policies: Optional[Tuple[Tuple[PolicySource, FixPolicyDocument], ...]] = None
    ) -> List[FixPolicyDocument]:
        return (
            [p[1] for p in self.identity_policies]
            + list(self.permission_boundaries)
            + [p for group in self.service_control_policy_levels for p in group]
            + ([p[1] for p in (resource_based_policies or [])])
        )


IamAction = str


@lru_cache(maxsize=4096)
def find_allowed_action(policy_document: FixPolicyDocument, service_prefix: str) -> Set[IamAction]:
    allowed_actions: Set[IamAction] = set()
    for statement in policy_document.statements:
        if statement.effect_allow:
            allowed_actions.update(get_expanded_action(statement, service_prefix))

    return allowed_actions


def find_non_service_actions(resource_arn: ARN) -> Set[IamAction]:
    try:
        service_prefix = resource_arn.service_prefix
        if service_prefix == "iam":
            resource_type = resource_arn.resource_string
            resource = resource_type.split("/")[0]
            if resource == "role":
                return {"sts:AssumeRole"}
    except Exception as e:
        log.info(f"Error when trying to get non-service actions for ARN {resource_arn}: {e}")
    return set()


@lru_cache(maxsize=1024)
def get_actions_matching_raw_arn(raw_arn: str) -> set[str]:
    results: set[str] = set()
    resource_type_name = get_resource_type_name_with_raw_arn(raw_arn)
    if resource_type_name is None:
        return results

    service_prefix = get_service_from_arn(raw_arn)
    service_prefix_data = get_service_prefix_data(service_prefix)
    for action_name, action_data in service_prefix_data["privileges"].items():
        if resource_type_name.lower() in action_data["resource_types_lower_name"]:
            results.add(f"{service_prefix}:{action_name}")

    return results


def get_actions_matching_arn(arn: str) -> set[str]:
    """
    Given a user-supplied ARN, get a list of all actions that correspond to that ARN.

    Arguments:
        arn: A user-supplied arn
    Returns:
        List: A list of all actions that can match it.
    """
    results = set()
    try:
        raw_arns = get_matching_raw_arns(arn)
        for raw_arn in raw_arns:
            raw_arn_actions = get_actions_matching_raw_arn(raw_arn)
            results.update(raw_arn_actions)
    except Exception as e:
        log.debug(f"Error when trying to get actions for ARN {arn}: {e}")

    return results


def find_all_allowed_actions(
    all_involved_policies: List[FixPolicyDocument], resource_arn: ARN, resource_actions: set[IamAction]
) -> Set[IamAction]:

    if additinal_actions := find_non_service_actions(resource_arn):
        resource_actions.update(additinal_actions)

    service_prefix = ""
    try:
        service_prefix = resource_arn.service_prefix
    except Exception as e:
        log.debug(f"Error when trying to get service prefix from ARN {resource_arn}: {e}")
    policy_actions: Set[IamAction] = set()
    for p in all_involved_policies:
        policy_actions.update(find_allowed_action(p, service_prefix))
    return policy_actions.intersection(resource_actions)


@lru_cache(maxsize=1024)
def expand(action: str, service_prefix: str) -> list[str]:
    if action == "*":
        return get_actions_for_service(service_prefix=service_prefix)
    elif "*" in action:
        prefix = action.split(":", maxsplit=1)[0]
        if prefix != service_prefix:
            return []
        service_actions = get_actions_for_service(service_prefix=prefix)
        expanded = [
            expanded_action
            for expanded_action in service_actions
            if fnmatch.fnmatchcase(expanded_action.lower(), action.lower())
        ]

        if not expanded:
            return [action]

        return expanded
    return [action]


def determine_actions_to_expand(action_list: list[str], service_prefix: str) -> list[str]:
    new_action_list = []
    for action in action_list:
        if "*" in action:
            expanded_action = expand(action, service_prefix)
            new_action_list.extend(expanded_action)
        elif action.startswith(service_prefix):
            new_action_list.append(action)
    new_action_list.sort()
    return new_action_list


@lru_cache(maxsize=4096)
def statement_expanded_actions(statement: StatementDetail, service_prefix: str) -> List[str]:
    if statement.actions:
        expanded: list[str] = determine_actions_to_expand(statement.actions, service_prefix)
        return expanded
    elif statement.not_action:
        not_actions = statement.not_action_effective_actions or []
        return [na for na in not_actions if na.startswith(service_prefix)]
    else:
        log.warning("Statement has neither Actions nor NotActions")
        return []


@lru_cache(maxsize=1024)
def get_expanded_action(statement: StatementDetail, service_prefix: str) -> List[str]:
    expanded: List[str] = statement_expanded_actions(statement, service_prefix)
    return expanded


@lru_cache(maxsize=1024)
def make_resoruce_regex(aws_resorce_wildcard: str) -> Pattern[str]:
    # step 1: translate aws wildcard to python regex
    python_regex = aws_resorce_wildcard.replace("*", ".*").replace("?", ".")
    # step 2: compile the regex
    return re.compile(f"^{python_regex}$", re.IGNORECASE)


@lru_cache(maxsize=1024)
def _compile_action_pattern(wildcard_pattern: str) -> tuple[str, re.Pattern[str] | None]:
    """
    Compile and cache the action pattern components.
    Returns (service, action_pattern, compiled_regex)
    """
    wildcard_pattern = wildcard_pattern.lower()
    parts = wildcard_pattern.split(":", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid action pattern format: {wildcard_pattern}")

    _, action_pattern = parts

    # Convert AWS wildcard pattern to regex pattern
    if "*" in action_pattern:
        pattern = "^" + re.escape(action_pattern).replace("\\*", ".*") + "$"
        compiled = re.compile(pattern)
    else:
        compiled = None

    return action_pattern, compiled


def expand_action_wildcards_and_match(action: ActionToCheck, wildcard_pattern: ActionWildcardPattern) -> bool:

    if wildcard_pattern.kind == WildcardKind.any:
        return True

    if wildcard_pattern.kind == WildcardKind.fixed:
        return action.raw_lower == wildcard_pattern.pattern

    if action.service != wildcard_pattern.service:
        return False

    # Get cached pattern components
    try:
        pattern_action, compiled_regex = _compile_action_pattern(wildcard_pattern.pattern)
    except ValueError:
        return False

    # Handle exact action match
    if pattern_action == action.action_name:
        return True

    # Handle regex pattern match
    if compiled_regex:
        return bool(compiled_regex.match(action.action_name))

    return False


def match_pattern(resource_segment: str, wildcard_segment: str, wildcard_segment_kind: ArnResourceValueKind) -> bool:
    match wildcard_segment_kind:
        case ArnResourceValueKind.Any:
            return True
        case ArnResourceValueKind.Pattern:
            return fnmatch.fnmatch(resource_segment, wildcard_segment)
        case ArnResourceValueKind.Static:
            return resource_segment == wildcard_segment


def expand_arn_wildcards_and_match(identifier: ARN, wildcard_string: ResourceWildcardPattern) -> bool:

    # if wildard is *, we can shortcut here
    if wildcard_string.partition is None:
        return True

    # go through the ARN segments and match them
    if not wildcard_string.partition == identifier.partition:
        return False

    if not wildcard_string.service == identifier.service_prefix:
        return False

    if not match_pattern(identifier.region, wildcard_string.region, wildcard_string.region_value_kind):
        return False

    if not match_pattern(identifier.account, wildcard_string.account, wildcard_string.account_value_kind):
        return False

    if not match_pattern(identifier.resource_string, wildcard_string.resource, wildcard_string.resource_value_kind):
        return False

    return True


@lru_cache(maxsize=4096)
def check_statement_match(
    statement: FixStatementDetail,
    effect: Optional[Literal["Allow", "Deny"]],
    action: ActionToCheck,
    principal: Optional[AwsResource],
    source_arn: Optional[str] = None,
) -> Union[None, Callable[[ARN], Optional[List[ResourceConstraint]]]]:
    """
    check if a statement matches the given effect, action, and principal,
    returns None if there is no match no matter what the resource is,
    or a callable that can be used to check if the resource matches
    """
    # step 1: check the principal if provided
    if principal:
        principal_match = False
        if policy_principal := statement.json.get("Principal", None):
            if policy_principal == "*":
                principal_match = True
            elif "AWS" in policy_principal:
                aws_principal_list = policy_principal["AWS"]
                if isinstance(aws_principal_list, str):
                    aws_principal_list = [aws_principal_list]
                if check_principal_match(principal, aws_principal_list):
                    principal_match = True
            else:
                # aws service principal is specified, we do not handle such cases yet
                pass
        elif policy_not_principal := statement.json.get("NotPrincipal", None):
            # * is not allowed in NotPrincipal, so we can skip the check
            principal_match = True
            if "AWS" in policy_not_principal:
                aws_principal_list = policy_not_principal["AWS"]
                assert isinstance(aws_principal_list, list)
                if check_principal_match(principal, aws_principal_list):
                    principal_match = False
            else:
                # aws service principal is specified, we do not handle such cases yet
                pass
        else:
            principal_match = True

        if not principal_match:
            # principal does not match, we can shortcut here
            return None

    # step 2: check if the effect matches
    if effect:
        if statement.effect != effect:
            # wrong effect, skip this statement
            return None

    # step 3: check if the action matches
    action_match = False
    if statement.actions:
        # shortcuts for known AWS managed policies
        if source_arn == "arn:aws:iam::aws:policy/ReadOnlyAccess":
            action_level = get_action_level(action.raw)
            if action_level in [PermissionLevel.read or PermissionLevel.list]:
                action_match = True
            else:
                action_match = False
        else:
            for a in statement.actions_patterns:
                if expand_action_wildcards_and_match(action=action, wildcard_pattern=a):
                    action_match = True
                    break
    else:
        # not_action
        action_match = True
        for na in statement.not_action_patterns:
            if expand_action_wildcards_and_match(action=action, wildcard_pattern=na):
                action_match = False
                break
    if not action_match:
        # action does not match, skip this statement
        return None

    def check_resource_match(arn: ARN) -> Optional[List[ResourceConstraint]]:
        # step 4: check if the resource matches
        matched_resource_constraints: List[ResourceConstraint] = []
        resource_matches = False
        if len(statement.resource_patterns) > 0:
            for resource_constraint in statement.resource_patterns:
                if expand_arn_wildcards_and_match(identifier=arn, wildcard_string=resource_constraint):
                    matched_resource_constraints.append(resource_constraint.raw_value)
                    resource_matches = True
                    break
        elif len(statement.not_resource_patterns) > 0:
            resource_matches = True
            for not_resource_constraint in statement.not_resource_patterns:
                if expand_arn_wildcards_and_match(identifier=arn, wildcard_string=not_resource_constraint):
                    resource_matches = False
                    break
                matched_resource_constraints.append("not " + not_resource_constraint.raw_value)
        else:
            # no Resource/NotResource specified, consider allowed
            resource_matches = True
        if not resource_matches:
            # resource does not match, skip this statement
            return None

        # step 5: (we're not doing this yet) check if the condition matches
        # here we just return the statement and condition checking is the responsibility of the caller
        return matched_resource_constraints

    return check_resource_match


def check_principal_match(principal: AwsResource, aws_principal_list: List[str]) -> bool:
    assert principal.arn
    for aws_principal in aws_principal_list:
        if aws_principal == "*":
            return True

        if principal.arn == aws_principal:
            return True

        if principal.id == aws_principal:
            return True

        principal_arn = ARN(principal.arn)
        if principal_arn.account == aws_principal:
            return True

    return False


@lru_cache(maxsize=4096)
def collect_matching_statements(
    *,
    policy: FixPolicyDocument,
    effect: Optional[Literal["Allow", "Deny"]],
    action: ActionToCheck,
    principal: Optional[AwsResource],
    source_arn: Optional[str] = None,
) -> Callable[[ARN], List[Tuple[FixStatementDetail, List[ResourceConstraint]]]]:
    """
    resoruce based policies contain principal field and need to be handled differently
    """
    matching_fns: List[Tuple[FixStatementDetail, Callable[[ARN], Optional[List[ResourceConstraint]]]]] = []

    for statement in policy.fix_statements:

        match_fn = check_statement_match(
            statement, effect=effect, action=action, principal=principal, source_arn=source_arn
        )
        if not match_fn:
            continue

        matching_fns.append((statement, match_fn))

    def collect_matching_statements_closure(resource: ARN) -> List[Tuple[FixStatementDetail, List[ResourceConstraint]]]:
        results: List[Tuple[FixStatementDetail, List[ResourceConstraint]]] = []
        for statement, match_fn in matching_fns:
            if constraints := match_fn(resource):
                results.append((statement, constraints))

        return results

    return collect_matching_statements_closure


@lru_cache(maxsize=4096)
def check_explicit_deny(
    request_context: IamRequestContext,
    action: ActionToCheck,
    resource_based_policies: Tuple[Tuple[PolicySource, FixPolicyDocument], ...],
) -> Callable[[ARN], Union[Literal["Denied", "NextStep"], List[Json]]]:

    matching_fns = []

    # we should skip service control policies for service linked roles
    if not is_service_linked_role(request_context.principal):
        for scp_level in request_context.service_control_policy_levels:
            for policy in scp_level:
                matching_fn = collect_matching_statements(
                    policy=policy, effect="Deny", action=action, principal=request_context.principal
                )
                matching_fns.append(matching_fn)

    # check permission boundaries
    for policy in request_context.permission_boundaries:
        matching_fn = collect_matching_statements(
            policy=policy, effect="Deny", action=action, principal=request_context.principal
        )
        matching_fns.append(matching_fn)

    # check the rest of the policies
    for _, policy in request_context.identity_policies:
        matching_fn = collect_matching_statements(
            policy=policy, effect="Deny", action=action, principal=request_context.principal
        )
        matching_fns.append(matching_fn)

    for _, policy in resource_based_policies:
        matching_fn = collect_matching_statements(
            policy=policy, effect="Deny", action=action, principal=request_context.principal
        )
        matching_fns.append(matching_fn)

    def check_explicit_deny_closure(arn: ARN) -> Union[Literal["Denied", "NextStep"], List[Json]]:

        denied_when_any_is_true: List[Json] = []

        for matching_fn in matching_fns:
            for statement, _ in matching_fn(arn):
                if statement.condition:
                    denied_when_any_is_true.append(statement.condition)
                else:
                    return "Denied"

        if denied_when_any_is_true:
            return denied_when_any_is_true

        return "NextStep"

    return check_explicit_deny_closure


def scp_allowed(request_context: IamRequestContext, action: ActionToCheck, resource: ARN) -> bool:

    # traverse the SCPs:  root -> OU -> account levels
    for scp_level_policies in request_context.service_control_policy_levels:
        level_allows = False
        for policy in scp_level_policies:
            matching_fn = collect_matching_statements(policy=policy, effect="Allow", action=action, principal=None)
            statements = matching_fn(resource)
            if statements:
                # 'Allow' statements in SCP can't have conditions, we do not check them
                level_allows = True
                break

        if not level_allows:
            return False

    return True


@frozen
class FinalAllow:
    scopes: List[PermissionScope]


@frozen
class Continue:
    scopes: List[PermissionScope]


@frozen
class Deny:
    pass


ResourceBasedPolicyResult = Union[FinalAllow, Continue, Deny]


# check if the resource based policies allow the action
# as a shortcut we return the first allow statement we find, or a first seen condition.
def check_resource_based_policies(
    principal: AwsResource,
    action: ActionToCheck,
    resource: ARN,
    resource_based_policies: Tuple[Tuple[PolicySource, FixPolicyDocument], ...],
) -> ResourceBasedPolicyResult:

    scopes: List[PermissionScope] = []

    arn = resource
    explicit_allow_required = False
    if arn.service_prefix == "iam" or arn.service_prefix == "kms":
        explicit_allow_required = True

    for source, policy in resource_based_policies:

        matching_fn = collect_matching_statements(
            policy=policy,
            effect="Allow",
            action=action,
            principal=principal,
        )
        matching_statements = matching_fn(arn)
        if len(matching_statements) == 0:
            continue

        for statement, constraints in matching_statements:
            if statement.condition:
                scopes.append(
                    PermissionScope(
                        source=source,
                        constraints=tuple(constraints),
                        conditions=PermissionCondition(allow=(to_json_str(statement.condition),)),
                    )
                )
            else:
                scopes.append(
                    PermissionScope(
                        source=source,
                        constraints=tuple(constraints),
                    )
                )

    # if we found any allow statements, let's check the principal and act accordingly
    if scopes:
        if isinstance(principal, AwsIamUser):
            # in case of IAM users, identity_based_policies and permission boundaries are not relevant
            # and we can return the result immediately
            return FinalAllow(scopes)

    # if we have KMS or IAM service, we want an explicit allow
    if explicit_allow_required:
        if not scopes:
            return Deny()

    # in case of other IAM principals, allow on resource based policy is not enough and
    # we need to check the permission boundaries
    return Continue(scopes)


@lru_cache(maxsize=4096)
def check_identity_based_policies(
    request_context: IamRequestContext, action: ActionToCheck
) -> Callable[[ARN], List[PermissionScope]]:

    matching_fns: List[
        Tuple[PolicySource, Callable[[ARN], List[Tuple[FixStatementDetail, List[ResourceConstraint]]]]]
    ] = []

    for source, policy in request_context.identity_policies:
        matching_fn = collect_matching_statements(
            policy=policy, effect="Allow", action=action, principal=None, source_arn=source.uri
        )
        matching_fns.append((source, matching_fn))

    def check_identity_policies_closure(resource: ARN) -> List[PermissionScope]:
        scopes: List[PermissionScope] = []
        for source, matching_fn in matching_fns:
            for statement, resource_constraints in matching_fn(resource):
                conditions = None
                if statement.condition:
                    conditions = PermissionCondition(allow=(to_json_str(statement.condition),))

                scopes.append(PermissionScope(source, tuple(resource_constraints), conditions=conditions))

        return scopes

    return check_identity_policies_closure


@lru_cache(maxsize=4096)
def check_permission_boundaries(
    request_context: IamRequestContext, action: ActionToCheck
) -> Callable[[ARN], Union[Literal["Denied", "NextStep"], List[Json]]]:

    matching_fns = []

    # ignore policy sources and resource constraints because permission boundaries
    # can never allow access to a resource, only restrict it
    for policy in request_context.permission_boundaries:
        matching_fn = collect_matching_statements(policy=policy, effect="Allow", action=action, principal=None)
        matching_fns.append(matching_fn)

    def check_permission_boundaries_closure(resource: ARN) -> Union[Literal["Denied", "NextStep"], List[Json]]:
        conditions: List[Json] = []
        for matching_fn in matching_fns:
            for statement, _ in matching_fn(resource):
                if statement.condition:
                    assert isinstance(statement.condition, dict)
                    conditions.append(statement.condition)
                else:  # if there is an allow statement without a condition, the action is allowed
                    return "NextStep"

        if len(conditions) > 0:
            return conditions

        # no matching permission boundaries that allow access
        return "Denied"

    return check_permission_boundaries_closure


def is_service_linked_role(principal: AwsResource) -> bool:
    assert principal.arn
    if ":role/" in principal.arn:
        arn = ARN(principal.arn)
        role_name = arn.resource_path
        return role_name.startswith("AWSServiceRoleFor")

    return False


action_level_overrides = {
    "sts:AssumeRole": PermissionLevel.can_become,
}


def get_action_level(action: str) -> PermissionLevel:
    if override := action_level_overrides.get(action):
        return override

    service, action_name = action.split(":")
    level = ""
    action_data = get_action_data(service, action_name)
    if not action_data:
        return PermissionLevel.unknown
    if len(action_data[service]) > 0:
        for info in action_data[service]:
            if action == info["action"]:
                level = info["access_level"]
                break
    if level == "List":
        return PermissionLevel.list
    elif level == "Read":
        return PermissionLevel.read
    elif level == "Tagging":
        return PermissionLevel.tagging
    elif level == "Write":
        return PermissionLevel.write
    elif level == "Permissions management":
        return PermissionLevel.permission
    else:
        return PermissionLevel.unknown


# logic according to https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
def check_policies(
    request_context: IamRequestContext,
    resource: ARN,
    action: ActionToCheck,
    resource_based_policies: Tuple[Tuple[PolicySource, FixPolicyDocument], ...],
) -> Optional[AccessPermission]:

    # when any of the conditions evaluate to true, the action is explicitly denied
    # comes from any explicit deny statements in all policies
    deny_conditions: List[Json] = []

    # when any of the conditions evaluate to false, the action is implicitly denied
    # comes from the permission boundaries
    restricting_conditions: List[Json] = []

    # when any of the scopes evaluate to true, the action is allowed
    # comes from the resource based policies and identity based policies
    allowed_scopes: List[PermissionScope] = []

    # 1. check for explicit deny. If denied, we can abort immediately
    result = check_explicit_deny(request_context, action, resource_based_policies)(resource)
    if result == "Denied":
        return None
    elif result == "NextStep":
        pass
    else:
        for c in result:
            # satisfying any of the conditions above will deny the action
            deny_conditions.append(c)

    # 2. check for organization SCPs
    if len(request_context.service_control_policy_levels) > 0 and not is_service_linked_role(request_context.principal):
        org_scp_allowed = scp_allowed(request_context, action, resource)
        if not org_scp_allowed:
            return None

    # 3. check resource based policies
    if len(resource_based_policies) > 0:
        resource_result = check_resource_based_policies(
            request_context.principal, action, resource, resource_based_policies
        )
        if isinstance(resource_result, FinalAllow):
            scopes = resource_result.scopes
            final_resource_scopes: Set[PermissionScope] = set()
            for scope in scopes:
                final_resource_scopes.add(scope.with_deny_conditions(deny_conditions))

            return AccessPermission(
                action=action.raw, level=get_action_level(action.raw), scopes=tuple(final_resource_scopes)
            )
        if isinstance(resource_result, Continue):
            scopes = resource_result.scopes
            allowed_scopes.extend(scopes)

        if isinstance(resource_result, Deny):
            return None

    # 4. to make it a bit simpler, we check the permission boundaries before checking identity based policies
    if len(request_context.permission_boundaries) > 0:
        permission_boundary_result = check_permission_boundaries(request_context, action)(resource)
        if permission_boundary_result == "Denied":
            return None
        elif permission_boundary_result == "NextStep":
            pass
        else:
            restricting_conditions.extend(permission_boundary_result)

    # 5. check identity based policies
    if len(request_context.identity_policies) == 0:
        if len(allowed_scopes) == 0:
            # resource policy did no allow any actions and we have zero identity based policies -> implicit deny
            return None
        # otherwise continue with the resource based policies
    else:
        identity_based_allowed = check_identity_based_policies(request_context, action)(resource)
        if not identity_based_allowed:
            return None
        allowed_scopes.extend(identity_based_allowed)

    # 6. check for session policies
    # we don't collect session principals and session policies, so this step is skipped

    # 7. if we reached here, the action is allowed
    level = get_action_level(action.raw)

    final_scopes: Set[PermissionScope] = set()
    for scope in allowed_scopes:
        if deny_conditions:
            scope = scope.with_deny_conditions(deny_conditions)
        final_scopes.add(scope)

    # if there is a scope with no conditions, we can ignore everything else
    for scope in final_scopes:
        if scope.has_no_condititons():
            final_scopes = {scope}
            break

    log.debug(
        f"Found access permission, {action} is allowed for {resource} by {request_context.principal}, level: {level}. Scopes: {len(final_scopes)}"
    )

    # return the result
    return AccessPermission(
        action=action.raw,
        level=level,
        scopes=tuple(final_scopes),
    )


# logic according to https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
@lru_cache(maxsize=4096)
def check_non_resource_policies(
    request_context: IamRequestContext,
    action: ActionToCheck,
) -> Callable[[ARN], Optional[AccessPermission]]:

    # step 1: calculate and cache the expensive function calls
    explicit_deny_fn = check_explicit_deny(request_context, action, ())
    permission_boundary_fn = None
    if len(request_context.permission_boundaries) > 0:
        permission_boundary_fn = check_permission_boundaries(request_context, action)
    identity_based_fn = check_identity_based_policies(request_context, action)

    # step 2: create the closure
    def check_non_resource_policies_closure(resource: ARN) -> Optional[AccessPermission]:

        # shortcut: check if any identity based policies are present
        if len(request_context.identity_policies) == 0:
            return None

        # when any of the conditions evaluate to true, the action is explicitly denied
        # comes from any explicit deny statements in all policies
        deny_conditions: List[Json] = []

        # when any of the conditions evaluate to false, the action is implicitly denied
        # comes from the permission boundaries
        restricting_conditions: List[Json] = []

        # when any of the scopes evaluate to true, the action is allowed
        # comes from the resource based policies and identity based policies
        allowed_scopes: List[PermissionScope] = []

        # 1. check for explicit deny. If denied, we can abort immediately
        result = explicit_deny_fn(resource)
        if result == "Denied":
            return None
        elif result == "NextStep":
            pass
        else:
            for c in result:
                # satisfying any of the conditions above will deny the action
                deny_conditions.append(c)

        # 2. check for organization SCPs # todo: move it outside the loop
        if len(request_context.service_control_policy_levels) > 0 and not is_service_linked_role(
            request_context.principal
        ):
            org_scp_allowed = scp_allowed(request_context, action, resource)
            if not org_scp_allowed:
                return None

        # 3. skip resource based policies because the resource has none

        # 4. to make it a bit simpler, we check the permission boundaries before checking identity based policies
        if permission_boundary_fn:
            permission_boundary_result = permission_boundary_fn(resource)
            if permission_boundary_result == "Denied":
                return None
            elif permission_boundary_result == "NextStep":
                pass
            else:
                restricting_conditions.extend(permission_boundary_result)

        # 5. check identity based policies
        identity_based_allowed = identity_based_fn(resource)
        if not identity_based_allowed:
            return None
        allowed_scopes.extend(identity_based_allowed)

        # 6. check for session policies
        # we don't collect session principals and session policies, so this step is skipped

        # 7. if we reached here, the action is allowed
        level = get_action_level(action.raw)

        final_scopes: Set[PermissionScope] = set()
        for scope in allowed_scopes:
            if deny_conditions:
                scope = scope.with_deny_conditions(deny_conditions)
            final_scopes.add(scope)

        # if there is a scope with no conditions, we can ignore everything else
        for scope in final_scopes:
            if scope.has_no_condititons():
                final_scopes = {scope}
                break

        log.debug(
            f"Found access permission, {action} is allowed for {resource} by {request_context.principal}, level: {level}. Scopes: {len(final_scopes)}"
        )

        # return the result
        return AccessPermission(
            action=action.raw,
            level=level,
            scopes=tuple(final_scopes),
        )

    return check_non_resource_policies_closure


def compute_permissions(
    resource: ARN,
    iam_context: IamRequestContext,
    resource_based_policies: Tuple[Tuple[PolicySource, FixPolicyDocument], ...],
    resource_actions: set[IamAction],
) -> List[AccessPermission]:

    # step 1: find the relevant action to check
    relevant_actions = find_all_allowed_actions(
        iam_context.all_policies(resource_based_policies),
        resource,
        resource_actions,
    )

    all_permissions: List[AccessPermission] = []

    # step 2: for every action, check if it is allowed
    for action in relevant_actions:
        try:
            service, action_name = action.split(":", 1)
        except ValueError:
            log.error(f"Invalid action: {action}")
            continue

        action_to_check = ActionToCheck(
            service=service.lower(), action_name=action_name.lower(), raw_lower=action.lower(), raw=action
        )

        if resource_based_policies:
            if p := check_policies(iam_context, resource, action_to_check, resource_based_policies):
                all_permissions.append(p)
        else:
            if p := check_non_resource_policies(iam_context, action_to_check)(resource):
                all_permissions.append(p)

    return all_permissions


class AccessEdgeCreator:

    def __init__(self, builder: GraphBuilder):
        self.builder = builder
        self.principals: List[IamRequestContext] = []
        self._init_principals()
        self.actions_for_resource: Dict[str, set[IamAction]] = self._compute_actions_for_resource()
        self.principal_tree = self._build_principal_tree()
        self.arn_to_context = {context.principal.arn: context for context in self.principals}

    def _init_principals(self) -> None:

        account_id = self.builder.account.id
        service_control_policy_levels: tuple[tuple[FixPolicyDocument, ...], ...] = ()
        account = next(self.builder.nodes(clazz=AwsAccount, filter=lambda a: a.id == account_id), None)
        if account and account._service_control_policies:
            service_control_policy_levels = tuple(
                [tuple([FixPolicyDocument(json) for json in level]) for level in account._service_control_policies]
            )

        for node in self.builder.nodes(clazz=AwsResource):
            if isinstance(node, AwsIamUser):

                identity_based_policies = tuple(self._get_user_based_policies(node))

                permission_boundaries: List[FixPolicyDocument] = []
                if (pb := node.user_permissions_boundary) and (pb_arn := pb.permissions_boundary_arn):
                    for pb_policy in self.builder.nodes(clazz=AwsIamPolicy, filter=lambda p: p.arn == pb_arn):
                        if pdj := pb_policy.policy_document_json():
                            pd = FixPolicyDocument(pdj)
                            permission_boundaries.append(pd)

                request_context = IamRequestContext(
                    principal=node,
                    identity_policies=identity_based_policies,
                    permission_boundaries=tuple(permission_boundaries),
                    service_control_policy_levels=service_control_policy_levels,
                )

                self.principals.append(request_context)

            if isinstance(node, AwsIamGroup):
                identity_based_policies = tuple(self._get_group_based_policies(node))

                request_context = IamRequestContext(
                    principal=node,
                    identity_policies=identity_based_policies,
                    permission_boundaries=(),  # permission boundaries are not applicable to groups
                    service_control_policy_levels=service_control_policy_levels,
                )

                self.principals.append(request_context)

            if isinstance(node, AwsIamRole):
                identity_based_policies = tuple(self._get_role_based_policies(node))
                # todo: colect these resources
                permission_boundaries = []
                if (pb := node.role_permissions_boundary) and (pb_arn := pb.permissions_boundary_arn):
                    for pb_policy in self.builder.nodes(clazz=AwsIamPolicy, filter=lambda p: p.arn == pb_arn):
                        if pdj := pb_policy.policy_document_json():
                            permission_boundaries.append(FixPolicyDocument(pdj))

                request_context = IamRequestContext(
                    principal=node,
                    identity_policies=identity_based_policies,
                    permission_boundaries=tuple(permission_boundaries),
                    service_control_policy_levels=service_control_policy_levels,
                )

                self.principals.append(request_context)

    def _build_principal_tree(self) -> PrincipalTree:

        tree = PrincipalTree()

        for context in self.principals:
            principal_arn = context.principal.arn
            if not principal_arn:
                continue

            principal_policies = context.all_policies()
            tree.add_principal(principal_arn, principal_policies)

        return tree

    def _compute_actions_for_resource(self) -> Dict[str, set[IamAction]]:

        actions_for_resource: Dict[str, set[IamAction]] = {}

        for node in self.builder.nodes(clazz=AwsResource, filter=lambda r: r.arn is not None):
            if not node.arn:
                continue

            actions_for_resource[node.arn] = get_actions_matching_arn(node.arn)

        return actions_for_resource

    def _get_user_based_policies(self, principal: AwsIamUser) -> List[Tuple[PolicySource, FixPolicyDocument]]:
        inline_policies = [
            (
                PolicySource(kind=PolicySourceKind.principal, uri=principal.arn or ""),
                FixPolicyDocument(policy.policy_document),
            )
            for policy in principal.user_policies
            if policy.policy_document
        ]
        attached_policies = []
        group_policies = []
        for _, to_node in self.builder.graph.edges(principal):
            if isinstance(to_node, AwsIamPolicy):
                if doc := to_node.policy_document_json():
                    attached_policies.append(
                        (
                            PolicySource(kind=PolicySourceKind.principal, uri=to_node.arn or ""),
                            FixPolicyDocument(doc),
                        )
                    )

            if isinstance(to_node, AwsIamGroup):
                group = to_node
                # inline group policies
                for policy in group.group_policies:
                    if policy.policy_document:
                        group_policies.append(
                            (
                                PolicySource(kind=PolicySourceKind.group, uri=group.arn or ""),
                                FixPolicyDocument(policy.policy_document),
                            )
                        )
                # attached group policies
                for _, group_successor in self.builder.graph.edges(group):
                    if isinstance(group_successor, AwsIamPolicy):
                        if doc := group_successor.policy_document_json():
                            group_policies.append(
                                (
                                    PolicySource(kind=PolicySourceKind.group, uri=group_successor.arn or ""),
                                    FixPolicyDocument(doc),
                                )
                            )

        return inline_policies + attached_policies + group_policies

    def _get_group_based_policies(self, principal: AwsIamGroup) -> List[Tuple[PolicySource, FixPolicyDocument]]:
        # not really a principal, but could be useful to have access edges for groups
        inline_policies = [
            (
                PolicySource(kind=PolicySourceKind.group, uri=principal.arn or ""),
                FixPolicyDocument(policy.policy_document),
            )
            for policy in principal.group_policies
            if policy.policy_document
        ]

        attached_policies = []
        for _, to_node in self.builder.graph.edges(principal):
            if isinstance(to_node, AwsIamPolicy):
                if doc := to_node.policy_document_json():
                    attached_policies.append(
                        (
                            PolicySource(kind=PolicySourceKind.group, uri=to_node.arn or ""),
                            FixPolicyDocument(doc),
                        )
                    )

        return inline_policies + attached_policies

    def _get_role_based_policies(self, principal: AwsIamRole) -> List[Tuple[PolicySource, FixPolicyDocument]]:
        inline_policies = []
        for doc in [p.policy_document for p in principal.role_policies if p.policy_document]:
            inline_policies.append(
                (
                    PolicySource(kind=PolicySourceKind.principal, uri=principal.arn or ""),
                    FixPolicyDocument(doc),
                )
            )

        attached_policies = []
        for _, to_node in self.builder.graph.edges(principal):
            if isinstance(to_node, AwsIamPolicy):
                if policy_doc := to_node.policy_document_json():
                    attached_policies.append(
                        (
                            PolicySource(kind=PolicySourceKind.principal, uri=to_node.arn or ""),
                            FixPolicyDocument(policy_doc),
                        )
                    )

        return inline_policies + attached_policies

    def add_access_edges(self) -> None:

        for node in self.builder.nodes(clazz=AwsResource, filter=lambda r: r.arn is not None):
            assert node.arn
            resource_arn = ARN(node.arn)

            if not isinstance(node, HasResourcePolicy):
                # here we have identity-based policies only and can prune some principals
                for arn in self.principal_tree.list_principals(resource_arn):
                    context = self.arn_to_context.get(arn)
                    if not context:
                        raise ValueError(f"Principal {arn} not found in the context")

                    permissions = compute_permissions(
                        resource_arn, context, tuple(), self.actions_for_resource.get(node.arn, set())
                    )

                    if not permissions:
                        continue

                    access: Dict[PermissionLevel, bool] = {}
                    for permission in permissions:
                        access[permission.level] = True
                    reported = to_json({"permissions": permissions} | access, strip_nulls=True)
                    self.builder.add_edge(
                        from_node=context.principal, edge_type=EdgeType.iam, reported=reported, node=node
                    )

            else:
                # here we have resource-based policies and must check all principals.
                for context in self.principals:
                    if context.principal.arn == node.arn:
                        # small graph cycles avoidance optimization
                        continue

                    resource_policies: List[Tuple[PolicySource, FixPolicyDocument]] = []
                    for source, json_policy in node.resource_policy(self.builder):
                        resource_policies.append((source, FixPolicyDocument(json_policy)))

                    permissions = compute_permissions(
                        resource_arn, context, tuple(resource_policies), self.actions_for_resource.get(node.arn, set())
                    )

                    if not permissions:
                        continue

                    access = {}
                    for permission in permissions:
                        access[permission.level] = True
                    reported = to_json({"permissions": permissions} | access, strip_nulls=True)
                    self.builder.add_edge(
                        from_node=context.principal, edge_type=EdgeType.iam, reported=reported, node=node
                    )

        all_principal_arns = {p.principal.arn for p in self.principals if p.principal.arn}

        # check that there are no cycles in the IAM edges besides the principal -> principal edges
        iam_edges_no_double_principal = []
        for edge in self.builder.graph.edges(keys=True):
            if len(edge) != 3:
                continue

            # skip non-iam edges
            key: EdgeKey = edge[2]
            if key.edge_type != EdgeType.iam:
                continue

            # skip the principal -> principal edges
            if key.src.arn in all_principal_arns and key.dst.arn in all_principal_arns:
                continue

            iam_edges_no_double_principal.append(edge)

        # check for loops:
        subgraph = self.builder.graph.edge_subgraph(iam_edges_no_double_principal)
        if not is_directed_acyclic_graph(subgraph):
            cycle = [edge[2] for edge in networkx.algorithms.cycles.find_cycle(subgraph)]
            desc = ", ".join(f"{key.edge_type}: {key.src.kdname}-->{key.dst.kdname}" for key in cycle)
            log.error(f"IAM graph of account {self.builder.account.arn} is not acyclic! Cycle {desc}")
