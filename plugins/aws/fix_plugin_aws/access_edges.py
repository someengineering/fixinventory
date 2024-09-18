from enum import Enum
from functools import lru_cache
from attr import define, evolve, frozen
from fix_plugin_aws.resource.base import AwsResource, GraphBuilder

from typing import List, Literal, Set, Optional, Tuple, Union, Pattern

from fix_plugin_aws.access_edges_utils import (
    PolicySource,
    PermissionScope,
    AccessPermission,
    PolicySourceKind,
    HasResourcePolicy,
)
from fix_plugin_aws.resource.iam import AwsIamGroup, AwsIamPolicy, AwsIamUser
from fixlib.baseresources import EdgeType
from fixlib.types import Json

from cloudsplaining.scan.policy_document import PolicyDocument
from cloudsplaining.scan.statement_detail import StatementDetail
from policy_sentry.querying.actions import get_action_data
from policy_sentry.querying.all import get_all_actions
from policy_sentry.util.arns import ARN
import re
import logging


log = logging.getLogger(__name__)

ALL_ACTIONS = get_all_actions()

ResourceContstaint = str


@define
class IamRequestContext:
    principal: AwsResource
    identity_policies: List[Tuple[PolicySource, PolicyDocument]]
    permission_boundaries: List[Tuple[PolicySource, PolicyDocument]]  # todo: use them too
    service_control_policies: List[Tuple[PolicySource, PolicyDocument]]  # todo: use them too
    # technically we should also add a list of session policies here, but they don't exist in the collector context

    def all_policies(
        self, resource_based_policies: Optional[List[Tuple[PolicySource, PolicyDocument]]] = None
    ) -> List[Tuple[PolicySource, PolicyDocument]]:
        return (
            self.identity_policies
            + self.permission_boundaries
            + self.service_control_policies
            + (resource_based_policies or [])
        )


def find_policy_doc(policy: AwsIamPolicy) -> Optional[Json]:
    if not policy.policy_document:
        return None

    return policy.policy_document.document


IamAction = str


@lru_cache(maxsize=1024)
def find_allowed_action(policy_document: PolicyDocument) -> Set[IamAction]:
    allowed_actions: Set[IamAction] = set()
    for statement in policy_document.statements:
        if statement.effect_allow:
            allowed_actions.update(get_expanded_action(statement))

    return allowed_actions


def find_all_allowed_actions(all_involved_policies: List[PolicyDocument]) -> Set[IamAction]:
    allowed_actions: Set[IamAction] = set()
    for p in all_involved_policies:
        allowed_actions.update(find_allowed_action(p))
    return allowed_actions


@lru_cache(maxsize=1024)
def get_expanded_action(statement: StatementDetail) -> Set[str]:
    actions = set()
    expanded: List[str] = statement.expanded_actions or []
    for action in expanded:
        actions.add(action)

    return actions


@lru_cache(maxsize=1024)
def make_resoruce_regex(aws_resorce_wildcard: str) -> Pattern[str]:
    # step 1: translate aws wildcard to python regex
    python_regex = aws_resorce_wildcard.replace("*", ".*").replace("?", ".")
    # step 2: compile the regex
    return re.compile(f"^{python_regex}$", re.IGNORECASE)


def expand_wildcards_and_match(*, identifier: str, wildcard_string: str) -> bool:
    """
    helper function to expand wildcards and match the identifier

    use case:
        match the resource constraint (wildcard) with the ARN
        match the wildcard action with the specific action
    """
    pattern = make_resoruce_regex(wildcard_string)
    return pattern.match(identifier) is not None


@frozen
class Allowed:
    resource_constraint: str
    condition: Optional[Json] = None


@frozen
class Denied:
    pass


AccessResult = Union[Allowed, Denied]


def check_statement_match(
    statement: StatementDetail,
    effect: Optional[Literal["Allow", "Deny"]],
    action: str,
    resource: AwsResource,
    principal: Optional[AwsResource],
) -> Tuple[bool, Optional[ResourceContstaint]]:
    """
    check if a statement matches the given effect, action, resource and principal, returns boolean if there is a match and optional resource constraint (if there were any)
    """
    if resource.arn is None:
        raise ValueError("Resource ARN is missing, go and fix the filtering logic")

    # step 1: check the principal if provided
    if principal:
        principal_match = False
        if policy_principal := statement.json.get("Principal", None):
            if policy_principal == "*":
                principal_match = True
            elif "AWS" in policy_principal:
                aws_principal_list = policy_principal["AWS"]
                assert isinstance(aws_principal_list, list)
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
            return False, None

    # step 2: check if the effect matches
    if effect:
        if statement.effect != effect:
            # wrong effect, skip this statement
            return False, None

    # step 3: check if the action matches
    action_match = False
    if statement.actions:
        for a in statement.actions:
            if expand_wildcards_and_match(identifier=action, wildcard_string=a):
                action_match = True
                break
    else:
        # not_action
        action_match = True
        for na in statement.not_action:
            if expand_wildcards_and_match(identifier=action, wildcard_string=na):
                action_match = False
                break
    if not action_match:
        # action does not match, skip this statement
        return False, None

    # step 4: check if the resource matches
    matched_resource_constraint: Optional[ResourceContstaint] = None
    resource_matches = False
    if len(statement.resources) > 0:
        for resource_constraint in statement.resources:
            if expand_wildcards_and_match(identifier=resource.arn, wildcard_string=resource_constraint):
                matched_resource_constraint = resource_constraint
                resource_matches = True
                break
    elif len(statement.not_resource) > 0:
        resource_matches = True
        for not_resource_constraint in statement.not_resource:
            if expand_wildcards_and_match(identifier=resource.arn, wildcard_string=not_resource_constraint):
                resource_matches = False
                break
            matched_resource_constraint = "not " + not_resource_constraint
    else:
        # no Resource/NotResource specified, consider allowed
        resource_matches = True
    if not resource_matches:
        # resource does not match, skip this statement
        return False, None

    # step 5: (we're not doing this yet) check if the condition matches
    # here we just return the statement and condition checking is the responsibility of the caller
    return (True, matched_resource_constraint)


def policy_matching_statement_exists(
    policy: PolicyDocument, effect: Literal["Allow", "Deny"], action: str, resource: AwsResource
) -> Optional[Tuple[StatementDetail, Optional[ResourceContstaint]]]:
    """
    this function is used for policies that do not have principal field, e.g. all non-resource based policies
    """
    if resource.arn is None:
        raise ValueError("Resource ARN is missing, go and fix the filtering logic")

    for statement in policy.statements:
        matches, maybe_resource_constraint = check_statement_match(statement, effect, action, resource, principal=None)
        if matches:
            return (statement, maybe_resource_constraint)

    return None


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


def collect_matching_resource_statements(
    principal: AwsResource, resoruce_policy: PolicyDocument, action: str, resource: AwsResource
) -> List[Tuple[StatementDetail, Optional[ResourceContstaint]]]:
    """
    resoruce based policies contain principal field and need to be handled differently
    """
    results: List[Tuple[StatementDetail, Optional[ResourceContstaint]]] = []

    if resource.arn is None:
        raise ValueError("Resource ARN is missing, go and fix the filtering logic")

    for statement in resoruce_policy.statements:

        matches, maybe_resource_constraint = check_statement_match(
            statement, effect=None, action=action, resource=resource, principal=principal
        )
        if matches:
            results.append((statement, maybe_resource_constraint))

    return results


def check_explicit_deny(
    request_context: IamRequestContext,
    resource: AwsResource,
    action: str,
    resource_based_policies: List[Tuple[PolicySource, PolicyDocument]],
) -> Union[Literal["Denied", "Allowed"], List[Json]]:

    denied_when_any: List[Json] = []

    # we should skip service control policies for service linked roles
    if not service_linked_role(request_context.principal):
        for _, policy in request_context.service_control_policies:
            result = policy_matching_statement_exists(policy, "Deny", action, resource)
            if result:
                statement, resource_constraint = result
                if statement.condition:
                    denied_when_any.append(statement.condition)
                else:
                    return "Denied"

    # check all the policies except the resource based ones
    for _, policy in request_context.identity_policies + request_context.permission_boundaries:
        result = policy_matching_statement_exists(policy, "Deny", action, resource)
        if result:
            statement, resource_constraint = result
            if statement.condition:
                denied_when_any.append(statement.condition)
            else:
                return "Denied"

    for _, policy in resource_based_policies:
        # resource based policies require a different handling
        resource_policy_statements = collect_matching_resource_statements(
            request_context.principal, policy, action, resource
        )
        for statement, _ in resource_policy_statements:
            if not statement.effect_deny:
                continue
            if statement.condition:
                denied_when_any.append(statement.condition)
            else:
                return "Denied"

    if len(denied_when_any) > 0:
        return denied_when_any

    return "Allowed"


def scp_allowed(request_context: IamRequestContext) -> bool:
    # todo: collect the necessary resources and implement this
    return True


class ResourcePolicyCheckResult(Enum):
    NO_MATCH = 0
    DENY_MATCH = 1
    ALLOW_MATCH = 2


@frozen
class FinalAllow:
    scopes: List[PermissionScope]


@frozen
class Continue:
    scopes: List[PermissionScope]


ResourceBasedPolicyResult = Union[FinalAllow, Continue]


# check if the resource based policies allow the action
# as a shortcut we return the first allow statement we find, or a first seen condition.
# todo: collect all allow statements and conditions
def check_resource_based_policies(
    principal: AwsResource,
    action: str,
    resource: AwsResource,
    resource_based_policies: List[Tuple[PolicySource, PolicyDocument]],
) -> ResourceBasedPolicyResult:

    scopes: List[PermissionScope] = []

    # todo: add special handling for IAM and KMS resources

    for source, policy in resource_based_policies:
        matching_statements = collect_matching_resource_statements(principal, policy, action, resource)
        if len(matching_statements) == 0:
            continue

        for statement, constraint in matching_statements:
            if statement.effect_allow:
                if statement.condition:
                    scopes.append(
                        PermissionScope(source=source, restriction=constraint or "*", conditions=[statement.condition])
                    )
                else:
                    scopes.append(PermissionScope(source=source, restriction=constraint or "*", conditions=[]))

    if isinstance(principal, AwsIamUser):
        # in case of IAM user, access is allowed regardless of the rest of the policies
        return FinalAllow(scopes)

    # todo: deal with session principals somehow
    # in case of other IAM principals, allow on resource based policy is not enough and
    # we need to check the permission boundaries
    return Continue(scopes)


def check_identity_based_policies(
    request_context: IamRequestContext, resource: AwsResource, action: str
) -> List[PermissionScope]:

    scopes: List[PermissionScope] = []

    for source, policy in request_context.identity_policies:
        if exists := policy_matching_statement_exists(policy, "Allow", action, resource):
            statement, resource_constraint = exists
            restriction: str = resource_constraint or "*"
            assert isinstance(statement.condition, dict)
            scopes.append(PermissionScope(source, restriction, [statement.condition]))

    return scopes


def check_permission_boundaries(
    request_context: IamRequestContext, resource: AwsResource, action: str
) -> Union[bool, List[Json]]:

    conditions: List[Json] = []

    for source, policy in request_context.permission_boundaries:
        if exists := policy_matching_statement_exists(policy, "Allow", action, resource):
            statement, constraint = exists
            if not statement.condition:
                return True
            conditions.append(statement.condition)

    if len(conditions) > 0:
        return conditions

    # no matching permission boundaries that allow access
    return False


def negate_condition(condition: Json) -> Json:
    # todo: implement this
    return condition


def merge_conditions(conditions: List[Json]) -> Json:
    # todo: implement this
    return conditions[0]


def service_linked_role(principal: AwsResource) -> bool:
    # todo: implement this
    return False


def get_action_level(action: str) -> str:
    service, action_name = action.split(":")
    action_data = get_action_data(service, action_name)
    level: str = [info["access_level"] for info in action_data[service] if action == info["action"]][0]
    return level


# logic according to https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-denyallow
def check_policies(
    request_context: IamRequestContext,
    resource: AwsResource,
    action: str,
    resource_based_policies: List[Tuple[PolicySource, PolicyDocument]],
) -> Optional[AccessPermission]:

    deny_conditions: Optional[Json] = None
    # 1. check for explicit deny. If denied, we can abort immediately
    result = check_explicit_deny(request_context, resource, action, resource_based_policies)
    if result == "Denied":
        return None
    elif result == "Allowed":
        pass
    else:
        negated = [negate_condition(c) for c in result]
        merged = merge_conditions(negated)
        deny_conditions = merged

    # 2. check for organization SCPs
    if len(request_context.service_control_policies) > 0 and not service_linked_role(request_context.principal):
        org_scp_allowed = scp_allowed(request_context)
        if not org_scp_allowed:
            return None

    # 3. check resource based policies
    resource_based_allowed_scopes: List[PermissionScope] = []
    if len(resource_based_policies) > 0:
        resource_result = check_resource_based_policies(
            request_context.principal, action, resource, resource_based_policies
        )
        if isinstance(resource_result, FinalAllow):
            scopes = resource_result.scopes
            allowed_scopes: List[PermissionScope] = []
            for scope in scopes:
                if deny_conditions:
                    new_conditions = [merge_conditions([deny_conditions, c]) for c in scope.conditions]
                    scope = evolve(scope, conditions=new_conditions)
                allowed_scopes.append(scope)

            return AccessPermission(action=action, level=get_action_level(action), scopes=allowed_scopes)
        if isinstance(resource_result, Continue):
            scopes = resource_result.scopes
            resource_based_allowed_scopes.extend(scopes)

    # 4. check identity based policies
    identity_based_scopes: List[PermissionScope] = []
    if len(request_context.identity_policies) == 0:
        if len(resource_based_allowed_scopes) == 0:
            # nothing from resource based policies and no identity based policies -> implicit deny
            return None
        # we still have to check permission boundaries if there are any, go to step 5
    else:
        identity_based_allowed = check_identity_based_policies(request_context, resource, action)
        if len(identity_based_allowed):
            return None

    # 5. check permission boundaries
    permission_boundary_conditions: List[Json] = []
    if len(request_context.permission_boundaries) > 0:
        permission_boundary_allowed = check_permission_boundaries(request_context, resource, action)
        if permission_boundary_allowed is False:
            return None
        if permission_boundary_allowed is True:
            pass
        if isinstance(permission_boundary_allowed, list):
            permission_boundary_conditions.extend(permission_boundary_allowed)

    # 6. check for session policies
    # we don't collect session principals and session policies, so this step is skipped

    # 7. if we reached here, the action is allowed
    service, action_name = action.split(":")
    action_data = get_action_data(service, action_name)
    level = [info["access_level"] for info in action_data[service] if action == info["action"]][0]

    # 8. deduplicate the policies

    # if there were any permission boundary conditions, we should merge them into the collected scopes
    # todo: merge the boundary conditions into the scopes

    # return the result
    return AccessPermission(
        action=action,
        level=level,
        scopes=resource_based_allowed_scopes + identity_based_scopes,  # todo: add scopes
    )


def compute_permissions(
    resource: AwsResource,
    iam_context: IamRequestContext,
    resource_based_policies: List[Tuple[PolicySource, PolicyDocument]],
) -> List[AccessPermission]:

    # step 1: find the relevant action to check
    relevant_actions = find_all_allowed_actions([p for _, p in iam_context.all_policies(resource_based_policies)])

    all_permissions: List[AccessPermission] = []

    # step 2: for every action, check if it is allowed
    for action in relevant_actions:
        if p := check_policies(iam_context, resource, action, resource_based_policies):
            all_permissions.append(p)

    return all_permissions


class AccessEdgeCreator:

    def __init__(self, builder: GraphBuilder):
        self.builder = builder
        self.principals: List[IamRequestContext] = []

    def init_principals(self) -> None:
        for node in self.builder.nodes(clazz=AwsResource):
            if isinstance(node, AwsIamUser):

                identity_based_policies = self.get_identity_based_policies(node)
                permission_boundaries: List[Tuple[PolicySource, PolicyDocument]] = []  # todo: add this
                service_control_policies: List[Tuple[PolicySource, PolicyDocument]] = (
                    []
                )  # todo: add this, see https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html

                request_context = IamRequestContext(
                    principal=node,
                    identity_policies=identity_based_policies,
                    permission_boundaries=permission_boundaries,
                    service_control_policies=service_control_policies,
                )

                self.principals.append(request_context)

    def get_identity_based_policies(self, principal: AwsResource) -> List[Tuple[PolicySource, PolicyDocument]]:
        if isinstance(principal, AwsIamUser):
            inline_policies = [
                (
                    PolicySource(kind=PolicySourceKind.Principal, arn=principal.arn or ""),
                    PolicyDocument(policy.policy_document),
                )
                for policy in principal.user_policies
                if policy.policy_document
            ]
            attached_policies = []
            group_policies = []
            for _, to_node in self.builder.graph.edges(principal):
                if isinstance(to_node, AwsIamPolicy):
                    if doc := find_policy_doc(to_node):
                        attached_policies.append(
                            (
                                PolicySource(kind=PolicySourceKind.Principal, arn=principal.arn or ""),
                                PolicyDocument(doc),
                            )
                        )

                if isinstance(to_node, AwsIamGroup):
                    group = to_node
                    # inline group policies
                    for policy in group.group_policies:
                        if policy.policy_document:
                            group_policies.append(
                                (
                                    PolicySource(kind=PolicySourceKind.Group, arn=group.arn or ""),
                                    PolicyDocument(policy.policy_document),
                                )
                            )
                    # attached group policies
                    for _, group_successor in self.builder.graph.edges(group):
                        if isinstance(group_successor, AwsIamPolicy):
                            if doc := find_policy_doc(group_successor):
                                group_policies.append(
                                    (
                                        PolicySource(kind=PolicySourceKind.Group, arn=group.arn or ""),
                                        PolicyDocument(doc),
                                    )
                                )

            return inline_policies + attached_policies + group_policies

        return []

    def add_access_edges(self) -> None:

        for node in self.builder.nodes(clazz=AwsResource, filter=lambda r: r.arn is not None):
            for context in self.principals:

                resource_policies: List[Tuple[PolicySource, PolicyDocument]] = []
                if isinstance(node, HasResourcePolicy):
                    for source, json_policy in node.resource_policy(self.builder):
                        resource_policies.append((source, PolicyDocument(json_policy)))

                permissions = compute_permissions(node, context, resource_policies)

                self.builder.add_edge(
                    from_node=context.principal, edge_type=EdgeType.access, permissions=permissions, to_node=node
                )
