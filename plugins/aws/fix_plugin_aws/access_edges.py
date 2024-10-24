from functools import lru_cache
from attr import frozen, define
import networkx
from fix_plugin_aws.resource.base import AwsAccount, AwsResource, GraphBuilder

from typing import Dict, List, Literal, Set, Optional, Tuple, Union, Pattern

from networkx.algorithms.dag import is_directed_acyclic_graph

from fixlib.baseresources import (
    PermissionCondition,
    PolicySource,
    PermissionScope,
    AccessPermission,
    ResourceConstraint,
)
from fix_plugin_aws.resource.iam import AwsIamGroup, AwsIamPolicy, AwsIamUser, AwsIamRole
from fixlib.baseresources import EdgeType, PolicySourceKind, HasResourcePolicy, PermissionLevel
from fixlib.json import to_json, to_json_str
from fixlib.types import Json

from cloudsplaining.scan.policy_document import PolicyDocument
from cloudsplaining.scan.statement_detail import StatementDetail
from policy_sentry.querying.actions import get_action_data, get_actions_matching_arn
from policy_sentry.querying.all import get_all_actions
from policy_sentry.util.arns import ARN, get_service_from_arn
from fixlib.graph import EdgeKey
import re
import logging

log = logging.getLogger("fix.plugins.aws")


ALL_ACTIONS = get_all_actions()


@define(slots=True)
class IamRequestContext:
    principal: AwsResource
    identity_policies: List[Tuple[PolicySource, PolicyDocument]]
    permission_boundaries: List[PolicyDocument]  # todo: use them too
    # all service control policies applicable to the principal,
    # starting from the root, then all org units, then the account
    service_control_policy_levels: List[List[PolicyDocument]]
    # technically we should also add a list of session policies here, but they don't exist in the collector context

    def all_policies(
        self, resource_based_policies: Optional[List[Tuple[PolicySource, PolicyDocument]]] = None
    ) -> List[PolicyDocument]:
        return (
            [p[1] for p in self.identity_policies]
            + self.permission_boundaries
            + [p for group in self.service_control_policy_levels for p in group]
            + ([p[1] for p in (resource_based_policies or [])])
        )


IamAction = str


def find_allowed_action(policy_document: PolicyDocument, service_prefix: str) -> Set[IamAction]:
    allowed_actions: Set[IamAction] = set()
    for statement in policy_document.statements:
        if statement.effect_allow:
            allowed_actions.update(get_expanded_action(statement, service_prefix))

    return allowed_actions


def find_non_service_actions(resource_arn: str) -> Set[IamAction]:
    try:
        splitted = resource_arn.split(":")
        service_prefix = splitted[2]
        if service_prefix == "iam":
            resource_type = splitted[5]
            resource = resource_type.split("/")[0]
            if resource == "role":
                return {"sts:AssumeRole"}
    except Exception as e:
        log.info(f"Error when trying to get non-service actions for ARN {resource_arn}: {e}")
    return set()


def find_all_allowed_actions(all_involved_policies: List[PolicyDocument], resource_arn: str) -> Set[IamAction]:
    resource_actions = set()
    try:
        resource_actions = set(get_actions_matching_arn(resource_arn))
    except Exception as e:
        log.debug(f"Error when trying to get actions matching ARN {resource_arn}: {e}")

    if additinal_actions := find_non_service_actions(resource_arn):
        resource_actions.update(additinal_actions)

    service_prefix = ""
    try:
        service_prefix = get_service_from_arn(resource_arn)
    except Exception as e:
        log.debug(f"Error when trying to get service prefix from ARN {resource_arn}: {e}")
    policy_actions: Set[IamAction] = set()
    for p in all_involved_policies:
        policy_actions.update(find_allowed_action(p, service_prefix))
    return policy_actions.intersection(resource_actions)


def get_expanded_action(statement: StatementDetail, service_prefix: str) -> Set[str]:
    actions = set()
    expanded: List[str] = statement.expanded_actions or []
    for action in expanded:
        if action.startswith(f"{service_prefix}:"):
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


def check_statement_match(
    statement: StatementDetail,
    effect: Optional[Literal["Allow", "Deny"]],
    action: str,
    resource: AwsResource,
    principal: Optional[AwsResource],
    source_arn: Optional[str] = None,
) -> Tuple[bool, List[ResourceConstraint]]:
    """
    check if a statement matches the given effect, action, resource and principal,
    returns boolean if there is a match and optional resource constraint (if there were any)
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
            return False, []

    # step 2: check if the effect matches
    if effect:
        if statement.effect != effect:
            # wrong effect, skip this statement
            return False, []

    # step 3: check if the action matches
    action_match = False
    if statement.actions:
        # shortcuts for known AWS managed policies
        if source_arn == "arn:aws:iam::aws:policy/ReadOnlyAccess":
            action_level = get_action_level(action)
            if action_level in [PermissionLevel.read or PermissionLevel.list]:
                action_match = True
            else:
                action_match = False
        else:
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
        return False, []

    # step 4: check if the resource matches
    matched_resource_constraints: List[ResourceConstraint] = []
    resource_matches = False
    if len(statement.resources) > 0:
        for resource_constraint in statement.resources:
            if expand_wildcards_and_match(identifier=resource.arn, wildcard_string=resource_constraint):
                matched_resource_constraints.append(resource_constraint)
                resource_matches = True
                break
    elif len(statement.not_resource) > 0:
        resource_matches = True
        for not_resource_constraint in statement.not_resource:
            if expand_wildcards_and_match(identifier=resource.arn, wildcard_string=not_resource_constraint):
                resource_matches = False
                break
            matched_resource_constraints.append("not " + not_resource_constraint)
    else:
        # no Resource/NotResource specified, consider allowed
        resource_matches = True
    if not resource_matches:
        # resource does not match, skip this statement
        return False, []

    # step 5: (we're not doing this yet) check if the condition matches
    # here we just return the statement and condition checking is the responsibility of the caller
    return (True, matched_resource_constraints)


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


def collect_matching_statements(
    *,
    policy: PolicyDocument,
    effect: Optional[Literal["Allow", "Deny"]],
    action: str,
    resource: AwsResource,
    principal: Optional[AwsResource],
    source_arn: Optional[str] = None,
) -> List[Tuple[StatementDetail, List[ResourceConstraint]]]:
    """
    resoruce based policies contain principal field and need to be handled differently
    """
    results: List[Tuple[StatementDetail, List[ResourceConstraint]]] = []

    if resource.arn is None:
        raise ValueError("Resource ARN is missing, go and fix the filtering logic")

    for statement in policy.statements:

        matches, maybe_resource_constraint = check_statement_match(
            statement, effect=effect, action=action, resource=resource, principal=principal, source_arn=source_arn
        )
        if matches:
            results.append((statement, maybe_resource_constraint))

    return results


def check_explicit_deny(
    request_context: IamRequestContext,
    resource: AwsResource,
    action: str,
    resource_based_policies: List[Tuple[PolicySource, PolicyDocument]],
) -> Union[Literal["Denied", "NextStep"], List[Json]]:

    denied_when_any_is_true: List[Json] = []

    # we should skip service control policies for service linked roles
    if not is_service_linked_role(request_context.principal):
        for scp_level in request_context.service_control_policy_levels:
            for policy in scp_level:
                policy_statements = collect_matching_statements(
                    policy=policy, effect="Deny", action=action, resource=resource, principal=request_context.principal
                )
                for statement, _ in policy_statements:
                    if statement.condition:
                        denied_when_any_is_true.append(statement.condition)
                    else:
                        return "Denied"

    # check permission boundaries
    for policy in request_context.permission_boundaries:
        policy_statements = collect_matching_statements(
            policy=policy, effect="Deny", action=action, resource=resource, principal=request_context.principal
        )
        for statement, _ in policy_statements:
            if statement.condition:
                denied_when_any_is_true.append(statement.condition)
            else:
                return "Denied"

    # check the rest of the policies
    for _, policy in request_context.identity_policies + resource_based_policies:
        policy_statements = collect_matching_statements(
            policy=policy, effect="Deny", action=action, resource=resource, principal=request_context.principal
        )
        for statement, _ in policy_statements:
            if statement.condition:
                denied_when_any_is_true.append(statement.condition)
            else:
                return "Denied"

    if denied_when_any_is_true:
        return denied_when_any_is_true

    return "NextStep"


def scp_allowed(request_context: IamRequestContext, action: str, resource: AwsResource) -> bool:

    # traverse the SCPs:  root -> OU -> account levels
    for scp_level_policies in request_context.service_control_policy_levels:
        level_allows = False
        for policy in scp_level_policies:
            statements = collect_matching_statements(
                policy=policy, effect="Allow", action=action, resource=resource, principal=None
            )
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
    action: str,
    resource: AwsResource,
    resource_based_policies: List[Tuple[PolicySource, PolicyDocument]],
) -> ResourceBasedPolicyResult:
    assert resource.arn

    scopes: List[PermissionScope] = []

    arn = ARN(resource.arn)
    explicit_allow_required = False
    if arn.service_prefix == "iam" or arn.service_prefix == "kms":
        explicit_allow_required = True

    for source, policy in resource_based_policies:

        matching_statements = collect_matching_statements(
            policy=policy,
            effect="Allow",
            action=action,
            resource=resource,
            principal=principal,
        )
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


def check_identity_based_policies(
    request_context: IamRequestContext, resource: AwsResource, action: str
) -> List[PermissionScope]:

    scopes: List[PermissionScope] = []

    for source, policy in request_context.identity_policies:
        for statement, resource_constraints in collect_matching_statements(
            policy=policy, effect="Allow", action=action, resource=resource, principal=None, source_arn=source.uri
        ):
            conditions = None
            if statement.condition:
                conditions = PermissionCondition(allow=(to_json_str(statement.condition),))

            scopes.append(PermissionScope(source, tuple(resource_constraints), conditions=conditions))

    return scopes


def check_permission_boundaries(
    request_context: IamRequestContext, resource: AwsResource, action: str
) -> Union[Literal["Denied", "NextStep"], List[Json]]:

    conditions: List[Json] = []

    # ignore policy sources and resource constraints because permission boundaries
    # can never allow access to a resource, only restrict it
    for policy in request_context.permission_boundaries:
        for statement, _ in collect_matching_statements(
            policy=policy, effect="Allow", action=action, resource=resource, principal=None
        ):
            if statement.condition:
                assert isinstance(statement.condition, dict)
                conditions.append(statement.condition)
            else:  # if there is an allow statement without a condition, the action is allowed
                return "NextStep"

    if len(conditions) > 0:
        return conditions

    # no matching permission boundaries that allow access
    return "Denied"


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
    resource: AwsResource,
    action: str,
    resource_based_policies: List[Tuple[PolicySource, PolicyDocument]],
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
    result = check_explicit_deny(request_context, resource, action, resource_based_policies)
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

            return AccessPermission(action=action, level=get_action_level(action), scopes=tuple(final_resource_scopes))
        if isinstance(resource_result, Continue):
            scopes = resource_result.scopes
            allowed_scopes.extend(scopes)

        if isinstance(resource_result, Deny):
            return None

    # 4. to make it a bit simpler, we check the permission boundaries before checking identity based policies
    if len(request_context.permission_boundaries) > 0:
        permission_boundary_result = check_permission_boundaries(request_context, resource, action)
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
        identity_based_allowed = check_identity_based_policies(request_context, resource, action)
        if not identity_based_allowed:
            return None
        allowed_scopes.extend(identity_based_allowed)

    # 6. check for session policies
    # we don't collect session principals and session policies, so this step is skipped

    # 7. if we reached here, the action is allowed
    level = get_action_level(action)

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
        action=action,
        level=level,
        scopes=tuple(final_scopes),
    )


def compute_permissions(
    resource: AwsResource,
    iam_context: IamRequestContext,
    resource_based_policies: List[Tuple[PolicySource, PolicyDocument]],
) -> List[AccessPermission]:

    assert resource.arn
    # step 1: find the relevant action to check
    relevant_actions = find_all_allowed_actions(iam_context.all_policies(resource_based_policies), resource.arn)

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
        self._init_principals()

    def _init_principals(self) -> None:

        account_id = self.builder.account.id
        service_control_policy_levels: List[List[PolicyDocument]] = []
        account = next(self.builder.nodes(clazz=AwsAccount, filter=lambda a: a.id == account_id), None)
        if account and account._service_control_policies:
            service_control_policy_levels = [
                [PolicyDocument(json) for json in level] for level in account._service_control_policies
            ]

        for node in self.builder.nodes(clazz=AwsResource):
            if isinstance(node, AwsIamUser):

                identity_based_policies = self._get_user_based_policies(node)

                permission_boundaries: List[PolicyDocument] = []
                if (pb := node.user_permissions_boundary) and (pb_arn := pb.permissions_boundary_arn):
                    for pb_policy in self.builder.nodes(clazz=AwsIamPolicy, filter=lambda p: p.arn == pb_arn):
                        if pdj := pb_policy.policy_document_json():
                            permission_boundaries.append(PolicyDocument(pdj))

                request_context = IamRequestContext(
                    principal=node,
                    identity_policies=identity_based_policies,
                    permission_boundaries=permission_boundaries,
                    service_control_policy_levels=service_control_policy_levels,
                )

                self.principals.append(request_context)

            if isinstance(node, AwsIamGroup):
                identity_based_policies = self._get_group_based_policies(node)

                request_context = IamRequestContext(
                    principal=node,
                    identity_policies=identity_based_policies,
                    permission_boundaries=[],  # permission boundaries are not applicable to groups
                    service_control_policy_levels=service_control_policy_levels,
                )

                self.principals.append(request_context)

            if isinstance(node, AwsIamRole):
                identity_based_policies = self._get_role_based_policies(node)
                # todo: colect these resources
                permission_boundaries = []
                if (pb := node.role_permissions_boundary) and (pb_arn := pb.permissions_boundary_arn):
                    for pb_policy in self.builder.nodes(clazz=AwsIamPolicy, filter=lambda p: p.arn == pb_arn):
                        if pdj := pb_policy.policy_document_json():
                            permission_boundaries.append(PolicyDocument(pdj))

                request_context = IamRequestContext(
                    principal=node,
                    identity_policies=identity_based_policies,
                    permission_boundaries=permission_boundaries,
                    service_control_policy_levels=service_control_policy_levels,
                )

                self.principals.append(request_context)

    def _get_user_based_policies(self, principal: AwsIamUser) -> List[Tuple[PolicySource, PolicyDocument]]:
        inline_policies = [
            (
                PolicySource(kind=PolicySourceKind.principal, uri=principal.arn or ""),
                PolicyDocument(policy.policy_document),
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
                                PolicySource(kind=PolicySourceKind.group, uri=group.arn or ""),
                                PolicyDocument(policy.policy_document),
                            )
                        )
                # attached group policies
                for _, group_successor in self.builder.graph.edges(group):
                    if isinstance(group_successor, AwsIamPolicy):
                        if doc := group_successor.policy_document_json():
                            group_policies.append(
                                (
                                    PolicySource(kind=PolicySourceKind.group, uri=group_successor.arn or ""),
                                    PolicyDocument(doc),
                                )
                            )

        return inline_policies + attached_policies + group_policies

    def _get_group_based_policies(self, principal: AwsIamGroup) -> List[Tuple[PolicySource, PolicyDocument]]:
        # not really a principal, but could be useful to have access edges for groups
        inline_policies = [
            (
                PolicySource(kind=PolicySourceKind.group, uri=principal.arn or ""),
                PolicyDocument(policy.policy_document),
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
                            PolicyDocument(doc),
                        )
                    )

        return inline_policies + attached_policies

    def _get_role_based_policies(self, principal: AwsIamRole) -> List[Tuple[PolicySource, PolicyDocument]]:
        inline_policies = []
        for doc in [p.policy_document for p in principal.role_policies if p.policy_document]:
            inline_policies.append(
                (
                    PolicySource(kind=PolicySourceKind.principal, uri=principal.arn or ""),
                    PolicyDocument(doc),
                )
            )

        attached_policies = []
        for _, to_node in self.builder.graph.edges(principal):
            if isinstance(to_node, AwsIamPolicy):
                if policy_doc := to_node.policy_document_json():
                    attached_policies.append(
                        (
                            PolicySource(kind=PolicySourceKind.principal, uri=to_node.arn or ""),
                            PolicyDocument(policy_doc),
                        )
                    )

        return inline_policies + attached_policies

    def add_access_edges(self) -> None:

        for node in self.builder.nodes(clazz=AwsResource, filter=lambda r: r.arn is not None):

            for context in self.principals:
                if context.principal.arn == node.arn:
                    # small graph cycles avoidance optimization
                    continue

                resource_policies: List[Tuple[PolicySource, PolicyDocument]] = []
                if isinstance(node, HasResourcePolicy):
                    for source, json_policy in node.resource_policy(self.builder):
                        resource_policies.append((source, PolicyDocument(json_policy)))

                permissions = compute_permissions(node, context, resource_policies)

                if not permissions:
                    continue

                access: Dict[PermissionLevel, bool] = {}

                for permission in permissions:
                    access[permission.level] = True

                reported = to_json({"permissions": permissions} | access, strip_nulls=True)

                self.builder.add_edge(from_node=context.principal, edge_type=EdgeType.iam, reported=reported, node=node)

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
