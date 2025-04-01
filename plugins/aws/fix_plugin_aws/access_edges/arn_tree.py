from typing import List, Set
from attrs import frozen
from fix_plugin_aws.access_edges.types import ArnResourceValueKind, FixPolicyDocument, WildcardKind
from policy_sentry.util.arns import ARN
import fnmatch
import logging


log = logging.getLogger("fix.plugins.aws")


@frozen(slots=True)
class ArnResource[T]:
    key: str
    values: Set[T]
    kind: ArnResourceValueKind
    not_resource: bool

    def matches(self, segment: str) -> bool:
        _match = False
        match self.kind:
            case ArnResourceValueKind.Any:
                _match = True
            case ArnResourceValueKind.Pattern:
                _match = fnmatch.fnmatch(segment, self.key)
            case ArnResourceValueKind.Static:
                _match = segment == self.key

        if self.not_resource:
            _match = not _match

        return _match


@frozen(slots=True)
class ArnAccountId[T]:
    key: str
    wildcard: bool  # if the account is a wildcard, e.g. "*" or "::"
    values: Set[T]
    children: List[ArnResource[T]]

    def matches(self, segment: str) -> bool:
        return self.wildcard or self.key == segment


@frozen(slots=True)
class ArnRegion[T]:
    key: str
    wildcard: bool  # if the region is a wildcard, e.g. "*" or "::"
    values: Set[T]
    children: List[ArnAccountId[T]]

    def matches(self, segment: str) -> bool:
        return self.wildcard or self.key == segment


@frozen(slots=True)
class ArnService[T]:
    key: str
    values: Set[T]
    children: List[ArnRegion[T]]

    def matches(self, segment: str) -> bool:
        return self.key == segment


@frozen(slots=True)
class ArnPartition[T]:
    key: str
    wildcard: bool  # for the cases like "Allow": "*" on all resources
    values: Set[T]
    children: List[ArnService[T]]

    def matches(self, segment: str) -> bool:
        return self.wildcard or segment == self.key


class ArnTree[T]:
    def __init__(self) -> None:
        self.partitions: List[ArnPartition[T]] = []

    def add_element(self, elem: T, policy_documents: List[FixPolicyDocument]) -> None:
        """
        This method iterates over every policy statement and adds corresponding arns to principal tree.
        """

        for policy_doc in policy_documents:
            for statement in policy_doc.fix_statements:
                if statement.effect_allow:
                    has_wildcard_resource = False
                    for resource in statement.resources:
                        if resource == "*":
                            has_wildcard_resource = True
                            continue
                        self._add_resource(resource, elem)
                    for not_resource in statement.not_resource:
                        self._add_resource(not_resource, elem, nr=True)

                    if has_wildcard_resource or (not statement.resources and not statement.not_resource):
                        for ap in statement.actions_patterns:
                            if ap.kind == WildcardKind.any:
                                self._add_allow_all_wildcard(elem)
                            self._add_service(ap.service, elem)

    def _add_allow_all_wildcard(self, elem: T) -> None:
        partition = next((p for p in self.partitions if p.key == "*"), None)
        if not partition:
            partition = ArnPartition(key="*", wildcard=True, values=set(), children=[])
            self.partitions.append(partition)

        partition.values.add(elem)

    def _add_resource(self, resource_constraint: str, elem: T, nr: bool = False) -> None:
        """
        _add resource will add the principal arn at the resource level
        """

        try:
            arn = ARN(resource_constraint)
            # Find existing or create partition
            partition = next((p for p in self.partitions if p.key == arn.partition), None)
            if not partition:
                partition = ArnPartition[T](key=arn.partition, wildcard=False, values=set(), children=[])
                self.partitions.append(partition)

            # Find or create service
            service = next((s for s in partition.children if s.key == arn.service_prefix), None)
            if not service:
                service = ArnService[T](key=arn.service_prefix, values=set(), children=[])
                partition.children.append(service)

            # Find or create region
            region_wildcard = arn.region == "*" or not arn.region
            region = next((r for r in service.children if r.key == (arn.region or "*")), None)
            if not region:
                region = ArnRegion[T](key=arn.region or "*", wildcard=region_wildcard, values=set(), children=[])
                service.children.append(region)

            # Find or create account
            account_wildcard = arn.account == "*" or not arn.account
            account = next((a for a in region.children if a.key == (arn.account or "*")), None)
            if not account:
                account = ArnAccountId[T](key=arn.account or "*", wildcard=account_wildcard, values=set(), children=[])
                region.children.append(account)

            # Add resource
            resource = next(
                (r for r in account.children if r.key == arn.resource_string and r.not_resource == nr), None
            )
            if not resource:
                if arn.resource_string == "*":
                    resource_kind = ArnResourceValueKind.Any
                elif "*" in arn.resource_string:
                    resource_kind = ArnResourceValueKind.Pattern
                else:
                    resource_kind = ArnResourceValueKind.Static
                resource = ArnResource(key=arn.resource_string, values=set(), kind=resource_kind, not_resource=nr)
                account.children.append(resource)

            resource.values.add(elem)

        except Exception as e:
            log.error(f"Error parsing ARN {resource_constraint}: {e}")
            pass

    def _add_service(self, service_prefix: str, elem: T) -> None:
        # Find existing or create partition
        partition = next((p for p in self.partitions if p.key == "*"), None)
        if not partition:
            partition = ArnPartition(key="*", wildcard=True, values=set(), children=[])
            self.partitions.append(partition)

        # Find or create service
        service = next((s for s in partition.children if s.key == service_prefix), None)
        if not service:
            service = ArnService(key=service_prefix, values=set(), children=[])
            partition.children.append(service)

        service.values.add(elem)

    def find_matching_values(self, resource_arn: ARN) -> Set[T]:
        """
        this will be called for every resource and it must be fast
        """
        result: Set[T] = set()

        matching_partitions = [p for p in self.partitions if p.key if p.matches(resource_arn.partition)]
        if not matching_partitions:
            return result

        matching_services = [
            s for p in matching_partitions for s in p.children if s.matches(resource_arn.service_prefix)
        ]
        if not matching_services:
            return result
        result.update([arn for s in matching_services for arn in s.values])

        matching_regions = [r for s in matching_services for r in s.children if r.matches(resource_arn.region)]
        if not matching_regions:
            return result
        result.update([arn for r in matching_regions for arn in r.values])

        matching_account_ids = [a for r in matching_regions for a in r.children if r.matches(resource_arn.account)]
        if not matching_account_ids:
            return result
        result.update([arn for a in matching_account_ids for arn in a.values])

        matching_resources = [
            r for a in matching_account_ids for r in a.children if r.matches(resource_arn.resource_string)
        ]
        if not matching_resources:
            return result

        result.update([arn for r in matching_resources for arn in r.values])

        return result


PrincipalArn = str


class PrincipalTree:

    def __init__(self) -> None:
        self.arn_tree = ArnTree[PrincipalArn]()

    def add_principal(self, principal_arn: PrincipalArn, policy_documents: List[FixPolicyDocument]) -> None:
        self.arn_tree.add_element(principal_arn, policy_documents)

    def list_principals(self, resource_arn: ARN) -> Set[str]:
        return self.arn_tree.find_matching_values(resource_arn)
