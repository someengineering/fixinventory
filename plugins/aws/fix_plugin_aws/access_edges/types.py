from enum import Enum
from attr import frozen
from cloudsplaining.scan.policy_document import PolicyDocument
from cloudsplaining.scan.statement_detail import StatementDetail
from fixlib.types import Json
import logging


log = logging.getLogger("fix.plugins.aws")


class WildcardKind(Enum):
    fixed = 1
    pattern = 2
    any = 3


@frozen(slots=True)
class ActionWildcardPattern:
    pattern: str
    service: str
    kind: WildcardKind


class ArnResourceValueKind(Enum):
    Static = 1  # the segment is a fixed value, e.g. "s3", "vpc/vpc-0e9801d129EXAMPLE",
    Pattern = 2  # the segment is a pattern, e.g. "my_corporate_bucket/*",
    Any = 3  # the segment is missing, e.g. "::" or it is a wildcard, e.g. "*"

    @staticmethod
    def from_str(value: str) -> "ArnResourceValueKind":
        if value == "*":
            return ArnResourceValueKind.Any
        if "*" in value:
            return ArnResourceValueKind.Pattern
        return ArnResourceValueKind.Static


@frozen(slots=True)
class ResourceWildcardPattern:
    raw_value: str
    partition: str | None  # None in case the whole string is "*"
    service: str
    region: str
    region_value_kind: ArnResourceValueKind
    account: str
    account_value_kind: ArnResourceValueKind
    resource: str
    resource_value_kind: ArnResourceValueKind

    @staticmethod
    def from_str(value: str) -> "ResourceWildcardPattern":
        if value == "*":
            return ResourceWildcardPattern(
                raw_value=value,
                partition=None,
                service="*",
                region="*",
                region_value_kind=ArnResourceValueKind.Any,
                account="*",
                account_value_kind=ArnResourceValueKind.Any,
                resource="*",
                resource_value_kind=ArnResourceValueKind.Any,
            )

        try:
            splitted = value.split(":", 5)
            if len(splitted) != 6:
                raise ValueError(f"Invalid resource pattern: {value}")
            _, partition, service, region, account, resource = splitted

            return ResourceWildcardPattern(
                raw_value=value,
                partition=partition,
                service=service,
                region=region,
                region_value_kind=ArnResourceValueKind.from_str(region),
                account=account,
                account_value_kind=ArnResourceValueKind.from_str(account),
                resource=resource,
                resource_value_kind=ArnResourceValueKind.from_str(resource),
            )
        except Exception as e:
            log.error(f"Error parsing resource pattern {value}: {e}")
            raise e


class FixStatementDetail(StatementDetail):
    def __init__(self, statement: Json):
        super().__init__(statement)

        def pattern_from_action(action: str) -> ActionWildcardPattern:
            if action == "*":
                return ActionWildcardPattern(pattern=action, service="*", kind=WildcardKind.any)

            action = action.lower()
            service, action_name = action.split(":", 1)
            if action_name == "*":
                kind = WildcardKind.any
            elif "*" in action_name:
                kind = WildcardKind.pattern
            else:
                kind = WildcardKind.fixed

            return ActionWildcardPattern(pattern=action, service=service, kind=kind)

        self.actions_patterns = [pattern_from_action(action) for action in self.actions]
        self.not_action_patterns = [pattern_from_action(action) for action in self.not_action]
        self.resource_patterns = [ResourceWildcardPattern.from_str(resource) for resource in self.resources]
        self.not_resource_patterns = [ResourceWildcardPattern.from_str(resource) for resource in self.not_resource]


class FixPolicyDocument(PolicyDocument):
    def __init__(self, policy_document: Json):
        super().__init__(policy_document)

        self.fix_statements = [FixStatementDetail(statement.json) for statement in self.statements]
