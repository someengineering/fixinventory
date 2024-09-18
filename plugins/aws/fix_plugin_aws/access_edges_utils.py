from enum import StrEnum
from abc import ABC
from attrs import frozen
from typing import List, Tuple, Any
from fixlib.types import Json


class PolicySourceKind(StrEnum):
    Principal = "principal"  # e.g. IAM user, attached policy
    Group = "group"  # policy comes from an IAM group
    Resource = "resource"  # e.g. s3 bucket policy


@frozen
class PolicySource:
    kind: PolicySourceKind
    arn: str


class HasResourcePolicy(ABC):
    # returns a list of all policies that affects the resource (inline, attached, etc.)
    def resource_policy(self, builder: Any) -> List[Tuple[PolicySource, Json]]:
        raise NotImplementedError


@frozen
class PermissionScope:
    source: PolicySource
    constraints: List[str]  # aka resource constraints
    conditions: List[Json]  # if nonempty and any is true, access is granted
    deny_conditions: List[Json]  # if nonempty and any is true, access is denied

    def with_deny_conditions(self, deny_conditions: List[Json]) -> "PermissionScope":
        return PermissionScope(self.source, self.constraints, self.conditions, deny_conditions)


@frozen
class AccessPermission:
    action: str
    level: str
    scopes: List[PermissionScope]
