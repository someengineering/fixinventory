from enum import StrEnum
from abc import ABC
from attrs import frozen, evolve
from typing import List, Tuple, Any
from fixlib.types import Json

ResourceConstraint = str


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
    constraints: List[ResourceConstraint]  # aka resource constraints
    allow_conditions: List[Json]  # if nonempty and any evals to true, access is granted, otherwise implicitly denied
    boundary_conditions: List[Json] = []  # if nonempty and any is evals to false, access is implicitly denied
    deny_conditions: List[Json] = []  # if nonempty and any evals to true, access is explicitly denied

    def with_deny_conditions(self, deny_conditions: List[Json]) -> "PermissionScope":
        return evolve(self, deny_conditions=deny_conditions)

    def with_boundary_conditions(self, boundary_conditions: List[Json]) -> "PermissionScope":
        return evolve(self, boundary_conditions=boundary_conditions)


@frozen
class AccessPermission:
    action: str
    level: str
    scopes: List[PermissionScope]
