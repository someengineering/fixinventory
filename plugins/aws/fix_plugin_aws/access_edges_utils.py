from abc import ABC
from attrs import frozen, evolve
from typing import List, Optional, Tuple, Any
from fixlib.types import Json
from fixlib.baseresources import PolicySourceKind

ResourceConstraint = str


@frozen
class PolicySource:
    kind: PolicySourceKind
    uri: str


class HasResourcePolicy(ABC):
    # returns a list of all policies that affects the resource (inline, attached, etc.)
    def resource_policy(self, builder: Any) -> List[Tuple[PolicySource, Json]]:
        raise NotImplementedError


@frozen
class PermissionCondition:
    # if nonempty and any evals to true, access is granted, otherwise implicitly denied
    allow: Optional[List[Json]] = None
    # if nonempty and any is evals to false, access is implicitly denied
    boundary: Optional[List[Json]] = None
    # if nonempty and any evals to true, access is explicitly denied
    deny: Optional[List[Json]] = None


@frozen
class PermissionScope:
    source: PolicySource
    constraints: List[ResourceConstraint]  # aka resource constraints
    conditions: Optional[PermissionCondition] = None

    def with_deny_conditions(self, deny_conditions: List[Json]) -> "PermissionScope":
        c = self.conditions or PermissionCondition()
        return evolve(self, conditions=evolve(c, deny=deny_conditions))

    def with_boundary_conditions(self, boundary_conditions: List[Json]) -> "PermissionScope":
        c = self.conditions or PermissionCondition()
        return evolve(self, conditions=evolve(c, boundary=boundary_conditions))


@frozen
class AccessPermission:
    action: str
    level: str
    scopes: List[PermissionScope]
