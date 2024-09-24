from abc import ABC
from attrs import frozen, evolve
from typing import List, Optional, Tuple, Any
from fixlib.json import to_json_str
from fixlib.types import Json
from fixlib.baseresources import PolicySourceKind

ResourceConstraint = str

ConditionString = str


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
    allow: Optional[Tuple[ConditionString, ...]] = None
    # if nonempty and any is evals to false, access is implicitly denied
    boundary: Optional[Tuple[ConditionString, ...]] = None
    # if nonempty and any evals to true, access is explicitly denied
    deny: Optional[Tuple[ConditionString, ...]] = None


@frozen
class PermissionScope:
    source: PolicySource
    constraints: Tuple[ResourceConstraint, ...]  # aka resource constraints
    conditions: Optional[PermissionCondition] = None

    def with_deny_conditions(self, deny_conditions: List[Json]) -> "PermissionScope":
        c = self.conditions or PermissionCondition()
        return evolve(self, conditions=evolve(c, deny=tuple([to_json_str(c) for c in deny_conditions])))

    def with_boundary_conditions(self, boundary_conditions: List[Json]) -> "PermissionScope":
        c = self.conditions or PermissionCondition()
        return evolve(self, conditions=evolve(c, boundary=tuple([to_json_str(c) for c in boundary_conditions])))

    def has_no_condititons(self) -> bool:
        if self.conditions is None:
            return True

        if self.conditions.allow is None and self.conditions.boundary is None and self.conditions.deny is None:
            return True

        return False


@frozen
class AccessPermission:
    action: str
    level: str
    scopes: Tuple[PermissionScope, ...]
