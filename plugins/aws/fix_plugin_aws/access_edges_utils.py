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
    restriction: str
    conditions: List[Json]


@frozen
class AccessPermission:
    action: str
    level: str
    scopes: List[PermissionScope]
