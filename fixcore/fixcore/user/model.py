from __future__ import annotations
from enum import Enum
from typing import Set, Dict, Any

from attr import define


class Permission(Enum):
    read = "read"  # can read all resource data
    write = "write"  # can change all resource data
    admin = "admin"  # can change configuration


@define
class Role:
    name: str
    permissions: Set[Permission]

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions


RoleAdmin = Role("admin", {Permission.admin, Permission.read, Permission.write})
RoleReadWrite = Role("readwrite", {Permission.read, Permission.write})
RoleReadOnly = Role("readonly", {Permission.read})
RoleService = Role("service", {Permission.admin, Permission.read, Permission.write})
PredefineRoles = {r.name: r for r in [RoleAdmin, RoleReadWrite, RoleReadOnly, RoleService]}
AllowedRoleNames = set(PredefineRoles.keys()) - {"service"}


@define
class AuthorizedUser:
    email: str
    roles: Set[str]
    permissions: Set[Permission]
    is_user: bool

    def has_permission(self, required_permissions: Set[Permission]) -> bool:
        return required_permissions.issubset(self.permissions)

    @staticmethod
    def from_jwt(jwt: Dict[str, Any]) -> AuthorizedUser:
        def permissions_for_role(role_name: str) -> Set[Permission]:
            if role_name not in PredefineRoles:
                return set()
            return PredefineRoles[role_name].permissions

        if "email" in jwt:  # This is a user token
            email = jwt["email"]
            roles = set(jwt["roles"].split(","))
            is_user = True
        else:  # This is a service token
            email = "service@inventory.fix.security"
            roles = {"service"}
            is_user = False
        return AuthorizedUser(
            email=email,
            roles=roles,
            permissions={perm for rn in roles for perm in permissions_for_role(rn)},
            is_user=is_user,
        )
