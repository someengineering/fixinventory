from __future__ import annotations
from enum import Enum
from typing import Set, Dict, Any

from attr import define


class Permission(Enum):
    Read = "Read"  # can read all resource data
    Write = "Write"  # can change all resource data
    Admin = "Admin"  # can change configuration


@define
class Role:
    name: str
    permissions: Set[Permission]

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions


PredefineRoles = {
    r.name: r
    for r in [
        Role("admin", {Permission.Admin, Permission.Read, Permission.Write}),
        Role("readwrite", {Permission.Read, Permission.Write}),
        Role("readonly", {Permission.Read}),
        Role("service", {Permission.Admin, Permission.Read, Permission.Write}),
    ]
}
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
            email = "service@resoto.com"
            roles = set("service")
            is_user = False
        return AuthorizedUser(
            email=email,
            roles=roles,
            permissions={perm for rn in roles for perm in permissions_for_role(rn)},
            is_user=is_user,
        )
