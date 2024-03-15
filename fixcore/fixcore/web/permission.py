from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Union, Set

from aiohttp import web
from aiohttp.web_request import Request

from fixcore.core_config import CoreConfig
from fixcore.error import NotEnoughPermissions
from fixcore.user.model import Permission, Role, PredefineRoles

log = logging.getLogger(__name__)


class PermissionChecker(ABC):
    @abstractmethod
    def requires_permission(self, request: Request, *permission: Union[Permission, Set[Permission]]) -> None:
        pass

    def _includes_permission(
        self, available_permissions: Set[Permission], *required_permission: Union[Permission, Set[Permission]]
    ) -> bool:
        for p in required_permission:
            if isinstance(p, Permission):
                if p not in available_permissions:
                    return False
            elif isinstance(p, set):
                if not p.issubset(available_permissions):
                    return False
            else:
                raise ValueError(f"Invalid permission {p}")
        return True

    def flatten(self, *permission: Union[Permission, Set[Permission]]) -> Set[Permission]:
        result = set()
        for p in permission:
            if isinstance(p, Permission):
                result.add(p)
            elif isinstance(p, set):
                result.update(p)
            else:
                raise ValueError(f"Invalid permission {p}")
        return result

    @staticmethod
    def create(config: CoreConfig) -> PermissionChecker:
        if config.args.psk:
            log.info("Use User based permission checker.")
            return UserPermissionChecker()
        elif config.args.role and (role := PredefineRoles.get(config.args.role)):
            log.info(f"Role defined on command line and no PSK. Require role {role.name} for all requests.")
            return StaticRoleChecker(role)
        else:
            log.info("Permission checking disabled - allow all requests.")
            return NoPermissionChecker()


class NoPermissionChecker(PermissionChecker):
    def requires_permission(self, request: Request, *permission: Union[Permission, Set[Permission]]) -> None:
        pass


class UserPermissionChecker(PermissionChecker):
    def requires_permission(self, request: Request, *permission: Union[Permission, Set[Permission]]) -> None:
        # Make sure, the current user has the required permissions
        if current_user := request.get("user"):
            if not self._includes_permission(current_user.permissions, *permission):
                raise NotEnoughPermissions(current_user.permissions, self.flatten(*permission))
        else:
            raise web.HTTPUnauthorized()


class StaticRoleChecker(PermissionChecker):
    def __init__(self, role: Role):
        self.role = role

    def requires_permission(self, request: Request, *permission: Union[Permission, Set[Permission]]) -> None:
        if not self._includes_permission(self.role.permissions, *permission):
            raise NotEnoughPermissions(self.role.permissions, self.flatten(*permission))
