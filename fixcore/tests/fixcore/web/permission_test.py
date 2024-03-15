from typing import Union, Set

from aiohttp.test_utils import make_mocked_request

from fixcore.user.model import AuthorizedUser, Permission, AllowedRoleNames, RoleReadOnly
from fixcore.web.permission import UserPermissionChecker, StaticRoleChecker, PermissionChecker, NoPermissionChecker


def create_assert(checker: PermissionChecker):  # type: ignore
    def assert_allowed(allowed: bool, user: AuthorizedUser, *permission: Union[Permission, Set[Permission]]) -> None:
        request = make_mocked_request("GET", "/")
        request["user"] = user
        try:
            checker.requires_permission(request, *permission)
            assert allowed
        except Exception:
            assert not allowed

    return assert_allowed


# ernie only has read permission
ernie = AuthorizedUser("ernie", {"readonly"}, {Permission.read}, True)
# batman has all the permissions
batman = AuthorizedUser("batman", AllowedRoleNames, {Permission.read, Permission.write, Permission.admin}, True)


def test_user_permission() -> None:
    assert_allowed = create_assert(UserPermissionChecker())
    # ernie is allowed to read
    assert_allowed(True, ernie)
    assert_allowed(True, ernie, Permission.read)
    assert_allowed(False, ernie, Permission.read, Permission.write)
    assert_allowed(False, ernie, Permission.read, Permission.write, Permission.admin)
    # batman can do everything
    assert_allowed(True, batman)
    assert_allowed(True, batman, Permission.read)
    assert_allowed(True, batman, Permission.read, Permission.write)
    assert_allowed(True, batman, Permission.read, Permission.write, Permission.admin)


def test_static_permission() -> None:
    assert_allowed = create_assert(StaticRoleChecker(RoleReadOnly))
    # ernie is allowed to read
    assert_allowed(True, ernie, Permission.read)
    assert_allowed(False, ernie, Permission.read, Permission.write)
    assert_allowed(False, ernie, Permission.read, Permission.write, Permission.admin)
    # the same goes for batman
    assert_allowed(True, batman, Permission.read)
    assert_allowed(False, batman, Permission.read, Permission.write)
    assert_allowed(False, batman, Permission.read, Permission.write, Permission.admin)


def test_allow_all_permission() -> None:
    assert_allowed = create_assert(NoPermissionChecker())
    # ernie can do everything
    assert_allowed(True, ernie, Permission.read)
    assert_allowed(True, ernie, Permission.read, Permission.write)
    assert_allowed(True, ernie, Permission.read, Permission.write, Permission.admin)
    # the same goes for batman
    assert_allowed(True, batman, Permission.read)
    assert_allowed(True, batman, Permission.read, Permission.write)
    assert_allowed(True, batman, Permission.read, Permission.write, Permission.admin)
