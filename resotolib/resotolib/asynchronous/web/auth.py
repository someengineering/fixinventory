import json
import logging
import re
import time
from contextvars import ContextVar
from datetime import datetime, timedelta
from re import RegexFlag
from typing import Any, Dict, Optional, Set, Callable, Awaitable, Tuple
from urllib.parse import urlparse

from aiohttp import web
from aiohttp.web import Request, StreamResponse
from aiohttp.web import middleware
from attr import define
from jwt import PyJWTError

from resotolib import jwt as ck_jwt
from resotolib.asynchronous.web import RequestHandler, Middleware
from resotolib.jwt import encode_jwt
from resotolib.types import Json
from resotolib.utils import utc

log = logging.getLogger(__name__)
JWT = Dict[str, Any]
__JWT_Context: ContextVar[JWT] = ContextVar("JWT", default={})
CodeLifeTime = timedelta(minutes=5)


@define
class AuthorizedUser:
    email: str
    roles: Set[str]
    authorized_at: datetime

    def is_valid(self) -> bool:
        return utc() - self.authorized_at < CodeLifeTime


__authorization_codes: Dict[str, AuthorizedUser] = {}


async def authorized_user(code: str) -> Optional[AuthorizedUser]:
    for invalid_code in [k for k, v in __authorization_codes.items() if not v.is_valid()]:
        __authorization_codes.pop(invalid_code, None)
    return __authorization_codes.get(code)


def add_authorized_user(code: str, user: AuthorizedUser) -> None:
    __authorization_codes[code] = user


async def jwt_from_context() -> JWT:
    """
    Inside a request handler, this value retrieves the current jwt.
    """
    return __JWT_Context.get()


def raw_jwt_from_auth_message(msg: str) -> Optional[str]:
    """
    Expected message: json object with type kind="authorization" and a jwt field
    { "kind": "authorization", "jwt": "Bearer <jwt>" }
    """
    try:
        js = json.loads(msg)
        assert js.get("kind") == "authorization"
        return js.get("jwt")  # type: ignore
    except Exception:
        return None


@middleware
async def no_check(request: Request, handler: RequestHandler) -> StreamResponse:
    # all requests are authorized automatically
    request["authorized"] = True
    return await handler(request)


def set_valid_jwt(request: Request, jwt_raw: str, psk: str) -> Optional[JWT]:
    try:
        # note: the expiration is already checked by this function
        jwt = ck_jwt.decode_jwt_from_header_value(jwt_raw, psk)
    except PyJWTError:
        return None
    if jwt:
        request["authorized"] = True  # deferred check in websocket handler
        request["jwt"] = jwt
        __JWT_Context.set(jwt)
    return jwt


def renew_user_jwt(psk: str, jwt_lifetime: timedelta, user: AuthorizedUser) -> Tuple[str, Json]:
    exp = int(time.time() + jwt_lifetime.total_seconds())
    data = {"email": user.email, "roles": ",".join(user.roles), "exp": exp}
    return encode_jwt(data, psk, expire_in=int(jwt_lifetime.total_seconds())), data


def check_auth(
    psk: str,
    jwt_lifetime: timedelta,
    always_allowed_paths: Set[str],
    not_allowed: Optional[Callable[[Request], Awaitable[StreamResponse]]] = None,
) -> Middleware:
    def always_allowed(request: Request) -> bool:
        for path in always_allowed_paths:
            if re.fullmatch(path, request.path, RegexFlag.IGNORECASE):
                return True
        return False

    async def valid_jwt(request: Request) -> bool:
        auth_header = request.headers.get("Authorization") or request.cookies.get("resoto_authorization")
        if auth_header:
            # make sure origin and host match, so the request is valid
            origin: Optional[str] = urlparse(request.headers.get("Origin")).hostname  # type: ignore
            host: Optional[str] = request.headers.get("Host")
            if host is not None and origin is not None:
                if ":" in host:
                    host = host.split(":")[0]
                if origin.lower() != host.lower():
                    log.warning(f"Origin {origin} is not allowed in request from {request.remote} to {request.path}")
                    raise web.HTTPForbidden()

            # try to authorize the request, even if it is one of the always allowed paths
            authorized = set_valid_jwt(request, auth_header, psk) is not None
            return authorized
        return False

    async def valid_code(request: Request) -> bool:
        code = request.query.get("code")
        if code:
            if (user := await authorized_user(code)) and user.is_valid():
                data = {"email": user.email, "roles": ",".join(user.roles)}
                jwt = encode_jwt(data, psk, expire_in=int(jwt_lifetime.total_seconds()))
                request["send_auth_response_header"] = f"Bearer {jwt}"
                request["jwt"] = data
                return True
        return False

    @middleware
    async def valid_auth_handler(request: Request, handler: RequestHandler) -> StreamResponse:
        allowed = False
        if always_allowed(request):
            allowed = True
        elif request.headers.get("Authorization"):
            allowed = await valid_jwt(request)
        elif request.query.get("code"):
            allowed = await valid_code(request)
        if allowed:
            request["authorized"] = True
            return await handler(request)
        else:
            if not_allowed:
                return await not_allowed(request)
            else:
                raise web.HTTPUnauthorized()

    return valid_auth_handler


def auth_handler(
    psk: Optional[str],
    jwt_lifetime: timedelta,
    always_allowed_paths: Set[str],
    not_allowed: Optional[Callable[[Request], Awaitable[StreamResponse]]] = None,
) -> Middleware:
    if psk:
        log.info("Use JWT authentication with a pre shared key")
        return check_auth(psk, jwt_lifetime, always_allowed_paths, not_allowed)
    else:
        log.info("No authentication requested.")
        return no_check
