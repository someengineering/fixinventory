import json
import logging
import re
from contextvars import ContextVar
from re import RegexFlag
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse

from aiohttp import web
from aiohttp.web import Request, StreamResponse
from aiohttp.web import middleware
from resotolib import jwt as ck_jwt
from jwt import PyJWTError

from resotolib.asynchronous.web import RequestHandler, Middleware

log = logging.getLogger(__name__)
JWT = Dict[str, Any]
__JWT_Context: ContextVar[JWT] = ContextVar("JWT", default={})


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
        return js.get("jwt")
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
        request["jwt"] = jwt
        request["authorized"] = True
        __JWT_Context.set(jwt)
    return jwt


def check_jwt(psk: str, always_allowed_paths: Set[str]) -> Middleware:
    def always_allowed(request: Request) -> bool:
        for path in always_allowed_paths:
            if re.fullmatch(path, request.path, RegexFlag.IGNORECASE):
                return True
        return False

    @middleware
    async def valid_jwt_handler(request: Request, handler: RequestHandler) -> StreamResponse:
        auth_header = request.headers.get("Authorization") or request.cookies.get("resoto_authorization")
        authorized = False
        if auth_header:
            # make sure origin and host match, so the request is valid
            origin: Optional[str] = urlparse(request.headers.get("Origin")).hostname
            host: Optional[str] = request.headers.get("Host")
            if host is not None and origin is not None:
                if ":" in host:
                    host = host.split(":")[0]
                if origin.lower() != host.lower():
                    log.warning(f"Origin {origin} is not allowed in request from {request.remote} to {request.path}")
                    raise web.HTTPForbidden()

            # try to authorize the request, even if it is one of the always allowed paths
            authorized = set_valid_jwt(request, auth_header, psk) is not None
        if authorized or always_allowed(request):
            return await handler(request)
        else:
            raise web.HTTPUnauthorized()

    return valid_jwt_handler


def auth_handler(psk: Optional[str], always_allowed_paths: Set[str]) -> Middleware:
    if psk:
        log.info("Use JWT authentication with a pre shared key")
        return check_jwt(psk, always_allowed_paths)
    else:
        log.info("No authentication requested.")
        return no_check
