import asyncio
from typing import Any

import pytest

# noinspection PyUnresolvedReferences
from aiohttp.pytest_plugin import aiohttp_client
from aiohttp.test_utils import TestClient
from aiohttp.web import Application, Request, Response
from multidict import CIMultiDict
from pytest import mark

from fixcore.dependencies import TenantDependencies
from fixcore.user.model import Permission
from fixcore.web.auth import AuthHandler
from fixlib.jwt import encode_jwt


@pytest.fixture
async def loop() -> Any:
    return asyncio.get_running_loop()


@pytest.fixture
async def app_with_auth(auth_handler: AuthHandler) -> Application:
    async def hello(_: Request, deps: TenantDependencies) -> Response:
        return Response(text="Hello, world")

    app = Application(middlewares=[auth_handler.middleware()])
    app.router.add_get("/", auth_handler.allow_with(hello))
    app.router.add_get("/with_read", auth_handler.allow_with(hello, Permission.read))
    app.router.add_get("/with_write", auth_handler.allow_with(hello, Permission.write))
    return app


@mark.asyncio
async def test_correct_psk(aiohttp_client: Any, app_with_auth: Application) -> None:
    client: TestClient = await aiohttp_client(app_with_auth)
    jwt = encode_jwt({"foo": "bla"}, "test")
    resp = await client.get("/", headers=CIMultiDict({"Authorization": f"Bearer {jwt}"}))
    assert resp.status == 200


@mark.asyncio
async def test_wrong_psk(aiohttp_client: Any, app_with_auth: Application) -> None:
    client: TestClient = await aiohttp_client(app_with_auth)
    jwt = encode_jwt({"foo": "bla"}, "wrong!")
    resp = await client.get("/", headers=CIMultiDict({"Authorization": f"Bearer {jwt}"}))
    assert resp.status == 401


@mark.asyncio
async def test_no_psk(aiohttp_client: Any, app_with_auth: Application) -> None:
    client: TestClient = await aiohttp_client(app_with_auth)
    resp = await client.get("/")
    assert resp.status == 401


@mark.asyncio
async def test_permission(aiohttp_client: Any, app_with_auth: Application) -> None:
    client: TestClient = await aiohttp_client(app_with_auth)
    jwt = encode_jwt({"email": "batman@gotham", "roles": "readonly"}, "test")
    headers = CIMultiDict({"Authorization": f"Bearer {jwt}"})
    assert (await client.get("/", headers=headers)).status == 200
    assert (await client.get("/with_read", headers=headers)).status == 200
    failing = await client.get("/with_write", headers=headers)
    assert failing.status == 403
    assert await failing.text() == "Not allowed to perform this operation. Missing permission: write"
