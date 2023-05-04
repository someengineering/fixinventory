from __future__ import annotations

import asyncio
import time
import webbrowser
from argparse import Namespace
from asyncio import Task, Condition
from configparser import ConfigParser
from pathlib import Path
from typing import Any, Optional, Tuple, Dict, MutableMapping
from urllib.parse import urlencode

import jwt
from aiohttp import web, hdrs, ClientSession
from resotoclient.async_client import ResotoClient

from resotolib.core import resotocore
from resotolib.logger import log
from resotolib.utils import get_free_port


class AccessDeniedError(Exception):
    pass


async def authorized_client(args: Namespace) -> ResotoClient:
    config = ReshConfig(Path.home() / ".resoto" / "resh.ini")

    # if a PSK was defined on the command line, use it
    if args.psk:
        return ResotoClient(
            url=resotocore.http_uri,
            psk=args.psk,
            custom_ca_cert_path=args.ca_cert,
            verify=args.verify_certs,
        )

    # No PSK defined. Do we need to authorize?
    try:
        await fetch_auth_header(resotocore.http_uri)
        # no authorization required
        return ResotoClient(url=resotocore.http_uri, custom_ca_cert_path=args.ca_cert, verify=args.verify_certs)
    except AccessDeniedError:
        if creds := config.valid_credentials(resotocore.http_uri):
            # Valid credentials found in config file
            method, auth_token = creds
            return ResotoClient(
                url=resotocore.http_uri,
                custom_ca_cert_path=args.ca_cert,
                verify=args.verify_certs,
                additional_headers={"Authorization": f"{method} {auth_token}"},
            )
        else:
            # No valid credentials found in config file. Start authorization flow
            done_condition = Condition()
            async with AuthServer(get_free_port(), "https://localhost:8900", done_condition) as srv:
                async with done_condition:
                    await done_condition.wait()
                    assert srv.code, "Authorization code not received"
                    result = await fetch_auth_header(resotocore.http_uri, params={"code": srv.code})
                    assert result, "Authorization failed"
                    method, token = result
                    config.set(resotocore.http_uri, "method", method)
                    config.set(resotocore.http_uri, "token", token)
                    config.write()
                    return ResotoClient(
                        url=resotocore.http_uri,
                        custom_ca_cert_path=args.ca_cert,
                        verify=args.verify_certs,
                        additional_headers={"Authorization": f"{method} {token}"},
                    )


async def fetch_auth_header(resotocore_url: str, params: Optional[Dict[str, str]] = None) -> Optional[Tuple[str, str]]:
    async with ClientSession() as session:
        # Call will return data about the user - we are only interested in the Authorization header
        async with session.get(resotocore_url + "/authorization/user", params=params, allow_redirects=False) as resp:
            if resp.status < 300:
                if auth := resp.headers.get("Authorization"):
                    log.debug(f"Received user information:  {await resp.text()}")
                    method, token = auth.split(" ")
                    return method, token
                return None
            raise AccessDeniedError("Access denied")


class ReshConfig:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.config = ConfigParser()
        self.config.read(path)
        self.dirty = False

    def get(self, section: str, option: str) -> Optional[str]:
        return self.config.get(section, option) if self.config.has_option(section, option) else None

    def section(self, section: str) -> MutableMapping[str, str]:
        return self.config[section]

    def set(self, section: str, option: str, value: str) -> None:
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, option, value)
        self.dirty = True

    def valid_credentials(self, host: str) -> Optional[tuple[str, str]]:
        jwt_token = self.get(host, "token")
        method = self.get(host, "method")
        if jwt_token is not None and method is not None:
            # make sure the token is still valid
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            if decoded.get("exp", 0) > time.time():
                return method, jwt_token
        return None

    def write(self) -> None:
        if self.dirty:
            with open(self.path, "w+", encoding="utf-8") as f:
                self.config.write(f)


class AuthServer:
    def __init__(self, port: int, resotocore_url: str, done_condition: Condition) -> None:
        self.port = port
        self.resotocore_url = resotocore_url
        self.done_condition = done_condition
        self.app = web.Application()
        self.app.add_routes([web.route(hdrs.METH_ANY, "/auth", self.handle_auth)])
        self.web_task: Optional[Task[Any]] = None
        self.code: Optional[str] = None

    def print_none(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def __aenter__(self) -> AuthServer:
        self.web_task = asyncio.get_running_loop().create_task(
            web._run_app(self.app, host="0.0.0.0", port=self.port, print=self.print_none)
        )
        params = urlencode({"redirect": f"http://127.0.0.1:{self.port}/auth"})
        webbrowser.open(self.resotocore_url + "/login?" + params, new=1)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.app.shutdown()
        await self.app.cleanup()
        if self.web_task:
            self.web_task.cancel()

    async def handle_auth(self, request: web.Request) -> web.Response:
        self.code = request.query["code"]
        async with self.done_condition:
            self.done_condition.notify_all()
        return web.Response(text="You can close this window now.")
