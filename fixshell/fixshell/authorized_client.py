from __future__ import annotations

import asyncio
import os
import time
import webbrowser
from argparse import Namespace
from asyncio import Task, Condition
from configparser import ConfigParser
from datetime import timedelta
from pathlib import Path
from ssl import SSLContext
from typing import Any, Optional, Tuple, Dict, MutableMapping
from urllib.parse import urlencode

import jwt
from aiohttp import web, hdrs, ClientSession
from fixclient.async_client import FixInventoryClient
from fixclient.ca import CertificatesHolder

from fixlib.core import fixcore
from fixlib.logger import log
from fixlib.utils import get_free_port


class AccessDeniedError(Exception):
    pass


async def new_client(args: Namespace) -> FixInventoryClient:
    headers = dict(args.add_headers)
    # if a PSK was defined on the command line, use it
    if args.psk:
        return FixInventoryClient(
            url=fixcore.http_uri,
            psk=args.psk,
            custom_ca_cert_path=args.ca_cert,
            verify=args.verify_certs,
            additional_headers=headers,
        )

    # fetch ssl certificate
    ssl = await CertificatesHolder(fixcore.http_uri, args.psk, args.ca_cert, timedelta(days=1)).ssl_context()
    # No PSK defined. Do we need to authorize?
    try:
        await fetch_auth_header(fixcore.http_uri, ssl=ssl)
        # no authorization required
        return FixInventoryClient(
            url=fixcore.http_uri,
            custom_ca_cert_path=args.ca_cert,
            verify=args.verify_certs,
            additional_headers=headers,
        )
    except AccessDeniedError:
        config = ReshConfig.default()
        if creds := config.valid_credentials(fixcore.http_uri):
            # Valid credentials found in config file
            method, auth_token = creds
            return FixInventoryClient(
                url=fixcore.http_uri,
                custom_ca_cert_path=args.ca_cert,
                verify=args.verify_certs,
                additional_headers={**headers, "Authorization": f"{method} {auth_token}"},
            )
        else:
            # No valid credentials found in config file. Start authorization flow
            done_condition = Condition()
            async with AuthServer(get_free_port(), fixcore.http_uri, done_condition) as srv:
                async with done_condition:
                    await done_condition.wait()
                    assert srv.code, "Authorization code not received"
                    result = await fetch_auth_header(fixcore.http_uri, ssl=ssl, params={"code": srv.code})
                    assert result, "Authorization failed"
                    method, token = result
                    config.update_auth(fixcore.http_uri, method, token)
                    return FixInventoryClient(
                        url=fixcore.http_uri,
                        custom_ca_cert_path=args.ca_cert,
                        verify=args.verify_certs,
                        additional_headers={**headers, "Authorization": f"{method} {token}"},
                    )


async def update_auth_header(client: FixInventoryClient) -> None:
    if auth := client.http_client.additional_headers.get("Authorization"):
        method, token = auth.split(" ", maxsplit=1)
        ReshConfig.default().update_auth(client.http_client.url, method, token)


async def fetch_auth_header(
    fixcore_url: str, ssl: SSLContext, params: Optional[Dict[str, str]] = None
) -> Optional[Tuple[str, str]]:
    async with ClientSession() as session:
        # Call will return data about the user - we are only interested in the Authorization header
        async with session.get(
            fixcore_url + "/authorization/user", params=params, allow_redirects=False, ssl=ssl
        ) as resp:
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

    def update_auth(self, host: str, method: str, token: str) -> None:
        self.set(host, "method", method)
        self.set(host, "token", token)
        self.write()

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
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with open(os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "w+", encoding="utf-8") as f:
                self.config.write(f)

    @staticmethod
    def default() -> ReshConfig:
        return ReshConfig(Path.home() / ".fix" / "resh.ini")


class AuthServer:
    def __init__(self, port: int, fixcore_url: str, done_condition: Condition) -> None:
        self.port = port
        self.fixcore_url = fixcore_url
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
        webbrowser.open(self.fixcore_url + "/login?" + params, new=1)
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
