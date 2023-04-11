from typing import AsyncGenerator, Optional, Union, List, Callable
import asyncio
from asyncio import Lock
import subprocess
from pathlib import Path
import aiofiles
from aiofiles import os as aos
from attrs import frozen
import aiohttp
import time
from datetime import timedelta
import shutil
from functools import partial

from async_lru import alru_cache

from resotocore.infra_apps.manifest import AppManifest
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb
from resotocore.config import ConfigHandler
from resotocore.config import ConfigEntity
from resotocore.ids import InfraAppName, ConfigId
from resotocore.model.model import Kind, ComplexKind
from resotocore.model.typed_model import from_js
from logging import getLogger

logger = getLogger(__name__)


@frozen
class FromHttp:
    http_url: str


@frozen
class FromGit:
    git_url: str


InstallationSource = Union[FromHttp, FromGit]


@frozen
class InfraAppPackage:
    manifest: AppManifest
    source: InstallationSource


PackageEntityDb = EntityDb[InfraAppName, InfraAppPackage]


def app_manifest_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[InfraAppName, InfraAppPackage]:
    return ArangoEntityDb(db, collection, InfraAppPackage, lambda k: InfraAppName(k.manifest.name))


def config_id(name: InfraAppName) -> ConfigId:
    return ConfigId(f"resoto/apps/{name}")


class PackageManager:
    def __init__(
        self,
        entity_db: PackageEntityDb,
        config_handler: ConfigHandler,
        repos_directory: Path = Path("/tmp/resoto-package-manager-repos"),
        check_interval: timedelta = timedelta(hours=1),
        cleanup_after: timedelta = timedelta(days=1),
        current_epoch_seconds: Callable[[], float] = time.time,
    ) -> None:
        """
        Package manager for infra apps.

        Args:
            entity_db: EntityDb for storing app manifests
            config_handler: ConfigHandler for storing app configs
            repos_directory: Directory where repos are temporarily cloned
            check_interval: Interval between checks for old repos cleanup
            cleanup_after: Time after which old repos are deleted from cache
        """

        self.entity_db = entity_db
        self.config_handler = config_handler
        self.install_delete_lock: Optional[Lock] = None
        self.update_lock: Optional[Lock] = None
        self.update_all_lock: Optional[Lock] = None
        self.repos_directory: Path = repos_directory
        self.check_interval = check_interval
        self.cleanup_after = cleanup_after
        self.current_epoch_seconds = current_epoch_seconds
        self.cleanup_task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        self.install_delete_lock = asyncio.Lock()
        self.update_lock = asyncio.Lock()
        self.update_all_lock = asyncio.Lock()
        self.cleanup_task = asyncio.create_task(self._cleanup_old_repos())
        self.repos_directory.mkdir(parents=True, exist_ok=True)

    async def stop(self) -> None:
        if self.cleanup_task:
            self.cleanup_task.cancel()
            await self.cleanup_task

    def list(self) -> AsyncGenerator[InfraAppName, None]:
        return self.entity_db.keys()

    async def info(self, name: InfraAppName) -> Optional[AppManifest]:
        if package := await self.entity_db.get(name):
            return package.manifest
        return None

    async def update(self, name: InfraAppName) -> Optional[AppManifest]:
        if not self.update_lock:
            raise RuntimeError("PackageManager not started")

        async with self.update_lock:
            if package := await self.entity_db.get(name):
                await self.delete(package.manifest.name)
                return await self.install(package.manifest.name, package.source)
        return None

    async def update_all(self) -> None:
        if not self.update_all_lock:
            raise RuntimeError("PackageManager not started")

        async with self.update_all_lock:
            async for package in self.entity_db.all():
                await self.update(package.manifest.name)

    async def delete(self, name: InfraAppName) -> bool:
        if not self.install_delete_lock:
            raise RuntimeError("PackageManager not started")

        async with self.install_delete_lock:
            await self.entity_db.delete(name)
            await self.config_handler.delete_config(config_id(name))
            return True

    async def install(self, name: InfraAppName, source: InstallationSource) -> Optional[AppManifest]:
        if not self.install_delete_lock:
            raise RuntimeError("PackageManager not started")

        async with self.install_delete_lock:
            if installed := await self.entity_db.get(name):
                return installed.manifest

            manifest = await self._fetch_manifest(name, source)
            if not manifest:
                return None
            conf_id = config_id(name)
            if schema := manifest.config_schema:
                kinds: List[Kind] = [from_js(kind, ComplexKind) for kind in schema]
                await self.config_handler.update_configs_model(kinds)
            config_entity = ConfigEntity(conf_id, manifest.default_config or {}, None)
            try:
                await self.config_handler.put_config(config_entity, validate=manifest.config_schema is not None)
                stored = await self.entity_db.update(InfraAppPackage(manifest, source))
                return stored.manifest
            except Exception as e:
                logger.error(f"Failed to install {name} from {source}", exc_info=e)
                return None

    async def _fetch_manifest(self, app_name: str, source: InstallationSource) -> Optional[AppManifest]:
        if isinstance(source, FromHttp):
            return await self._http_download(source.http_url)
        elif isinstance(source, FromGit):
            return await self._read_from_git(source.git_url, app_name)
        else:
            raise ValueError(f"Unknown source type: {type(source)}")

    async def _read_from_git(self, repo_url: str, app_name: str) -> Optional[AppManifest]:
        try:
            repo_dir = await self._git_clone(repo_url)
            if not repo_dir:
                return None
            manifest_path = Path(repo_dir) / f"{app_name}.json"
            async with aiofiles.open(manifest_path, "r") as f:
                manifest = AppManifest.from_json_str(await f.read())

            return manifest
        except Exception as e:
            logger.error(f"Failed to fetch manifest for {app_name} from git repo {repo_url}", exc_info=e)
            return None

    @alru_cache(maxsize=128, ttl=600)
    async def _git_clone(self, repo_url: str) -> Optional[Path]:
        suffix = "-" + "-".join(repo_url.split("/")[-2:])
        suffix = suffix.replace(".git", "")
        try:
            # pylint: disable=unnecessary-dunder-call
            tmpdir = await aiofiles.tempfile.TemporaryDirectory(suffix=suffix, dir=self.repos_directory).__aenter__()
            await asyncio.to_thread(
                lambda: subprocess.run(
                    ["git", "clone", repo_url, tmpdir],
                    check=True,
                )
            )
            return Path(tmpdir)
        except Exception as e:
            logger.error(f"Failed to clone git repo {repo_url}", exc_info=e)
            return None

    async def _http_download(self, url: str) -> Optional[AppManifest]:
        try:
            async with aiohttp.ClientSession() as session:
                logger.debug(f"Fetching: {url}")
                async with session.get(url) as response:
                    logger.debug(f"Status: {response.status}")
                    if response.status != 200:
                        raise RuntimeError(f"Failed to fetch {url}")
                    manifest_bytes = await response.read()
                    manifest = AppManifest.from_bytes(manifest_bytes)
                    return manifest
        except Exception as e:
            logger.error(f"Failed to fetch manifest from {url}", exc_info=e)
            return None

    async def _cleanup_old_repos(self) -> None:
        while True:
            await asyncio.sleep(self.check_interval.seconds)
            try:
                for path in await aos.listdir(self.repos_directory):  # type: ignore
                    path = self.repos_directory / path
                    if await aos.path.isdir(path):
                        mtime = await aos.path.getmtime(path)
                        if (self.current_epoch_seconds() - mtime) > self.cleanup_after.seconds:
                            logger.debug(f"Cleaning up old repo {path}")
                            await asyncio.to_thread(partial(shutil.rmtree, path))
            except Exception as e:
                logger.error("Failed to cleanup old repos", exc_info=e)
