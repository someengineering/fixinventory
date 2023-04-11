from typing import AsyncGenerator, Optional, Union, List, Callable, Dict
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
import hashlib
from collections import defaultdict

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
        repos_cache_directory: Path = Path("~/.cache/resoto-package-manager"),
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
        self.update_lock: Optional[Lock] = None
        self.repos_cache_directory: Path = repos_cache_directory
        self.check_interval = check_interval
        self.cleanup_after = cleanup_after
        self.current_epoch_seconds = current_epoch_seconds
        self.cleanup_task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        self.update_lock = asyncio.Lock()
        self.repos_cache_directory.mkdir(parents=True, exist_ok=True)

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
                new_manifest = await self._fetch_manifest(name, package.source)
                if not new_manifest:
                    logger.warning(f"Failed to fetch manifest for app {name}, skipping update")
                    return None

                await self._delete(package.manifest.name)
                return await self._install_from_manifest(new_manifest, package.source)
        return None

    async def update_all(self) -> None:
        if not self.update_lock:
            raise RuntimeError("PackageManager not started")

        async with self.update_lock:
            packages: Dict[InstallationSource, List[AppManifest]] = defaultdict(list)
            async for package in self.entity_db.all():
                packages[package.source].append(package.manifest)

            for source, manifests in packages.items():
                if isinstance(source, FromGit):
                    repo_dir = await self._get_latest_git_repo(source.git_url)
                    if not repo_dir:
                        logger.warning(f"Failed to fetch git repo {source.git_url}, skipping update")
                        continue

                    for manifest in manifests:
                        new_manifest = await self._read_manifest_from_git_repo(repo_dir, manifest.name)
                        if not new_manifest:
                            logger.warning(
                                f"Failed to read manifest {manifest.name} from "
                                "git repo {source.git_url}, skipping update"
                            )
                            continue
                        await self._delete(manifest.name)
                        await self._install_from_manifest(new_manifest, source)

                elif isinstance(source, FromHttp):
                    for manifest in manifests:
                        new_manifest = await self._download_manifest(source.http_url)
                        if not new_manifest:
                            logger.warning(f"Failed to download manifest for app {manifest.name}, skipping update")
                            continue
                        await self._delete(manifest.name)
                        await self._install_from_manifest(new_manifest, source)
                else:
                    raise NotImplementedError(f"Updating from {source} not implemented")

    async def delete(self, name: InfraAppName) -> None:
        if not self.update_lock:
            raise RuntimeError("PackageManager not started")
        async with self.update_lock:
            await self._delete(name)

    async def _delete(self, name: InfraAppName) -> None:
        await self.entity_db.delete(name)
        await self.config_handler.delete_config(config_id(name))

    async def install(self, name: InfraAppName, source: InstallationSource) -> Optional[AppManifest]:
        if not self.update_lock:
            raise RuntimeError("PackageManager not started")

        async with self.update_lock:
            if installed := await self.entity_db.get(name):
                return installed.manifest

            manifest = await self._fetch_manifest(name, source)
            if not manifest:
                return None
            return await self._install_from_manifest(manifest, source)

    async def _install_from_manifest(self, manifest: AppManifest, source: InstallationSource) -> Optional[AppManifest]:
        conf_id = config_id(manifest.name)
        if schema := manifest.config_schema:
            kinds: List[Kind] = [from_js(kind, ComplexKind) for kind in schema]
            await self.config_handler.update_configs_model(kinds)
        config_entity = ConfigEntity(conf_id, manifest.default_config or {}, None)
        try:
            await self.config_handler.put_config(config_entity, validate=manifest.config_schema is not None)
            stored = await self.entity_db.update(InfraAppPackage(manifest, source))
            return stored.manifest
        except Exception as e:
            logger.error(f"Failed to install {manifest.name} from {source}", exc_info=e)
            return None

    async def _fetch_manifest(self, app_name: str, source: InstallationSource) -> Optional[AppManifest]:
        if isinstance(source, FromHttp):
            return await self._download_manifest(source.http_url)
        elif isinstance(source, FromGit):
            repo_dir = await self._get_latest_git_repo(source.git_url)
            if not repo_dir:
                return None

            return await self._read_manifest_from_git_repo(repo_dir, app_name)
        else:
            raise ValueError(f"Unknown source type: {type(source)}")

    async def _read_manifest_from_git_repo(self, repo_dir: Path, app_name: str) -> Optional[AppManifest]:
        try:
            manifest_path = repo_dir / f"{app_name}.json"
            async with aiofiles.open(manifest_path, "r") as f:
                manifest = AppManifest.from_json_str(await f.read())

            return manifest
        except Exception as e:
            logger.error(f"Failed to read manifest for {app_name} from directory {repo_dir}", exc_info=e)
            return None

    async def _get_latest_git_repo(self, repo_url: str) -> Optional[Path]:
        url_hash = hashlib.sha256(repo_url.encode()).hexdigest()

        repo_dir = self.repos_cache_directory / url_hash

        if await aos.path.exists(repo_dir):
            # try to pull
            if not await self._git_pull(repo_dir):  # pull failed, delete and clone
                await asyncio.to_thread(lambda: shutil.rmtree(repo_dir))
                return await self._git_clone(repo_url, repo_dir)
            else:  # pull succeeded
                return repo_dir
        else:
            return await self._git_clone(repo_url, repo_dir)

    async def _git_pull(self, repo_dir: Path) -> Optional[Path]:
        try:
            await asyncio.to_thread(
                lambda: subprocess.run(
                    ["git", "pull"],
                    cwd=repo_dir,
                    check=True,
                )
            )
            return repo_dir
        except Exception as e:
            logger.error(f"Failed to pull git repo {repo_dir}", exc_info=e)
            return None

    async def _git_clone(self, repo_url: str, repo_dir: Path) -> Optional[Path]:
        try:
            await asyncio.to_thread(
                lambda: subprocess.run(
                    ["git", "clone", repo_url, repo_dir],
                    check=True,
                )
            )
            return repo_dir
        except Exception as e:
            logger.error(f"Failed to clone git repo {repo_url}", exc_info=e)
            return None

    async def _download_manifest(self, url: str) -> Optional[AppManifest]:
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
