from typing import AsyncIterator, Optional, List, Dict, Union, Tuple, Callable
import asyncio
from asyncio import Lock
from pathlib import Path
import aiohttp
import aiofiles
from collections import defaultdict
from abc import ABC
from attrs import frozen
from jsons import loads as json_loads

from fixcore.infra_apps.manifest import AppManifest
from fixcore.db.packagedb import PackageEntityDb, InfraAppPackage
from fixcore.config import ConfigHandler
from fixcore.config import ConfigEntity
from fixcore.ids import InfraAppName, ConfigId
from fixcore.model.model import Kind, ComplexKind
from fixcore.types import Json
from fixcore.model.typed_model import from_js
from fixcore.cli.model import InfraAppAlias, InfraAppAliasParameter
from logging import getLogger
from fixcore.service import Service

logger = getLogger(__name__)


def config_id(name: InfraAppName) -> ConfigId:
    return ConfigId(f"fix.apps.{name}")


class Failure(ABC):
    def __nonzero__(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


@frozen
class ManifestNotFound(Failure):
    name: InfraAppName

    def __str__(self) -> str:
        return f"Manifest for app {self.name} was not found."


@frozen
class ManifestDownloadFailed(Failure):
    url: str
    reason: str

    def __str__(self) -> str:
        return f"Failed to download app manifest from {self.url}: {self.reason}"


@frozen
class ManifestInstallFailed(Failure):
    name: InfraAppName
    reason: str

    def __str__(self) -> str:
        return f"Failed to install app {self.name} from manifest. Reason: {self.reason}"


class PackageManager(Service):
    def __init__(
        self,
        entity_db: PackageEntityDb,
        config_handler: ConfigHandler,
        add_command_alias: Callable[[InfraAppAlias], None],
        remove_command_alias: Callable[[str], None],
        repos_cache_directory: Path = Path.home() / ".cache" / "fix-infra-apps",
    ) -> None:
        """
        Package manager for infra apps.

        Args:
            entity_db: EntityDb for storing app manifests
            config_handler: ConfigHandler for storing app configs
            repos_cache_directory: Directory where the infra apps repos are cloned
        """

        super().__init__()
        self.entity_db = entity_db
        self.config_handler = config_handler
        self.update_lock: Optional[Lock] = None
        self.repos_cache_directory: Path = repos_cache_directory
        self.cleanup_task: Optional[asyncio.Task[None]] = None
        self.cdn_url = "https://cdn.some.engineering/fixinventory/apps/index.json"
        self.add_command_alias = add_command_alias
        self.remove_command_alias = remove_command_alias

    async def start(self) -> None:
        self.update_lock = asyncio.Lock()
        self.repos_cache_directory.mkdir(parents=True, exist_ok=True)

        # set up custom commands
        manifests = [await self.get_manifest(name) async for name in self.list()]
        self._setup_command_aliases([m for m in manifests if m is not None])

    def _setup_command_aliases(self, manifests: List[AppManifest]) -> None:
        for manifest in manifests:

            def to_param(arg: Tuple[str, Json]) -> InfraAppAliasParameter:
                name, arg_schema = arg
                return InfraAppAliasParameter(
                    name=name,
                    help=arg_schema.get("help", ""),
                    default=arg_schema.get("default", None),
                )

            parameters = [to_param(arg) for arg in (manifest.args_schema or {}).items()]
            alias_template = InfraAppAlias(
                name=manifest.name,
                description=manifest.description,
                readme=manifest.readme,
                parameters=parameters,
            )
            self.add_command_alias(alias_template)

    async def stop(self) -> None:
        if self.cleanup_task:
            self.cleanup_task.cancel()
            await self.cleanup_task

    async def search(self, query: Optional[str], url: Optional[str]) -> AsyncIterator[AppManifest]:
        maybe_available_manifests = await self._get_manifests(url)
        if isinstance(maybe_available_manifests, Failure):
            raise RuntimeError(str(maybe_available_manifests))
        available_manifests = maybe_available_manifests.values()
        if query is None:
            for manifest in available_manifests:
                yield manifest
        else:
            query = query.lower()
            for manifest in available_manifests:
                if query in manifest.name.lower():
                    yield manifest
                    continue
                if query in manifest.description.lower():
                    yield manifest
                    continue
                if query in manifest.readme.lower():
                    yield manifest
                    continue
                if query in manifest.categories:
                    yield manifest
                    continue

    def list(self) -> AsyncIterator[InfraAppName]:
        return self.entity_db.keys()

    async def get_manifest(self, name: InfraAppName) -> Optional[AppManifest]:
        if package := await self.entity_db.get(name):
            return package.manifest
        return None

    async def info(self, name: InfraAppName, url: Optional[str]) -> Json:
        async def get_manifest() -> AppManifest:
            if package := await self.entity_db.get(name):
                return package.manifest
            else:
                result = await self._fetch_manifest(name, url or self.cdn_url)
                if isinstance(result, Failure):
                    raise ValueError(f"Can't find the package {name}, reason: {result}")
                return result

        manifest = await get_manifest()
        json = {
            "name": manifest.name,
            "description": manifest.description,
            "url": manifest.url,
            "version": manifest.version,
        }
        return json

    async def update(self, name: InfraAppName) -> AppManifest:
        assert self.update_lock, "PackageManager not started"

        async with self.update_lock:
            if package := await self.entity_db.get(name):
                new_manifest = await self._fetch_manifest(name, package.source_url)
                if isinstance(new_manifest, Failure):
                    logger.warning(f"Failed to fetch manifest for app {name}, skipping update")
                    raise RuntimeError(str(new_manifest))

                await self._delete(package.manifest.name)
                result = await self._install_from_manifest(new_manifest, package.source_url)
                if isinstance(result, Failure):
                    logger.warning(f"Failed to install app {name} from manifest, skipping update")
                    raise RuntimeError(str(result))
                return result
            else:
                raise RuntimeError(f"App {name} is not installed, cannot update")

    async def update_from_manifest(self, manifest: AppManifest) -> AppManifest:
        assert self.update_lock, "PackageManager not started"

        async with self.update_lock:
            if package := await self.entity_db.get(manifest.name):
                await self._delete(package.manifest.name)
                result = await self._install_from_manifest(manifest, package.source_url)
                if isinstance(result, Failure):
                    logger.warning(f"Failed to install app {manifest.name} from manifest, skipping update")
                    raise RuntimeError(str(result))
                return result
            else:
                raise RuntimeError(f"App {manifest.name} is not installed, cannot update")

    async def update_all(self) -> AsyncIterator[Tuple[InfraAppName, Union[AppManifest, Failure]]]:
        assert self.update_lock, "PackageManager not started"

        async with self.update_lock:
            packages: Dict[str, List[AppManifest]] = defaultdict(list)
            async for package in self.entity_db.all():
                packages[package.source_url].append(package.manifest)

            for url, manifests in packages.items():
                manifests_cache = await self._get_manifests(url)
                if isinstance(manifests_cache, Failure):
                    logger.warning(f"Failed to download manifests for url {url}, skipping update")
                    continue
                for manifest in manifests:
                    new_manifest = manifests_cache.get(manifest.name, ManifestNotFound(manifest.name))
                    if isinstance(new_manifest, Failure):
                        logger.warning(f"Failed to download manifest for app {manifest.name}, skipping update")
                        yield (manifest.name, new_manifest)
                        continue
                    await self._delete(manifest.name)
                    await self._install_from_manifest(new_manifest, url)
                    yield (manifest.name, new_manifest)

    async def delete(self, name: InfraAppName) -> None:
        assert self.update_lock, "PackageManager not started"
        async with self.update_lock:
            await self._delete(name)

    async def _delete(self, name: InfraAppName) -> None:
        if await self.entity_db.get(name) is None:
            return
        await self.entity_db.delete(name)
        # clean up the aliases
        self.remove_command_alias(name)

    # user-facing method, errors are thrown as exceptions
    async def install(self, name: InfraAppName, url: Optional[str]) -> AppManifest:
        assert self.update_lock, "PackageManager not started"

        async with self.update_lock:
            if installed := await self.entity_db.get(name):
                return installed.manifest

            manifest = await self._fetch_manifest(name, url or self.cdn_url)
            if isinstance(manifest, Failure):
                raise RuntimeError(str(manifest))
            result = await self._install_from_manifest(manifest, url or self.cdn_url)
            if isinstance(result, Failure):
                raise RuntimeError(str(result))
            return result

    async def _install_from_manifest(
        self, manifest: AppManifest, url: str
    ) -> Union[ManifestInstallFailed, AppManifest]:
        conf_id = config_id(manifest.name)
        if schema := manifest.config_schema:
            kinds: List[Kind] = [from_js(kind, ComplexKind) for kind in schema]
            await self.config_handler.update_configs_model(kinds)
        config_entity = ConfigEntity(conf_id, manifest.default_config or {}, None)
        try:
            if await self.config_handler.get_config(conf_id) is None:
                await self.config_handler.put_config(config_entity, validate=manifest.config_schema is not None)
            stored = await self.entity_db.update(InfraAppPackage(manifest, url))

            # add the custom command alias
            self._setup_command_aliases([manifest])

            return stored.manifest
        except Exception as e:
            logger.error(f"Failed to install {manifest.name} from {url}", exc_info=e)
            return ManifestInstallFailed(manifest.name, str(e))

    async def _fetch_manifest(self, app_name: InfraAppName, url: str) -> Union[Failure, AppManifest]:
        url = url or self.cdn_url
        manifests = await self._get_manifests(url)
        if isinstance(manifests, Failure):
            return manifests
        return manifests.get(app_name, ManifestNotFound(app_name))

    async def _get_manifests(self, url: Optional[str]) -> Union[Failure, Dict[InfraAppName, AppManifest]]:
        url = url or self.cdn_url
        if url.startswith("file://"):
            path = Path(url[7:])
            return await self._get_manifests_from_file(path)
        else:
            return await self._get_manifests_from_cdn(url)

    async def _get_manifests_from_cdn(self, url: str) -> Union[Failure, Dict[InfraAppName, AppManifest]]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        raise RuntimeError(f"Failed to fetch {self.cdn_url}")
                    manifests_bytes = await response.read()
                    json = json_loads(manifests_bytes.decode())
                    assert isinstance(json, list)
                    manifests: Dict[InfraAppName, AppManifest] = {}
                    for manifest_json in json:
                        manifest = AppManifest.from_json(manifest_json)
                        manifests[manifest.name] = manifest
                    return manifests
        except Exception as e:
            logger.error(f"Failed to fetch manifests from {self.cdn_url}", exc_info=e)
            return ManifestDownloadFailed(url, str(e))

    async def _get_manifests_from_file(self, path: Path) -> Union[Failure, Dict[InfraAppName, AppManifest]]:
        try:
            async with aiofiles.open(path) as f:
                manifests_bytes = await f.read()
                json = json_loads(manifests_bytes)
                assert isinstance(json, list)
                manifests: Dict[InfraAppName, AppManifest] = {}
                for manifest_json in json:
                    manifest = AppManifest.from_json(manifest_json)
                    manifests[manifest.name] = manifest
                return manifests
        except Exception as e:
            logger.error(f"Failed to fetch manifests from {path}", exc_info=e)
            return ManifestDownloadFailed(str(path.absolute()), str(e))
