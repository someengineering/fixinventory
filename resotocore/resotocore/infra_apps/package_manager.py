from typing import AsyncGenerator, Optional, Union, List
import asyncio
import subprocess
from pathlib import Path
import aiofiles
from attrs import frozen
import aiohttp

from resotocore.infra_apps.manifest import AppManifest
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb
from resotocore.config import ConfigHandler
from resotocore.config import ConfigEntity, ConfigValidation
from resotocore.ids import InfraAppName, ConfigId
from resotocore.model.model import Kind, ComplexKind
from resotocore.model.typed_model import from_js
from logging import getLogger

logger = getLogger(__name__)


AppManifestEntityDb = EntityDb[InfraAppName, AppManifest]


def app_manifest_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[InfraAppName, AppManifest]:
    return ArangoEntityDb(db, collection, AppManifest, lambda k: InfraAppName(k.name))


def config_id(name: InfraAppName) -> ConfigId:
    return ConfigId(f"resoto/apps/{name}")


@frozen
class FromHttp:
    url: str


@frozen
class FromGit:
    url: str


InstallationSource = Union[FromHttp, FromGit]


class PackageManager:
    def __init__(
        self,
        entity_db: AppManifestEntityDb,
        config_handler: ConfigHandler,
    ) -> None:
        self.entity_db = entity_db
        self.config_handler = config_handler

    def list(self) -> AsyncGenerator[InfraAppName, None]:
        return self.entity_db.keys()

    async def info(self, name: InfraAppName) -> Optional[AppManifest]:
        return await self.entity_db.get(name)

    async def update(self, manifest: AppManifest) -> AppManifest:
        return await self.entity_db.update(manifest)

    async def delete(self, name: InfraAppName) -> bool:
        await self.entity_db.delete(name)
        await self.config_handler.delete_config(config_id(name))
        return True

    async def install(self, name: InfraAppName, source: InstallationSource) -> Optional[AppManifest]:
        if manifest := await self.entity_db.get(name):
            return manifest

        manifest = await self._fetch_manifest(name, source)
        if not manifest:
            return None
        conf_id = config_id(name)
        validate = False
        if schema := manifest.config_schema:
            validate = True
            kinds: List[Kind] = [from_js(kind, ComplexKind) for kind in schema]
            await self.config_handler.update_configs_model(kinds)
            await self.config_handler.put_config_validation(ConfigValidation(conf_id, external_validation=False))
        config_entity = ConfigEntity(conf_id, manifest.default_config or {}, None)
        try:
            await self.config_handler.put_config(config_entity, validate=validate)
            return await self.entity_db.update(manifest)
        except Exception as e:
            logger.error(f"Failed to install {name} from {source}", exc_info=e)
            return None

    async def _fetch_manifest(self, app_name: str, source: InstallationSource) -> Optional[AppManifest]:
        if isinstance(source, FromHttp):
            return await self._http_download(source.url)
        elif isinstance(source, FromGit):
            return await self._git_clone(source.url, app_name)
        else:
            raise ValueError(f"Unknown source type: {type(source)}")

    async def _git_clone(self, repo_url: str, app_name: str) -> Optional[AppManifest]:
        try:
            async with aiofiles.tempfile.TemporaryDirectory() as tmpdir:
                await asyncio.to_thread(
                    lambda: subprocess.run(
                        ["git", "clone", repo_url, tmpdir],
                        check=True,
                    )
                )
                manifest_path = Path(tmpdir) / f"{app_name}.json"
                async with aiofiles.open(manifest_path, "r") as f:
                    manifest = AppManifest.from_json_str(await f.read())

                return manifest
        except Exception as e:
            logger.error(f"Failed to fetch manifest for {app_name} from git repo {repo_url}", exc_info=e)
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
