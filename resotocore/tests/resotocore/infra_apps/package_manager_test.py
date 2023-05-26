from typing import cast, Awaitable, Optional
from resotocore.db.packagedb import PackageEntityDb, app_package_entity_db
from resotocore.infra_apps.package_manager import PackageManager
from resotocore.infra_apps.manifest import AppManifest
from resotocore.ids import InfraAppName, ConfigId
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.config import ConfigHandler, ConfigEntity
from resotocore.core_config import ResotoCoreCommandsConfigId
from arango.database import StandardDatabase
from types import SimpleNamespace
import pytest
from asyncio import Future
import aiofiles
import aiohttp
from pathlib import Path


@pytest.fixture
async def package_entity_db(test_db: StandardDatabase) -> PackageEntityDb:
    async_db = AsyncArangoDB(test_db)
    entity_db = app_package_entity_db(async_db, "test_package_entity_db")
    await entity_db.create_update_schema()
    await entity_db.wipe()
    return entity_db


def async_none() -> Awaitable[None]:
    future: Future[None] = Future()
    future.set_result(None)
    return future


config_handler_store = {}


async def patch_config(config_entity: ConfigEntity, validate: bool, dry_run: bool) -> None:
    config_handler_store[config_entity.id] = config_entity
    return None


async def get_config(cfg_id: ConfigId) -> Optional[ConfigEntity]:
    return config_handler_store.get(cfg_id)


config_handler = cast(
    ConfigHandler,
    SimpleNamespace(
        get_config=get_config,
        put_config=lambda config_entity, validate: async_none(),
        patch_config=patch_config,
        delete_config=lambda config_id: async_none(),
        update_configs_model=lambda models: async_none(),
        put_config_validation=lambda config_validation: async_none(),
    ),
)


@pytest.mark.asyncio
async def test_install_delete(package_entity_db: PackageEntityDb) -> None:
    name = InfraAppName("cleanup-untagged")
    package_manager = PackageManager(package_entity_db, config_handler)
    await package_manager.start()

    manifest = await package_manager.install(name, None)
    assert manifest is not None
    assert manifest.name == name

    # check that it is installed
    installed_apps = [name async for name in package_manager.list()]
    assert installed_apps == [name]

    installed_app = await package_manager.get_manifest(name)
    assert installed_app is not None
    assert installed_app.name == name

    # check that the alias is created
    command_config_entity = config_handler_store.get(ResotoCoreCommandsConfigId)
    assert command_config_entity is not None
    command_config = command_config_entity.config.get("custom_commands", {}).get("commands", [None])[0]
    assert command_config is not None
    assert command_config.get("name") == manifest.name
    assert command_config.get("template") == f"apps run {manifest.name}"
    assert command_config.get("info") == manifest.description

    # update is possible
    updated_manifest = await package_manager.update(name)
    assert updated_manifest is not None
    assert updated_manifest.name == name

    # update all is possible
    updated_apps = [name async for name, manifest in package_manager.update_all() if isinstance(manifest, AppManifest)]
    installed_apps = [name async for name in package_manager.list()]
    assert installed_apps == updated_apps == [name]

    # check that it can be deleted
    await package_manager.delete(name)

    # check that it is not installed anymore
    installed_apps_after_deletion = [name async for name in package_manager.list()]
    assert installed_apps_after_deletion == []

    # check that the alias is deleted
    command_config_entity = config_handler_store.get(ResotoCoreCommandsConfigId)
    assert command_config_entity is not None
    commands = command_config_entity.config.get("custom_commands", {}).get("commands", [{}])
    command_config = [command for command in commands if command.get("name") == manifest.name]
    assert len(command_config) == 0


@pytest.mark.asyncio
async def test_local_install(package_entity_db: PackageEntityDb) -> None:
    name = InfraAppName("cleanup-untagged")
    package_manager = PackageManager(package_entity_db, config_handler)
    await package_manager.start()

    # check that the app is not installed
    installed_apps = [name async for name in package_manager.list()]
    assert installed_apps == []

    async with aiohttp.ClientSession() as session:
        async with session.get(package_manager.cdn_url) as response:
            assert response.status == 200
            index_bytes = await response.read()

            async with aiofiles.tempfile.TemporaryDirectory() as tmp:
                index_path = Path(tmp) / "index.json"

                async with aiofiles.open(index_path, "wb") as f:
                    await f.write(index_bytes)

                await package_manager.install(
                    name,
                    "file://" + str(index_path),
                )

    # check that the app is installed
    installed_apps = [name async for name in package_manager.list()]
    assert installed_apps == [name]
