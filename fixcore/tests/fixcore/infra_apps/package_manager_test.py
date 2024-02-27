from typing import cast, Awaitable, Dict
from fixcore.db.packagedb import PackageEntityDb, app_package_entity_db
from fixcore.infra_apps.package_manager import PackageManager
from fixcore.infra_apps.manifest import AppManifest
from fixcore.ids import InfraAppName
from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.config import ConfigHandler
from fixcore.cli.model import InfraAppAlias
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


config_handler = cast(
    ConfigHandler,
    SimpleNamespace(
        get_config=lambda config_id: async_none(),
        put_config=lambda config_entity, validate: async_none(),
        delete_config=lambda config_id: async_none(),
        update_configs_model=lambda models: async_none(),
        put_config_validation=lambda config_validation: async_none(),
    ),
)


@pytest.mark.asyncio
async def test_install_delete(package_entity_db: PackageEntityDb) -> None:
    name = InfraAppName("cleanup-untagged")
    enabled_aliases: Dict[str, InfraAppAlias] = {}

    def enable_alias(alias: InfraAppAlias) -> None:
        enabled_aliases[alias.name] = alias

    def disable_alias(name: str) -> None:
        enabled_aliases.pop(name)

    package_manager = PackageManager(
        package_entity_db,
        config_handler,
        enable_alias,
        disable_alias,
    )
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
    alias_template = enabled_aliases.get(name)
    assert alias_template is not None
    assert alias_template.name == manifest.name
    assert alias_template.template() == f"apps run {manifest.name}" + r" {{args}}"
    assert alias_template.description == manifest.description
    assert alias_template.readme == manifest.readme

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
    alias_template = enabled_aliases.get(name)
    assert alias_template is None


@pytest.mark.asyncio
async def test_local_install(package_entity_db: PackageEntityDb) -> None:
    name = InfraAppName("cleanup-untagged")
    package_manager = PackageManager(package_entity_db, config_handler, lambda at: None, lambda s: None)
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
