from typing import cast, Awaitable
from resotocore.db.packagedb import PackageEntityDb, app_package_entity_db
from resotocore.infra_apps.package_manager import PackageManager
from resotocore.infra_apps.manifest import AppManifest
from resotocore.ids import InfraAppName
from resotocore.db.async_arangodb import AsyncArangoDB
from arango.database import StandardDatabase
from types import SimpleNamespace
from resotocore.config import ConfigHandler
import pytest
from asyncio import Future


@pytest.fixture
async def model_db(test_db: StandardDatabase) -> PackageEntityDb:
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
        put_config=lambda config_entity, validate: async_none(),
        delete_config=lambda config_id: async_none(),
        update_configs_model=lambda models: async_none(),
        put_config_validation=lambda config_validation: async_none(),
    ),
)


@pytest.mark.asyncio
async def test_install_delete(model_db: PackageEntityDb) -> None:
    name = InfraAppName("cleanup-untagged")
    package_manager = PackageManager(model_db, config_handler)
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
