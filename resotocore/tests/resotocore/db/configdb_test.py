import pytest
from arango.database import StandardDatabase
from typing import List

from resotocore.config import ConfigEntity, ConfigModel
from resotocore.db import configdb
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.configdb import ConfigEntityDb, ConfigModelEntityDb

# noinspection PyUnresolvedReferences
from resotocore.model.model import ComplexKind, Property

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import test_db, local_client, system_db

# noinspection PyUnresolvedReferences
from tests.resotocore.message_bus_test import message_bus, all_events


@pytest.fixture
async def config_db(test_db: StandardDatabase) -> ConfigEntityDb:
    async_db = AsyncArangoDB(test_db)
    cfg_db = configdb.config_entity_db(async_db, "configs")
    await cfg_db.create_update_schema()
    await cfg_db.wipe()
    return cfg_db


@pytest.fixture
async def model_db(test_db: StandardDatabase) -> ConfigModelEntityDb:
    async_db = AsyncArangoDB(test_db)
    cfg_db = configdb.config_model_entity_db(async_db, "config_models")
    await cfg_db.create_update_schema()
    await cfg_db.wipe()
    return cfg_db


@pytest.fixture
def configs() -> List[ConfigEntity]:
    return [ConfigEntity(f"id_{a}", {"some": a, "config": "test"}) for a in range(0, 10)]


@pytest.fixture
def config_models() -> List[ConfigModel]:
    kind = ComplexKind("test", [], [Property("foo", "string")])
    return [ConfigModel(f"id_{a}", [kind]) for a in range(0, 10)]


@pytest.mark.asyncio
async def test_load(config_db: ConfigEntityDb, configs: List[ConfigEntity]) -> None:
    await config_db.update_many(configs)
    loaded = [sub async for sub in config_db.all()]
    assert configs.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_update(config_db: ConfigEntityDb, configs: List[ConfigEntity]) -> None:
    # multiple updates should work as expected
    await config_db.update_many(configs)
    await config_db.update_many(configs)
    await config_db.update_many(configs)
    loaded = [sub async for sub in config_db.all()]
    assert configs.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_delete(config_db: ConfigEntityDb, configs: List[ConfigEntity]) -> None:
    await config_db.update_many(configs)
    remaining = list(configs)
    for _ in configs:
        sub = remaining.pop()
        await config_db.delete(sub)
        loaded = [sub async for sub in config_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in config_db.all()]) == 0


@pytest.mark.asyncio
async def test_keys(config_db: ConfigEntityDb, configs: List[ConfigEntity]) -> None:
    assert [key async for key in config_db.keys()] == []
    await config_db.update_many(configs)
    assert [key async for key in config_db.keys()] == [a.id for a in configs]


@pytest.mark.asyncio
async def test_load_model(model_db: ConfigModelEntityDb, config_models: List[ConfigModel]) -> None:
    await model_db.update_many(config_models)
    loaded = [sub async for sub in model_db.all()]
    assert config_models.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_update_model(model_db: ConfigModelEntityDb, config_models: List[ConfigModel]) -> None:
    # multiple updates should work as expected
    await model_db.update_many(config_models)
    await model_db.update_many(config_models)
    await model_db.update_many(config_models)
    loaded = [sub async for sub in model_db.all()]
    assert config_models.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_delete_model(model_db: ConfigModelEntityDb, config_models: List[ConfigModel]) -> None:
    await model_db.update_many(config_models)
    remaining = list(config_models)
    for _ in config_models:
        sub = remaining.pop()
        await model_db.delete(sub)
        loaded = [sub async for sub in model_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in model_db.all()]) == 0


@pytest.mark.asyncio
async def test_keys_model(model_db: ConfigModelEntityDb, config_models: List[ConfigModel]) -> None:
    assert [key async for key in model_db.keys()] == []
    await model_db.update_many(config_models)
    assert [key async for key in model_db.keys()] == [a.id for a in config_models]
