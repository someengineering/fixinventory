from typing import List

import pytest
from arango.database import StandardDatabase

from fixcore.config import ConfigEntity, ConfigValidation
from fixcore.db import configdb
from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.db.configdb import ConfigEntityDb, ConfigValidationEntityDb
from fixcore.ids import ConfigId


@pytest.fixture
async def config_db(test_db: StandardDatabase) -> ConfigEntityDb:
    async_db = AsyncArangoDB(test_db)
    cfg_db = configdb.config_entity_db(async_db, "configs")
    await cfg_db.create_update_schema()
    await cfg_db.wipe()
    return cfg_db


@pytest.fixture
async def validation_db(test_db: StandardDatabase) -> ConfigValidationEntityDb:
    async_db = AsyncArangoDB(test_db)
    cfg_db = configdb.config_validation_entity_db(async_db, "config_models")
    await cfg_db.create_update_schema()
    await cfg_db.wipe()
    return cfg_db


@pytest.fixture
def configs() -> List[ConfigEntity]:
    return [ConfigEntity(ConfigId(f"id_{a}"), {"some": a, "config": "test"}) for a in range(0, 10)]


@pytest.fixture
def config_models() -> List[ConfigValidation]:
    return [ConfigValidation(f"id_{a}", True) for a in range(0, 10)]


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
        await config_db.delete_value(sub)
        loaded = [sub async for sub in config_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in config_db.all()]) == 0


@pytest.mark.asyncio
async def test_keys(config_db: ConfigEntityDb, configs: List[ConfigEntity]) -> None:
    assert [key async for key in config_db.keys()] == []
    await config_db.update_many(configs)
    assert [key async for key in config_db.keys()] == [a.id for a in configs]


@pytest.mark.asyncio
async def test_load_model(validation_db: ConfigValidationEntityDb, config_models: List[ConfigValidation]) -> None:
    await validation_db.update_many(config_models)
    loaded = [sub async for sub in validation_db.all()]
    assert config_models.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_update_model(validation_db: ConfigValidationEntityDb, config_models: List[ConfigValidation]) -> None:
    # multiple updates should work as expected
    await validation_db.update_many(config_models)
    await validation_db.update_many(config_models)
    await validation_db.update_many(config_models)
    loaded = [sub async for sub in validation_db.all()]
    assert config_models.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_delete_model(validation_db: ConfigValidationEntityDb, config_models: List[ConfigValidation]) -> None:
    await validation_db.update_many(config_models)
    remaining = list(config_models)
    for _ in config_models:
        sub = remaining.pop()
        await validation_db.delete_value(sub)
        loaded = [sub async for sub in validation_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in validation_db.all()]) == 0


@pytest.mark.asyncio
async def test_keys_model(validation_db: ConfigValidationEntityDb, config_models: List[ConfigValidation]) -> None:
    assert [key async for key in validation_db.keys()] == []
    await validation_db.update_many(config_models)
    assert [key async for key in validation_db.keys()] == [a.id for a in config_models]
