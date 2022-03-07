import pytest
from arango.database import StandardDatabase
from typing import List

from resotocore.config import ConfigEntity
from resotocore.db import configdb
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.configdb import ConfigEntityDb

# noinspection PyUnresolvedReferences
from tests.resotocore.task.task_description_test import workflow_instance, test_workflow

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
def instances() -> List[ConfigEntity]:
    return [ConfigEntity(f"id_{a}", {"some": a, "config": "test"}) for a in range(0, 10)]


@pytest.mark.asyncio
async def test_load(config_db: ConfigEntityDb, instances: List[ConfigEntity]) -> None:
    await config_db.update_many(instances)
    loaded = [sub async for sub in config_db.all()]
    assert instances.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_update(config_db: ConfigEntityDb, instances: List[ConfigEntity]) -> None:
    # multiple updates should work as expected
    await config_db.update_many(instances)
    await config_db.update_many(instances)
    await config_db.update_many(instances)
    loaded = [sub async for sub in config_db.all()]
    assert instances.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_delete(config_db: ConfigEntityDb, instances: List[ConfigEntity]) -> None:
    await config_db.update_many(instances)
    remaining = list(instances)
    for _ in instances:
        sub = remaining.pop()
        await config_db.delete(sub)
        loaded = [sub async for sub in config_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in config_db.all()]) == 0


@pytest.mark.asyncio
async def test_keys(config_db: ConfigEntityDb, instances: List[ConfigEntity]) -> None:
    assert [key async for key in config_db.keys()] == []
    await config_db.update_many(instances)
    assert [key async for key in config_db.keys()] == [a.id for a in instances]
