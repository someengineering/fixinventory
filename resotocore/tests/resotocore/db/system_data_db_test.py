import pytest
from arango.database import StandardDatabase

from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.system_data_db import SystemDataDb


@pytest.fixture
async def system_data_db(test_db: StandardDatabase) -> SystemDataDb:
    async_db = AsyncArangoDB(test_db)
    return SystemDataDb(async_db)


@pytest.mark.asyncio
async def test_system_info(system_data_db: SystemDataDb) -> None:
    assert await system_data_db.info() is not None
    key, certificate = await system_data_db.ca()
    assert key is not None
    assert certificate is not None


@pytest.mark.asyncio
async def test_system_data_update(system_data_db: SystemDataDb) -> None:
    existing = await system_data_db.info()
    assert await system_data_db.update_info(company="foo") == {**existing, "company": "foo"}
    assert await system_data_db.update_info(test="bla") == {**existing, "company": "foo", "test": "bla"}
    assert await system_data_db.info() == {**existing, "company": "foo", "test": "bla"}
