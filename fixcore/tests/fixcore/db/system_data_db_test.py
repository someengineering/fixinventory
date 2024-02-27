import pytest

from fixcore.db import SystemData
from fixcore.db.system_data_db import SystemDataDb
from fixcore.util import utc


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

    data = SystemData("foo", utc(), 1, "1.2.3")
    assert (await system_data_db.update_system_data(data)).version == data.version
