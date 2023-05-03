from contextlib import suppress

import pytest
from arango.database import StandardDatabase

from resotocore.db import SystemData
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.system_data_db import SystemDataDb
from resotocore.model.typed_model import to_js
from resotocore.util import uuid_str, utc


@pytest.fixture
async def system_data_db(test_db: StandardDatabase) -> SystemDataDb:
    with suppress(Exception):
        system = SystemData(uuid_str(), utc(), 1)
        test_db.insert_document("system_data", {"_key": "system", **to_js(system)}, overwrite=False)
    with suppress(Exception):
        test_db.insert_document(
            "system_data", {"_key": "ca", "key": "private_key", "certificate": "some cert"}, overwrite=False
        )
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
