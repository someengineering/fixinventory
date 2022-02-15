from uuid import uuid1

import pytest
from arango.collection import StandardCollection
from arango.database import StandardDatabase

from core.db.async_arangodb import AsyncArangoDB

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import test_db, system_db, local_client


@pytest.fixture
async def async_db(test_db: StandardDatabase) -> AsyncArangoDB:
    return AsyncArangoDB(test_db)


@pytest.fixture
async def test_collection(test_db: StandardDatabase) -> StandardCollection:
    tmp_name = "tmp_" + str(uuid1()).replace("-", "")
    print(tmp_name)
    try:
        collection = test_db.create_collection(tmp_name)
        yield collection
    finally:
        test_db.delete_collection(tmp_name, ignore_missing=True)


@pytest.mark.asyncio
async def test_events(async_db: AsyncArangoDB, test_collection: StandardCollection) -> None:
    tc = test_collection.name

    with pytest.raises(Exception):
        async with async_db.begin_transaction(read=[tc], write=[tc]) as tx:
            await tx.insert(tc, {"_key": "foo"})
            raise Exception("foo")
    result = list(await async_db.all(tc))
    assert len(result) == 0

    async with async_db.begin_transaction(read=[tc], write=[tc]) as tx:
        await tx.insert(tc, {"_key": "foo"})
    result = list(await async_db.all(tc))
    assert len(result) == 1
