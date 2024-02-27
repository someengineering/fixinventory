from typing import AsyncIterator, cast
from uuid import uuid1

import pytest
from arango.collection import StandardCollection
from arango.database import StandardDatabase

from fixcore.db.async_arangodb import AsyncArangoDB


@pytest.fixture
async def test_collection(test_db: StandardDatabase) -> AsyncIterator[StandardCollection]:
    tmp_name = "tmp_" + str(uuid1()).replace("-", "")
    print(tmp_name)
    try:
        yield cast(StandardCollection, test_db.create_collection(tmp_name))
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
