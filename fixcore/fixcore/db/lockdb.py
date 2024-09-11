import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import cast, List, AsyncIterator

from arango import CollectionCreateError

from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.types import Json
from fixcore.util import utc

log = logging.getLogger(__name__)


class LockAcquisitionError(Exception):
    pass


class LockDB:
    def __init__(self, db: AsyncArangoDB, collection_name: str) -> None:
        self.db = db
        self.collection_name = collection_name

    @asynccontextmanager
    async def lock(
        self,
        name: str,
        *,
        get_lock: timedelta = timedelta(seconds=60),  # how long to try to get the lock
        lock_for: timedelta = timedelta(seconds=60),  # acquired: how long to hold the lock max
        retry_interval: timedelta = timedelta(seconds=0.1),  # how long to wait between retries
    ) -> AsyncIterator[None]:
        now = utc()
        ttl = int((now + lock_for).timestamp())
        deadline = now + get_lock
        lock_acquired = False
        while not lock_acquired and utc() < deadline:
            try:
                # try to insert a document with key __lock__
                await self.db.insert(self.collection_name, dict(_key=name, expires=ttl), sync=True)
            except Exception:
                # could not insert the document. Wait and try again
                await asyncio.sleep(retry_interval.total_seconds())
                continue
            lock_acquired = True
            try:
                yield
            finally:
                await self.db.delete(self.collection_name, name, ignore_missing=True)
        if not lock_acquired:
            raise LockAcquisitionError(f"Could not acquire lock {name}")

    async def create_update_schema(self) -> None:
        if not await self.db.has_collection(self.collection_name):
            try:
                await self.db.create_collection(self.collection_name)
            except CollectionCreateError as ex:
                if ex.error_code != 1207:  # already exists
                    raise
        collection = self.db.collection(self.collection_name)
        indexes = {idx["name"]: idx for idx in cast(List[Json], collection.indexes())}
        if "ttl" not in indexes:
            try:
                # The ttl expiry is only a safeguard - if the process is not able to clean up requested locks
                collection.add_index(dict(type="ttl", fields=["expires"], expireAfter=0, name="ttl"))
            except Exception as ex:
                log.info(f"Could not create TTL index for lock collection: {ex}")
