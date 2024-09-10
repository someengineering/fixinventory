from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.db.entitydb import EntityDb, ArangoEntityDb
from fixcore.model.model import UsageDatapoint

ResourceUsageDb = EntityDb[str, UsageDatapoint]


class UsageDb(ArangoEntityDb[str, UsageDatapoint]):
    async def create_update_schema(self) -> None:
        name = self.collection_name
        db = self.db
        if not await db.has_collection(name):
            collection = await db.create_collection(name)
            collection.add_index(
                dict(type="persistent", fields=["id", "at", "change_id"], storedValues=["v"], name="change_at")
            )
            one_year = 60 * 60 * 24 * 365
            collection.add_index(dict(type="ttl", fields=["at"], expireAfter=one_year, name="ttl"))


def resource_usage_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, UsageDatapoint]:
    return UsageDb(db, collection, UsageDatapoint, lambda d: d.id + str(d.at))
