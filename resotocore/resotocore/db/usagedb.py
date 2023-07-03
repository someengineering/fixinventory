from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb
from resotocore.model.model import UsageDatapoint

ResourceUsageDb = EntityDb[str, UsageDatapoint]


def resource_usage_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, UsageDatapoint]:
    return ArangoEntityDb(db, collection, UsageDatapoint, lambda d: d.id + str(d.at))
