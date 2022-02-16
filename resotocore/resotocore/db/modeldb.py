from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from resotocore.model.model import Kind

ModelDb = EntityDb[Kind]
EventModelDb = EventEntityDb[Kind]


def model_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[Kind]:
    return ArangoEntityDb(db, collection, Kind, lambda k: k.fqn)  # type: ignore
