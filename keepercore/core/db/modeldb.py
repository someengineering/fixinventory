from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from core.model.model import Kind

ModelDb = EntityDb[Kind]
EventModelDb = EventEntityDb[Kind]


class ArangoModelDB(ArangoEntityDb[Kind]):
    def __init__(self, db: AsyncArangoDB, collection: str):
        super().__init__(db, collection, Kind, lambda k: k.fqn)  # type: ignore
