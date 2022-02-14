from resotocore.config import ConfigEntity
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb

ConfigEntityDb = EntityDb[ConfigEntity]
EventConfigEntityDb = EventEntityDb[ConfigEntity]


def config_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[ConfigEntity]:
    return ArangoEntityDb(db, collection, ConfigEntity, lambda k: k.id)
