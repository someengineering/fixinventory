from resotocore.config import ConfigEntity, ConfigModel
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb


# Database to store config entities
ConfigEntityDb = EntityDb[ConfigEntity]
EventConfigEntityDb = EventEntityDb[ConfigEntity]


def config_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[ConfigEntity]:
    return ArangoEntityDb(db, collection, ConfigEntity, lambda k: k.id)


# Database to store config entity models
ConfigModelEntityDb = EntityDb[ConfigModel]
EventConfigModelEntityDb = EventEntityDb[ConfigModel]


def config_model_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[ConfigModel]:
    return ArangoEntityDb(db, collection, ConfigModel, lambda k: k.id)
