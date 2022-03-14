from resotocore.config import ConfigEntity, ConfigValidation
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb


# Database to store config entities
ConfigEntityDb = EntityDb[ConfigEntity]
EventConfigEntityDb = EventEntityDb[ConfigEntity]


def config_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[ConfigEntity]:
    return ArangoEntityDb(db, collection, ConfigEntity, lambda k: k.id)


# Database to store config entity models
ConfigValidationEntityDb = EntityDb[ConfigValidation]
EventConfigValidationEntityDb = EventEntityDb[ConfigValidation]


def config_validation_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[ConfigValidation]:
    return ArangoEntityDb(db, collection, ConfigValidation, lambda k: k.id)
