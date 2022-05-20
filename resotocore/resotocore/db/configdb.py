from resotocore.config import ConfigEntity, ConfigValidation
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from resotocore.ids import ConfigId


# Database to store config entities
ConfigEntityDb = EntityDb[ConfigId, ConfigEntity]
EventConfigEntityDb = EventEntityDb[ConfigId, ConfigEntity]


def config_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[ConfigId, ConfigEntity]:
    return ArangoEntityDb(db, collection, ConfigEntity, lambda k: k.id)


# Database to store config entity models
ConfigValidationEntityDb = EntityDb[str, ConfigValidation]
EventConfigValidationEntityDb = EventEntityDb[str, ConfigValidation]


def config_validation_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, ConfigValidation]:
    return ArangoEntityDb(db, collection, ConfigValidation, lambda k: k.id)
