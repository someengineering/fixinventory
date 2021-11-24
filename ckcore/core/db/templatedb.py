from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from core.query import Template

TemplateEntityDb = EntityDb[Template]
EventTemplateEntityDb = EventEntityDb[Template]


def template_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[Template]:
    return ArangoEntityDb(db, collection, Template, lambda k: k.name)
