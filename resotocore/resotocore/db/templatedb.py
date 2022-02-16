from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from resotocore.query.model import Template

TemplateEntityDb = EntityDb[Template]
EventTemplateEntityDb = EventEntityDb[Template]


def template_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[Template]:
    return ArangoEntityDb(db, collection, Template, lambda k: k.name)
