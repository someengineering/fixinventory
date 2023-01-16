from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from resotocore.inspect import InspectionCheck

InspectionCheckEntityDb = EntityDb[str, InspectionCheck]
EventInspectionCheckEntityDb = EventEntityDb[str, InspectionCheck]


def inspection_check_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, InspectionCheck]:
    return ArangoEntityDb(db, collection, InspectionCheck, lambda k: k.id)
