from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from core.task.task_description import Job

JobDb = EntityDb[Job]
EventJobDb = EventEntityDb[Job]


def job_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[Job]:
    return ArangoEntityDb(db, collection, Job, lambda k: k.id)
