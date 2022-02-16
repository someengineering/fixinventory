from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from resotocore.task.task_description import Job

JobDb = EntityDb[Job]
EventJobDb = EventEntityDb[Job]


def job_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[Job]:
    return ArangoEntityDb(db, collection, Job, lambda k: k.id)
