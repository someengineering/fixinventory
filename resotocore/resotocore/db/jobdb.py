from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from resotocore.task.task_description import Job

JobDb = EntityDb[str, Job]
EventJobDb = EventEntityDb[str, Job]


def job_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[str, Job]:
    return ArangoEntityDb(db, collection, Job, lambda k: k.id)
