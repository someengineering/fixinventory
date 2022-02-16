from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from resotocore.task.model import Subscriber

SubscriberDb = EntityDb[Subscriber]
EventSubscriberDb = EventEntityDb[Subscriber]


def subscriber_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[Subscriber]:
    return ArangoEntityDb(db, collection, Subscriber, lambda k: k.id)
