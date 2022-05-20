from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from resotocore.ids import SubscriberId
from resotocore.task.model import Subscriber

SubscriberDb = EntityDb[SubscriberId, Subscriber]
EventSubscriberDb = EventEntityDb[SubscriberId, Subscriber]


def subscriber_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[SubscriberId, Subscriber]:
    return ArangoEntityDb(db, collection, Subscriber, lambda k: k.id)
