from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from core.workflow.model import Subscriber

SubscriberDb = EntityDb[Subscriber]
EventSubscriberDb = EventEntityDb[Subscriber]


class ArangoSubscriberDb(ArangoEntityDb[Subscriber]):
    def __init__(self, db: AsyncArangoDB, collection: str):
        super().__init__(db, collection, Subscriber, lambda k: k.id)
