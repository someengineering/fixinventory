import asyncio
import pytest
from arango.database import StandardDatabase
from typing import List

from resotocore.analytics import AnalyticsEventSender, InMemoryEventSender
from resotocore.db import subscriberdb
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EventEntityDb
from resotocore.db.subscriberdb import SubscriberDb, EventSubscriberDb
from resotocore.task.model import Subscriber, Subscription
from resotocore.ids import SubscriberId

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import test_db, system_db, local_client

# noinspection PyUnresolvedReferences
from tests.resotocore.analytics import event_sender


@pytest.fixture
async def subscriber_db(test_db: StandardDatabase) -> SubscriberDb:
    async_db = AsyncArangoDB(test_db)
    subscriber_db = subscriberdb.subscriber_db(async_db, "subscriber")
    await subscriber_db.create_update_schema()
    await subscriber_db.wipe()
    return subscriber_db


@pytest.fixture
def event_db(subscriber_db: SubscriberDb, event_sender: AnalyticsEventSender) -> EventSubscriberDb:
    return EventEntityDb(subscriber_db, event_sender, "subscriber")


@pytest.fixture
def subscribers() -> List[Subscriber]:
    subs = [Subscription("foo", True) for _ in range(0, 10)]
    return [Subscriber.from_list(SubscriberId(str(a)), subs) for a in range(0, 10)]


@pytest.mark.asyncio
async def test_load(subscriber_db: SubscriberDb, subscribers: List[Subscriber]) -> None:
    await subscriber_db.update_many(subscribers)
    loaded = [sub async for sub in subscriber_db.all()]
    assert subscribers.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_update(subscriber_db: SubscriberDb, subscribers: List[Subscriber]) -> None:
    # multiple updates should work as expected
    await subscriber_db.update_many(subscribers)
    await subscriber_db.update_many(subscribers)
    await subscriber_db.update_many(subscribers)
    loaded = [sub async for sub in subscriber_db.all()]
    assert subscribers.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_delete(subscriber_db: SubscriberDb, subscribers: List[Subscriber]) -> None:
    await subscriber_db.update_many(subscribers)
    remaining = list(subscribers)
    for _ in subscribers:
        sub = remaining.pop()
        await subscriber_db.delete_value(sub)
        loaded = [sub async for sub in subscriber_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in subscriber_db.all()]) == 0


@pytest.mark.asyncio
async def test_events(
    event_db: EventSubscriberDb, subscribers: List[Subscriber], event_sender: InMemoryEventSender
) -> None:
    # 2 times update
    await event_db.update_many(subscribers)
    await event_db.update_many(subscribers)
    # 6 times delete
    for sub in subscribers:
        await event_db.delete_value(sub)
    # make sure all events will arrive
    await asyncio.sleep(0.1)
    # ensure the correct count and order of events
    assert [a.kind for a in event_sender.events] == ["subscriber-updated-many"] * 2 + ["subscriber-deleted"] * 10
