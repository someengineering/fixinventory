from __future__ import annotations

import logging
from abc import ABC
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Optional, Iterable

from core.db.subscriberdb import SubscriberDb
from core.workflow.model import Subscriber, Subscription

log = logging.getLogger(__name__)


class SubscriptionHandler(ABC):
    def __init__(self, db: SubscriberDb) -> None:
        # subscriber by subscriber id
        self.db = db
        self.subscribers_by_id: Dict[str, Subscriber] = {}
        self.subscribers_by_event: Dict[str, List[Subscriber]] = {}

    async def start(self) -> None:
        await self.__load_from_db()
        log.info(f"Loaded {len(self.subscribers_by_id)} subscribers for {len(self.subscribers_by_event)} events")

    async def all_subscribers(self) -> Iterable[Subscriber]:
        return self.subscribers_by_id.values()

    async def get_subscriber(self, subscriber_id: str) -> Optional[Subscriber]:
        return self.subscribers_by_id.get(subscriber_id)

    async def list_subscriber_for(self, event_type: str) -> List[Subscriber]:
        return self.subscribers_by_event.get(event_type, [])

    async def add_subscription(
        self, subscriber_id: str, event_type: str, wait_for_completion: bool, timeout: timedelta
    ) -> Subscriber:
        existing = self.subscribers_by_id.get(subscriber_id, Subscriber(subscriber_id, {}))
        updated = existing.add_subscription(event_type, wait_for_completion, timeout)
        if existing != updated:
            log.info(f"Subscriber {subscriber_id}: add subscription={event_type} ({wait_for_completion}, {timeout})")
            await self.db.update(updated)
            await self.__load_from_db()
        return updated

    async def remove_subscription(self, subscriber_id: str, event_type: str) -> Subscriber:
        existing = self.subscribers_by_id.get(subscriber_id, Subscriber(subscriber_id, {}))
        updated = existing.remove_subscription(event_type)
        if existing != updated:
            log.info(f"Subscriber {subscriber_id}: remove subscription={event_type}")
            if updated.subscriptions:
                await self.db.update(updated)
            else:
                await self.db.delete(subscriber_id)
            await self.__load_from_db()
        return updated

    async def update_subscriptions(self, subscriber_id: str, subscriptions: list[Subscription]) -> Subscriber:
        existing = self.subscribers_by_id.get(subscriber_id, None)
        updated = Subscriber.from_list(subscriber_id, subscriptions)
        if existing != updated:
            log.info(f"Subscriber {subscriber_id}: update all subscriptions={subscriptions}")
            await self.db.update(updated)
            await self.__load_from_db()
        return updated

    async def remove_subscriber(self, subscriber_id: str) -> Optional[Subscriber]:
        existing = self.subscribers_by_id.get(subscriber_id, None)
        if existing:
            log.info(f"Subscriber {subscriber_id}: remove subscriber")
            await self.db.delete(subscriber_id)
            await self.__load_from_db()
        return existing

    async def __load_from_db(self) -> None:
        self.subscribers_by_id = {s.id: s async for s in self.db.all()}
        self.subscribers_by_event = self.update_subscriber_by_event(self.subscribers_by_id.values())

    @staticmethod
    def update_subscriber_by_event(subscribers: Iterable[Subscriber]) -> Dict[str, List[Subscriber]]:
        result: Dict[str, List[Subscriber]] = defaultdict(list)
        for subscriber in subscribers:
            for subscription in subscriber.subscriptions.values():
                result[subscription.message_type].append(subscriber)
        return result
