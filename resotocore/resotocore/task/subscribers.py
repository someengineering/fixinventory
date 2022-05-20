from __future__ import annotations

import logging
from abc import ABC
from collections import defaultdict
from datetime import timedelta, datetime
from typing import Optional, Iterable, Dict, List

from resotocore.db.subscriberdb import SubscriberDb
from resotocore.message_bus import MessageBus
from resotocore.util import utc, Periodic
from resotocore.task.model import Subscriber, Subscription
from resotocore.ids import SubscriberId

log = logging.getLogger(__name__)


class SubscriptionHandler(ABC):
    """
    SubscriptionHandler maintains all subscriptions in memory and syncs its internal state with the underlying db.
    Only reason for persistence is recovery of all subscriptions after restart.
    This handler belongs to the event system, which assumes there is only one instance running in each cluster!
    """

    def __init__(self, db: SubscriberDb, message_bus: MessageBus) -> None:
        self.db = db
        self.message_bus = message_bus
        self._subscribers_by_id: Dict[SubscriberId, Subscriber] = {}
        self._subscribers_by_event: Dict[str, List[Subscriber]] = {}
        self.started_at = utc()
        self.cleaner = Periodic("subscription_cleaner", self.check_outdated_handler, timedelta(seconds=10))
        self.not_connected_since: Dict[str, datetime] = {}

    async def start(self) -> None:
        await self.__load_from_db()
        log.info(f"Loaded {len(self._subscribers_by_id)} subscribers for {len(self._subscribers_by_event)} events")
        await self.cleaner.start()

    async def stop(self) -> None:
        await self.cleaner.stop()

    async def all_subscribers(self) -> Iterable[Subscriber]:
        return self._subscribers_by_id.values()

    async def get_subscriber(self, subscriber_id: SubscriberId) -> Optional[Subscriber]:
        return self._subscribers_by_id.get(subscriber_id)

    async def list_subscriber_for(self, event_type: str) -> List[Subscriber]:
        return self._subscribers_by_event.get(event_type, [])

    async def add_subscription(
        self, subscriber_id: SubscriberId, event_type: str, wait_for_completion: bool, timeout: timedelta
    ) -> Subscriber:
        existing = self._subscribers_by_id.get(subscriber_id, Subscriber(subscriber_id, {}))
        updated = existing.add_subscription(event_type, wait_for_completion, timeout)
        if existing != updated:
            log.info(f"Subscriber {subscriber_id}: add subscription={event_type} ({wait_for_completion}, {timeout})")
            await self.db.update(updated)
            await self.__load_from_db()
        return updated

    async def remove_subscription(self, subscriber_id: SubscriberId, event_type: str) -> Subscriber:
        existing = self._subscribers_by_id.get(subscriber_id, Subscriber(subscriber_id, {}))
        updated = existing.remove_subscription(event_type)
        if existing != updated:
            log.info(f"Subscriber {subscriber_id}: remove subscription={event_type}")
            if updated.subscriptions:
                await self.db.update(updated)
            else:
                await self.db.delete(subscriber_id)
            await self.__load_from_db()
        return updated

    async def update_subscriptions(self, subscriber_id: SubscriberId, subscriptions: List[Subscription]) -> Subscriber:
        existing = self._subscribers_by_id.get(subscriber_id, None)
        updated = Subscriber.from_list(subscriber_id, subscriptions)
        if existing != updated:
            log.info(f"Subscriber {subscriber_id}: update all subscriptions={subscriptions}")
            await self.db.update(updated)
            await self.__load_from_db()
        return updated

    async def remove_subscriber(self, subscriber_id: SubscriberId) -> Optional[Subscriber]:
        existing = self._subscribers_by_id.get(subscriber_id, None)
        if existing:
            log.info(f"Subscriber {subscriber_id}: remove subscriber")
            await self.db.delete(subscriber_id)
            await self.__load_from_db()
        return existing

    async def __load_from_db(self) -> None:
        self._subscribers_by_id = {s.id: s async for s in self.db.all()}
        self._subscribers_by_event = self.update_subscriber_by_event(self._subscribers_by_id.values())

    def subscribers_by_event(self) -> Dict[str, List[Subscriber]]:
        return self._subscribers_by_event

    @staticmethod
    def update_subscriber_by_event(subscribers: Iterable[Subscriber]) -> Dict[str, List[Subscriber]]:
        result: Dict[str, List[Subscriber]] = defaultdict(list)
        for subscriber in subscribers:
            for subscription in subscriber.subscriptions.values():
                result[subscription.message_type].append(subscriber)
        return result

    async def check_outdated_handler(self) -> None:
        """
        Periodically check, if there are subscribers that have subscribed, but are not connected.
        The subscription will be removed when a dead subscription is detected.
        """
        now = utc()
        # In case the service has just been started/restarted:
        # do not remove any subscriptions during the first minutes.
        if (now - self.started_at) > timedelta(minutes=5):
            expected = set(self._subscribers_by_id.keys())
            connected = set(self.message_bus.active_listener.keys())
            # remove all connected subscriber from the not connected map
            for c in connected:
                self.not_connected_since.pop(c, None)
            missing = expected - connected
            for subscriber in missing:
                at = self.not_connected_since.get(subscriber)
                if at and (now - at) > timedelta(minutes=3):
                    log.warning(f"Subscriber {subscriber} is missing. Remove all subscription.")
                    await self.remove_subscriber(subscriber)
                    self.not_connected_since.pop(subscriber, None)
                elif at:
                    pass
                else:
                    self.not_connected_since[subscriber] = now
