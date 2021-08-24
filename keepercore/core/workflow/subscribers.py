from __future__ import annotations

from abc import ABC
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Optional, Iterable

from dataclasses import dataclass, field


@dataclass(unsafe_hash=True, frozen=True)
class Subscription(ABC):
    message_type: str
    wait_for_completion: bool = field(default=True)
    timeout: timedelta = field(default=timedelta(seconds=60))


@dataclass(unsafe_hash=True, frozen=True)
class Subscriber(ABC):
    id: str
    subscriptions: dict[str, Subscription]

    @staticmethod
    def from_list(uid: str, subscriptions: list[Subscription]) -> Subscriber:
        return Subscriber(uid, {s.message_type: s for s in subscriptions})

    def add_subscription(self, message_type: str, wait_for_completion: bool, timeout: timedelta) -> Subscriber:
        subscription = Subscription(message_type, wait_for_completion, timeout)
        existing = self.subscriptions.get(message_type)
        if existing == subscription:
            return self
        else:
            return Subscriber(self.id, self.subscriptions | {subscription.message_type: subscription})

    def remove_subscription(self, message_type: str) -> Subscriber:
        subs = self.subscriptions.copy()
        subs.pop(message_type, None)
        return Subscriber(self.id, subs)

    def __contains__(self, message_type: str) -> bool:
        return message_type in self.subscriptions

    def __getitem__(self, message_type: str) -> Subscription:
        return self.subscriptions[message_type]


# TODO: add database handling
class SubscriptionHandler(ABC):
    def __init__(self) -> None:
        # subscriber by subscriber id
        self.subscribers_by_id: Dict[str, Subscriber] = {}
        self.subscribers_by_event: Dict[str, List[Subscriber]] = {}

    async def start(self) -> None:
        return None

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
            self.subscribers_by_id[subscriber_id] = updated
            self.subscribers_by_event = self.update_subscriber_by_event(self.subscribers_by_id.values())
        return updated

    async def remove_subscription(self, subscriber_id: str, event_type: str) -> Subscriber:
        existing = self.subscribers_by_id.get(subscriber_id, Subscriber(subscriber_id, {}))
        updated = existing.remove_subscription(event_type)
        if existing != updated:
            self.subscribers_by_id[subscriber_id] = updated
            self.subscribers_by_event = self.update_subscriber_by_event(self.subscribers_by_id.values())
        return updated

    async def update_subscriptions(self, subscriber_id: str, subscriptions: list[Subscription]) -> Subscriber:
        existing = self.subscribers_by_id.get(subscriber_id, None)
        updated = Subscriber.from_list(subscriber_id, subscriptions)
        if existing != updated:
            self.subscribers_by_id[subscriber_id] = updated
            self.subscribers_by_event = self.update_subscriber_by_event(self.subscribers_by_id.values())
        return updated

    async def remove_subscriber(self, subscriber_id: str) -> Optional[Subscriber]:
        existing = self.subscribers_by_id.get(subscriber_id, None)
        if existing:
            self.subscribers_by_id.pop(subscriber_id, None)
            self.subscribers_by_event = self.update_subscriber_by_event(self.subscribers_by_id.values())
        return existing

    @staticmethod
    def update_subscriber_by_event(subscribers: Iterable[Subscriber]) -> Dict[str, List[Subscriber]]:
        result: Dict[str, List[Subscriber]] = defaultdict(list)
        for subscriber in subscribers:
            for subscription in subscriber.subscriptions.values():
                result[subscription.message_type].append(subscriber)
        return result
