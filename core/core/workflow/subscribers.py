from __future__ import annotations

from abc import ABC
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Optional, Iterable


class Subscription(ABC):
    def __init__(self, message_type: str, wait_for_completion: bool, timeout: timedelta):
        self.message_type = message_type
        self.wait_for_completion = wait_for_completion
        self.timeout = timeout


class Subscriber(ABC):
    def __init__(self, uid: str, subscriptions: Optional[List[Subscription]] = None):
        self.id = uid
        subs = subscriptions if subscriptions else []
        self.subscriptions: Dict[str, Subscription] = {sub.message_type: sub for sub in subs}

    def add_subscription(self, message_type: str, wait_for_completion: bool, timeout: timedelta) -> Subscriber:
        existing = self.subscriptions.get(message_type)
        if existing:
            return self
        else:
            subscription = Subscription(message_type, wait_for_completion, timeout)
            subscriber = Subscriber(self.id, list(self.subscriptions.values()) + [subscription])
            return subscriber

    def remove_subscription(self, message_type: str) -> Subscriber:
        existing = self.subscriptions.get(message_type)
        if existing:
            return Subscriber(
                self.id, list(filter(lambda x: x.message_type != message_type, self.subscriptions.values()))
            )
        else:
            return self

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
        existing = self.subscribers_by_id.get(subscriber_id, Subscriber(subscriber_id, []))
        updated = existing.add_subscription(event_type, wait_for_completion, timeout)
        self.subscribers_by_id[subscriber_id] = updated
        self.subscribers_by_event = self.update_subscriber_by_event(self.subscribers_by_id.values())
        return updated

    async def remove_subscription(self, subscriber_id: str, event_type: str) -> Subscriber:
        existing = self.subscribers_by_id.get(subscriber_id, Subscriber(subscriber_id, []))
        updated = existing.remove_subscription(event_type)
        self.subscribers_by_id[subscriber_id] = updated
        self.subscribers_by_event = self.update_subscriber_by_event(self.subscribers_by_id.values())
        return updated

    @staticmethod
    def update_subscriber_by_event(subscribers: Iterable[Subscriber]) -> Dict[str, List[Subscriber]]:
        result: Dict[str, List[Subscriber]] = defaultdict(list)
        for subscriber in subscribers:
            for subscription in subscriber.subscriptions.values():
                result[subscription.message_type].append(subscriber)
        return result
