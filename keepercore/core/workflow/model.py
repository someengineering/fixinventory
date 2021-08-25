from __future__ import annotations
from dataclasses import dataclass, field

from datetime import timedelta


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Subscription:
    message_type: str
    wait_for_completion: bool = field(default=True)
    timeout: timedelta = field(default=timedelta(seconds=60))


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Subscriber:
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
