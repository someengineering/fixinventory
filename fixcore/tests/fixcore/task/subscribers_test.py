from datetime import timedelta
from typing import Any, AsyncIterator

from deepdiff import DeepDiff
from pytest import fixture, mark

from fixcore.ids import SubscriberId
from fixcore.message_bus import MessageBus
from fixcore.model.typed_model import to_js, from_js
from fixcore.task.model import Subscription, Subscriber
from fixcore.task.subscribers import SubscriptionHandler, SubscriptionHandlerService


@fixture
async def handler() -> AsyncIterator[SubscriptionHandlerService]:
    async with SubscriptionHandlerService(MessageBus()) as handler:
        await handler.add_subscription(SubscriberId("sub_1"), "test", True, timedelta(seconds=3))
        yield handler


def test_json_marshalling_subscription() -> None:
    roundtrip(Subscription("test"))
    roundtrip(Subscription("test", False, timedelta(days=1)))
    assert from_js({"message_type": "foo"}, Subscription) == Subscription("foo")
    assert from_js({"message_type": "foo"}, Subscription) == Subscription("foo")
    assert from_js({"message_type": "a", "timeout": 86400}, Subscription) == Subscription("a", True, timedelta(days=1))


def test_json_marshalling_subscribers() -> None:
    subscriptions = [
        Subscription("a", True, timedelta(seconds=1)),
        Subscription("b", True, timedelta(minutes=1)),
        Subscription("c", True, timedelta(hours=1)),
        Subscription("d", False, timedelta(days=1)),
        Subscription("e", False, timedelta(weeks=1)),
    ]
    roundtrip(Subscriber.from_list(SubscriberId("foo"), []))
    roundtrip(Subscriber.from_list(SubscriberId("foo"), subscriptions))


@mark.asyncio
async def test_subscribe(handler: SubscriptionHandler) -> None:
    # register first time
    result = await handler.add_subscription(SubscriberId("foo"), "event_bla", True, timedelta(seconds=3))
    assert len(result.subscriptions) == 1
    assert result.subscriptions["event_bla"].message_type == "event_bla"
    # register again is ignored
    result = await handler.add_subscription(SubscriberId("foo"), "event_bla", True, timedelta(seconds=3))
    assert len(result.subscriptions) == 1
    assert result.subscriptions["event_bla"].message_type == "event_bla"


@mark.asyncio
async def test_unsubscribe(handler: SubscriptionHandler) -> None:
    # register first time
    subscriber_id = SubscriberId("foo")
    subs = [Subscription("event_bla"), Subscription("event_bar")]
    result = await handler.update_subscriptions(subscriber_id, subs)
    assert len(result.subscriptions) == 2
    updated = await handler.remove_subscription(subscriber_id, "event_bla")
    assert len(updated.subscriptions) == 1
    # second time should be ignored
    updated = await handler.remove_subscription(subscriber_id, "event_bla")
    assert len(updated.subscriptions) == 1
    # last subscription is removed
    updated = await handler.remove_subscription(subscriber_id, "event_bar")
    assert len(updated.subscriptions) == 0


@mark.asyncio
async def test_get_subscriber(handler: SubscriptionHandler) -> None:
    result = await handler.get_subscriber(SubscriberId("sub_1"))
    assert result
    assert result.id == "sub_1"


@mark.asyncio
async def test_by_event_type(handler: SubscriptionHandler) -> None:
    result = await handler.list_subscriber_for("test")
    assert len(result) == 1
    assert result[0].subscriptions["test"].message_type == "test"
    result2 = await handler.list_subscriber_for("does not exist")
    assert len(result2) == 0


def roundtrip(obj: Any) -> None:
    js = to_js(obj)
    again = from_js(js, type(obj))
    assert DeepDiff(obj, again) == {}, f"Json: {js} serialized as {again}"
