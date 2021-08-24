from datetime import timedelta
from typing import Any

from deepdiff import DeepDiff
from pytest import fixture, mark

from core.model.typed_model import to_js, from_js
from core.workflow.subscribers import SubscriptionHandler, Subscription, Subscriber


@fixture
async def handler() -> SubscriptionHandler:
    result = SubscriptionHandler()
    await result.add_subscription("sub_1", "test", True, timedelta(seconds=3))
    return result


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
    roundtrip(Subscriber.from_list("foo", []))
    roundtrip(Subscriber.from_list("foo", subscriptions))


@mark.asyncio
async def test_subscribe(handler: SubscriptionHandler) -> None:
    # register first time
    result = await handler.add_subscription("foo", "event_bla", True, timedelta(seconds=3))
    assert len(result.subscriptions) == 1
    assert result.subscriptions["event_bla"].message_type == "event_bla"
    # register again is ignored
    result = await handler.add_subscription("foo", "event_bla", True, timedelta(seconds=3))
    assert len(result.subscriptions) == 1
    assert result.subscriptions["event_bla"].message_type == "event_bla"


@mark.asyncio
async def test_unsubscribe(handler: SubscriptionHandler) -> None:
    # register first time
    result = await handler.add_subscription("foo", "event_bla", True, timedelta(seconds=3))
    assert len(result.subscriptions) == 1
    updated = await handler.remove_subscription("foo", "event_bla")
    assert len(updated.subscriptions) == 0


@mark.asyncio
async def test_get_subscriber(handler: SubscriptionHandler) -> None:
    result = await handler.get_subscriber("sub_1")
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
