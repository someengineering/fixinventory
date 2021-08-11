from datetime import timedelta

from pytest import fixture, mark

from core.workflow.subscribers import SubscriptionHandler


@fixture
async def handler() -> SubscriptionHandler:
    result = SubscriptionHandler()
    await result.add_subscription("sub_1", "test", True, timedelta(seconds=3))
    return result


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
