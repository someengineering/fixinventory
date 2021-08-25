from datetime import timedelta

from pytest import fixture

from core.event_bus import EventBus
from core.workflow.model import Subscriber
from core.workflow.subscribers import SubscriptionHandler
from core.workflow.workflow_handler import WorkflowHandler
from tests.core.db.entitydb import InMemoryDb

# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus


@fixture
async def subscription_handler(event_bus: EventBus) -> SubscriptionHandler:
    in_mem = InMemoryDb(Subscriber, lambda x: x.id)
    result = SubscriptionHandler(in_mem, event_bus)
    await result.add_subscription("sub_1", "test", True, timedelta(seconds=3))
    return result


@fixture
async def workflow_handler(event_bus: EventBus, subscription_handler: SubscriptionHandler) -> WorkflowHandler:
    # TODO: implement me
    pass
