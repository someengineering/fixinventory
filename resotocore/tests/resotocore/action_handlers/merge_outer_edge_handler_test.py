import pytest
import asyncio
from pytest import fixture
from tests.resotocore.task.task_handler_test import task_handler
from resotocore.action_handlers.merge_outer_edge_handler import MergeOuterEdgesHandler
from resotocore.message_bus import Action, MessageBus
from resotocore.task.task_handler import TaskHandlerService
from resotocore.task.subscribers import SubscriptionHandler
from tests.resotocore.message_bus_test import message_bus, all_events, wait_for_message
from tests.resotocore.db.runningtaskdb_test import running_task_db
from typing import AsyncGenerator
from resotocore.task.task_description import (
    Workflow,
    Step,
    PerformAction,
    EventTrigger,
    StepErrorBehaviour,
    TimeTrigger,
    Job,
    TaskSurpassBehaviour,
    ExecuteCommand,
)

from tests.resotocore.db.graphdb_test import (
    filled_graph_db,
    graph_db,
    test_db,
    foo_model,
    foo_kinds,
    system_db,
    local_client,
)

# noinspection PyUnresolvedReferences
from tests.resotocore.cli.cli_test import cli, cli_deps

# noinspection PyUnresolvedReferences
from tests.resotocore.analytics import event_sender

# noinspection PyUnresolvedReferences
from tests.resotocore.worker_task_queue_test import worker, task_queue, performed_by, incoming_tasks

# noinspection PyUnresolvedReferences
from tests.resotocore.query.template_expander_test import expander

# noinspection PyUnresolvedReferences
from tests.resotocore.config.config_handler_service_test import config_handler
from tests.resotocore.db.entitydb import InMemoryDb

# noinspection PyUnresolvedReferences
from tests.resotocore.web.certificate_handler_test import cert_handler

# noinspection PyUnresolvedReferences
from tests.resotocore.task.task_handler_test import test_workflow, subscription_handler, job_db


@fixture()
async def merge_handler(
    message_bus: MessageBus,
    subscription_handler: SubscriptionHandler,
    task_handler: TaskHandlerService,
) -> AsyncGenerator[MergeOuterEdgesHandler, None]:
    handler = MergeOuterEdgesHandler(message_bus, subscription_handler, task_handler)
    await handler.start()
    yield handler
    await handler.stop()


merge_outer_edges = "merge_outer_edges"


@pytest.mark.asyncio
async def test_handler_invocation(
    merge_handler: MergeOuterEdgesHandler, subscription_handler: SubscriptionHandler, message_bus: MessageBus
) -> None:
    merge_called: asyncio.Future[str] = asyncio.get_event_loop().create_future()

    def mocked_merge(self: MergeOuterEdgesHandler, task_id: str) -> None:
        merge_called.set_result(task_id)

    merge_handler.merge_outer_edges = lambda task_id: mocked_merge(merge_handler, task_id)

    subscribers = await subscription_handler.list_subscriber_for(merge_outer_edges)

    assert subscribers[0].id == "resotocore.merge_outer_edges"

    await message_bus.emit(Action(merge_outer_edges, "test_task_1", merge_outer_edges))

    assert await merge_called == "test_task_1"
