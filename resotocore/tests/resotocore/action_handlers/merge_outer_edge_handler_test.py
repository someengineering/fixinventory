import pytest
import asyncio
from pytest import fixture

from resotocore.action_handlers.merge_outer_edge_handler import MergeOuterEdgesHandler
from resotocore.message_bus import Action, MessageBus
from resotocore.task.task_handler import TaskHandlerService
from resotocore.task.subscribers import SubscriptionHandler
from typing import AsyncGenerator
from resotocore.ids import TaskId

# noinspection PyUnresolvedReferences
from tests.resotocore.task.task_handler_test import task_handler

# noinspection PyUnresolvedReferences
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
from tests.resotocore.db.runningtaskdb_test import running_task_db

# noinspection PyUnresolvedReferences
from tests.resotocore.message_bus_test import message_bus, all_events, wait_for_message

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

# noinspection PyUnresolvedReferences
from tests.resotocore.web.certificate_handler_test import cert_handler

# noinspection PyUnresolvedReferences
from tests.resotocore.task.task_handler_test import test_workflow, subscription_handler, job_db


@fixture()
async def merge_handler(
    message_bus: MessageBus, subscription_handler: SubscriptionHandler, task_handler: TaskHandlerService
) -> AsyncGenerator[MergeOuterEdgesHandler, None]:
    handler = MergeOuterEdgesHandler(message_bus, subscription_handler, task_handler)
    await handler.start()
    yield handler
    await handler.stop()


merge_outer_edges = "merge_outer_edges"


@pytest.mark.asyncio
async def test_handler_invocation(
    merge_handler: MergeOuterEdgesHandler,
    subscription_handler: SubscriptionHandler,
    message_bus: MessageBus,
) -> None:
    merge_called: asyncio.Future[TaskId] = asyncio.get_event_loop().create_future()

    def mocked_merge(task_id: TaskId) -> None:
        merge_called.set_result(task_id)

    # monkey patching the merge_outer_edges method
    # use setattr here, since assignment does not work in mypy https://github.com/python/mypy/issues/2427
    setattr(merge_handler, "merge_outer_edges", mocked_merge)

    subscribers = await subscription_handler.list_subscriber_for(merge_outer_edges)

    assert subscribers[0].id == "resotocore"

    task_id = TaskId("test_task_1")

    await message_bus.emit(Action(merge_outer_edges, task_id, merge_outer_edges))

    assert await merge_called == task_id
