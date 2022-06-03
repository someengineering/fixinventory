import pytest
import asyncio
from pytest import fixture

from resotocore.action_handlers.merge_outer_edge_handler import MergeOuterEdgesHandler
from resotocore.db.deferred_edge_db import PendingDeferredEdges
from resotocore.db.model import QueryModel
from resotocore.message_bus import Action, MessageBus
from resotocore.task.task_handler import TaskHandlerService
from resotocore.task.subscribers import SubscriptionHandler
from resotocore.db.db_access import DbAccess
from resotocore.analytics import NoEventSender
from resotocore.model.adjust_node import NoAdjust
from resotocore.model.graph_access import ByNodeId, BySearchCriteria, DeferredEdge, EdgeType
from resotocore.dependencies import empty_config
from resotocore.model.model import Model
from resotocore.query.query_parser import parse_query
from resotocore.db.graphdb import ArangoGraphDB
from resotocore.model.typed_model import to_js
from resotocore.types import Json

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
    BaseResource,
    Foo,
    Bla,
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

from tests.resotocore.model import ModelHandlerStatic


@fixture()
def db_access(graph_db: ArangoGraphDB) -> DbAccess:
    access = DbAccess(graph_db.db.db, NoEventSender(), NoAdjust(), empty_config())
    return access


@fixture()
async def merge_handler(
    message_bus: MessageBus,
    subscription_handler: SubscriptionHandler,
    task_handler: TaskHandlerService,
    db_access: DbAccess,
    foo_model: Model,
) -> AsyncGenerator[MergeOuterEdgesHandler, None]:
    model_handler = ModelHandlerStatic(foo_model)
    handler = MergeOuterEdgesHandler(
        message_bus, subscription_handler, task_handler, db_access, model_handler, parse_query
    )
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


@pytest.mark.asyncio
async def test_merge_outer_edges(
    merge_handler: MergeOuterEdgesHandler, graph_db: ArangoGraphDB, foo_model: Model, db_access: DbAccess
) -> None:

    await graph_db.wipe()
    await graph_db.create_node(foo_model, "id1", to_json(Foo("id1", "foo")), "root")
    await graph_db.create_node(foo_model, "id2", to_json(Bla("id2", "bla")), "root")

    await db_access.get_pending_outer_edge_db().update(
        PendingDeferredEdges(
            TaskId("task123"),
            graph_db.name,
            [
                DeferredEdge(ByNodeId("id1"), BySearchCriteria("is(bla)"), EdgeType.default),
            ],
        )
    )
    await merge_handler.merge_outer_edges(TaskId("task123"))

    graph = await graph_db.search_graph(QueryModel(parse_query("is(graph_root) -default[0:]->"), foo_model))
    assert graph.has_edge("id1", "id2")


def to_json(obj: BaseResource) -> Json:
    return {"kind": obj.kind(), **to_js(obj)}
