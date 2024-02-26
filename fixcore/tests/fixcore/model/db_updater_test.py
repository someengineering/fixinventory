import asyncio
import json
from datetime import timedelta
from multiprocessing import set_start_method
from typing import List, AsyncGenerator, Any

import pytest

from fixcore.analytics import AnalyticsEventSender
from fixcore.db.deferredouteredgedb import deferred_outer_edge_db
from fixcore.db.graphdb import ArangoGraphDB
from fixcore.db.model import GraphUpdate
from fixcore.model.graph_access import DeferredEdge, ByNodeId
from fixcore.system_start import empty_config
from fixcore.ids import TaskId, NodeId
from fixcore.message_bus import MessageBus
from fixcore.model.db_updater import GraphMerger
from fixcore.model.model import Kind, Model
from fixcore.model.typed_model import to_js
from tests.fixcore.db.graphdb_test import create_graph
from tests.fixcore.model import ModelHandlerStatic


@pytest.mark.asyncio
async def test_merge_process(
    event_sender: AnalyticsEventSender, graph_db: ArangoGraphDB, foo_kinds: List[Kind], message_bus: MessageBus
) -> None:
    # set explicitly (is done in main explicitly as well)
    set_start_method("spawn")

    # wipe any existing data
    await graph_db.wipe()
    # store the model in db, so it can be loaded by the sub process
    graph_db.db.collection(f"{graph_db.name}_model").insert_many([to_js(a) for a in foo_kinds])
    # define args to parse for the sub process
    config = empty_config(["--graphdb-username", "test", "--graphdb-password", "test", "--graphdb-database", "test"])
    # create sample graph data to insert
    graph = create_graph("test")
    outer_edge_db = deferred_outer_edge_db(graph_db.db, "deferred_outer_edges")
    await outer_edge_db.create_update_schema()
    await outer_edge_db.wipe()

    async def iterator() -> AsyncGenerator[bytes, None]:
        def to_b(a: Any) -> bytes:
            return bytes(json.dumps(a) + "\n", "utf-8")

        for node in graph.nodes():
            yield to_b(graph.nodes[node])
        for from_node, to_node, data in graph.edges(data=True):
            yield to_b({"from": from_node, "to": to_node, "edge_type": data["edge_type"]})
        yield to_b(
            {"from_selector": {"node_id": "id_123"}, "to_selector": {"node_id": "id_456"}, "edge_type": "delete"}
        )

    model_handler = ModelHandlerStatic(Model.from_kinds(foo_kinds))
    async with GraphMerger(model_handler, event_sender, config, message_bus) as merger:
        task_id = TaskId("test_task_123")
        result = await merger.merge_graph(
            graph_db, iterator(), timedelta(seconds=30), None, task_id, wait_for_result=True
        )
        assert result == GraphUpdate(112, 1, 0, 212, 0, 0)
        edges = await outer_edge_db.all_for_task(task_id)
        assert len(edges) == 1
        elem = edges[0]
        assert elem.task_id == "test_task_123"
        assert elem.edges[0] == DeferredEdge(ByNodeId(NodeId("id_123")), ByNodeId(NodeId("id_456")), "delete")

        # make another update without wait
        current_count = graph_db.db.collection("ns").count()
        graph = create_graph("test2", width=1)
        no_result = await merger.merge_graph(
            graph_db, iterator(), timedelta(seconds=30), None, TaskId("test_task_124"), wait_for_result=False
        )
        assert no_result is None

        async def wait_for_result() -> None:
            while graph_db.db.collection("ns").count() == current_count:
                await asyncio.sleep(0.01)

        # make sure that the update is processed in the background
        await asyncio.wait_for(wait_for_result(), timeout=5)
