import json
from datetime import timedelta
from multiprocessing import set_start_method
from typing import List, AsyncGenerator

import pytest

from resotocore.analytics import AnalyticsEventSender
from resotocore.db.graphdb import ArangoGraphDB
from resotocore.db.model import GraphUpdate
from resotocore.dependencies import empty_config
from resotocore.ids import TaskId
from resotocore.model.db_updater import merge_graph_process
from resotocore.model.model import Kind
from resotocore.model.typed_model import to_js
from resotocore.db.deferred_edge_db import outer_edge_db

# noinspection PyUnresolvedReferences
from tests.resotocore.analytics import event_sender
from tests.resotocore.db.graphdb_test import create_graph

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import graph_db, foo_kinds, test_db, local_client, system_db


@pytest.mark.asyncio
async def test_merge_process(
    event_sender: AnalyticsEventSender, graph_db: ArangoGraphDB, foo_kinds: List[Kind]
) -> None:
    # set explicitly (is done in main explicitly as well)
    set_start_method("spawn")

    # wipe any existing data
    await graph_db.wipe()
    # store the model in db, so it can be loaded by the sub process
    graph_db.db.collection("model").insert_many([to_js(a) for a in foo_kinds])
    # define args to parse for the sub process
    config = empty_config(["--graphdb-username", "test", "--graphdb-password", "test", "--graphdb-database", "test"])
    # create sample graph data to insert
    graph = create_graph("test")

    await outer_edge_db(graph_db.db, "deferred_outer_edges").create_update_schema()

    async def iterator() -> AsyncGenerator[bytes, None]:
        for node in graph.nodes():
            yield bytes(json.dumps(graph.nodes[node]), "utf-8")
        for from_node, to_node, data in graph.edges(data=True):
            yield bytes(json.dumps({"from": from_node, "to": to_node, "edge_type": data["edge_type"]}), "utf-8")
        yield bytes(
            json.dumps(
                {"from_selector": {"node_id": "id_123"}, "to_selector": {"node_id": "id_456"}, "edge_type": "delete"}
            ),
            "utf-8",
        )

    result = await merge_graph_process(
        graph_db, event_sender, config, iterator(), timedelta(seconds=30), None, TaskId("test_task_123")
    )
    assert result == GraphUpdate(112, 1, 0, 212, 0, 0)
    elem = graph_db.db.collection("deferred_outer_edges").get("test_task_123")
    assert elem["_key"] == "test_task_123"
    assert elem["task_id"] == "test_task_123"
    assert elem["edges"][0] == {"from_node": {"value": "id_123"}, "to_node": {"value": "id_456"}, "edge_type": "delete"}
