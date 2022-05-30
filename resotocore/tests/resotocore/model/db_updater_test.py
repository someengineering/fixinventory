import json
from datetime import timedelta
from multiprocessing import set_start_method
from typing import List, AsyncGenerator

import pytest

from resotocore.analytics import AnalyticsEventSender
from resotocore.db.graphdb import ArangoGraphDB
from resotocore.db.model import GraphUpdate
from resotocore.dependencies import empty_config
from resotocore.model.db_updater import merge_graph_process
from resotocore.model.model import Kind
from resotocore.model.typed_model import to_js

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

    async def iterator() -> AsyncGenerator[bytes, None]:
        for node in graph.nodes():
            yield bytes(json.dumps(graph.nodes[node]), "utf-8")
        for from_node, to_node, data in graph.edges(data=True):
            yield bytes(json.dumps({"from": from_node, "to": to_node, "edge_type": data["edge_type"]}), "utf-8")

    result = await merge_graph_process(graph_db, event_sender, config, iterator(), timedelta(seconds=30), None, None)
    assert result == GraphUpdate(112, 1, 0, 212, 0, 0)
