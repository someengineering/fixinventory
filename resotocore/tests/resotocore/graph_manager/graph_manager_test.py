from resotocore.graph_manager.graph_manager import GraphManager
from resotocore.ids import GraphName
from resotocore.db.db_access import DbAccess
from resotocore.db.model import GraphUpdate
from resotocore.model.model import Model
import pytest
from tests.resotocore.db.graphdb_test import create_multi_collector_graph
import re


@pytest.mark.asyncio
async def test_template_generation(foo_model: Model, db_access: DbAccess) -> None:
    graph_name = GraphName("test_graph")
    graph_db = await db_access.create_graph(graph_name)
    await graph_db.wipe()
    await db_access.delete_graph(GraphName("test_graph_copy"))

    # populate some data in the graphes
    nodes, info = await graph_db.merge_graph(create_multi_collector_graph(), foo_model)
    assert info == GraphUpdate(110, 1, 0, 218, 0, 0)
    assert len(nodes) == 8

    graph_manager = GraphManager(db_access)
    await graph_manager.start()

    # list
    assert GraphName("test_graph") in await graph_manager.list(".*")

    # copy
    await graph_manager.copy(GraphName("test_graph"), GraphName("test_graph_copy"), False)
    assert set(await graph_manager.list(".*")).issuperset(["test_graph", "test_graph_copy"])

    # snapshot
    await graph_manager.snapshot(GraphName("test_graph"), "label")
    graphs = await graph_manager.list(".*")
    for name in ["test_graph", "test_graph_copy", "snapshot-test_graph-label-.*"]:
        for graph in graphs:
            if re.match(name, graph):
                break
        else:
            raise AssertionError(f"Could not find graph with name {name} in {graphs}")

    # delete
    await graph_manager.delete(GraphName("test_graph_copy"))
    assert GraphName("test_graph_copy") not in set(await graph_manager.list(".*"))

    # cleanup
    for graph in await graph_manager.list(".*"):
        await graph_manager.delete(graph)
