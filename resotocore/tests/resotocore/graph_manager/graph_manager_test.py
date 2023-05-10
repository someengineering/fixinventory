from typing import AsyncIterator, List, cast
from resotocore.graph_manager.graph_manager import GraphManager
from resotocore.ids import GraphName
from resotocore.db.db_access import DbAccess
from resotocore.db.model import GraphUpdate
from resotocore.model.model import Model
from resotocore.types import Json
import pytest
from tests.resotocore.db.graphdb_test import create_multi_collector_graph
import re


@pytest.mark.asyncio
async def test_graph_manager(foo_model: Model, db_access: DbAccess) -> None:
    graph_name = GraphName("test_graph")
    graph_db = await db_access.create_graph(graph_name)
    await graph_db.wipe()

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

    # test export and import
    dump = []
    async for string in graph_manager.db_access.export_graph(GraphName("test_graph")):
        dump.append(string)

    async def dump_iter() -> AsyncIterator[str]:
        for string in dump:
            yield string

    await graph_manager.import_graph(GraphName("test_graph_import"), dump_iter(), True)
    # check vertices count
    original_vertices_count = await db_access.db.count("test_graph")
    imported_vertices_count = await db_access.db.count("test_graph_import")
    assert original_vertices_count == imported_vertices_count

    async def collect_docs(graph_name: str) -> List[Json]:
        vertices = []
        async with await db_access.db.aql_cursor(f"for v in {graph_name} return v") as cursor:
            async for vertex in cursor:
                vertex = cast(Json, vertex)
                if vertex.get("_key") == "root":
                    continue
                # remove the fields that are going to be different after the import
                vertex.pop("_id")
                vertex.pop("_rev")
                vertex.pop("hash", None)
                vertex.pop("_from", None)
                vertex.pop("_to", None)
                vertices.append(vertex)

        return sorted(vertices, key=lambda doc: doc["_key"])  # type: ignore

    # check vertices content after import
    original_vertices = await collect_docs("test_graph")
    imported_vertices = await collect_docs("test_graph_import")
    assert original_vertices == imported_vertices

    # check default edges after import
    assert await db_access.db.count("test_graph_default") == await db_access.db.count("test_graph_import_default")
    original_default_edges = await collect_docs("test_graph_default")
    imported_default_edges = await collect_docs("test_graph_import_default")
    assert original_default_edges == imported_default_edges

    # check delete edges after import
    assert await db_access.db.count("test_graph_delete") == await db_access.db.count("test_graph_import_delete")
    orignal_delete_edges = await collect_docs("test_graph_delete")
    imported_delete_edges = await collect_docs("test_graph_import_delete")
    assert orignal_delete_edges == imported_delete_edges

    # check model after import
    assert await db_access.db.count("test_graph_model") == await db_access.db.count("test_graph_import_model")
    assert await collect_docs("test_graph_model") == await collect_docs("test_graph_import_model")

    # cleanup
    for graph in await graph_manager.list(".*"):
        await graph_manager.delete(graph)
