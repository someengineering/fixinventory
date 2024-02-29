from typing import AsyncIterator, List, cast

from attr import evolve

from fixcore.graph_manager.graph_manager import GraphManager
from fixcore.ids import GraphName
from fixcore.db.db_access import DbAccess, _compress_timestamps
from fixcore.db.model import GraphUpdate
from fixcore.model.model import Model
from fixcore.types import Json
from fixcore.config.core_config_handler import CoreConfigHandler
from fixcore.core_config import SnapshotsScheduleConfig, SnapshotSchedule, FixCoreSnapshotsConfigId
from fixcore.task import TaskHandler
import pytest
from tests.fixcore.db.graphdb_test import create_multi_collector_graph
import re
from fixlib.utils import utc
from datetime import timedelta


@pytest.mark.asyncio
async def test_graph_manager(
    foo_model: Model,
    db_access: DbAccess,
    core_config_handler: CoreConfigHandler,
    task_handler: TaskHandler,
) -> None:
    # test setup
    graph_name = GraphName("test_graph")
    graph_db = await db_access.create_graph(graph_name, validate_name=False)
    await graph_db.wipe()
    await db_access.delete_graph(GraphName("test_graph_copy"))

    # test timestamp compression:
    assert _compress_timestamps("test_graph") == "test_graph"
    assert _compress_timestamps("foo123") == "foo123"
    assert _compress_timestamps("foo_2023-05-24T14:06:50+0000") == "foo_20230524T140650Z"
    assert _compress_timestamps("2023-05-24T14:06:50+0000_foo") == "20230524T140650Z_foo"
    assert (
        _compress_timestamps("foo_2023-05-24T14:06:50+0000_bar_2023-05-24T14:06:50+0000")
        == "foo_20230524T140650Z_bar_20230524T140650Z"
    )
    assert (
        _compress_timestamps("foo-bar-graph-label-2023-05-24T14:06:50+0000") == "foo-bar-graph-label-20230524T140650Z"
    )

    # populate some data in the graphes
    nodes, info = await graph_db.merge_graph(create_multi_collector_graph(), foo_model)
    assert info == GraphUpdate(110, 1, 0, 218, 0, 0)
    assert len(nodes) == 8

    config = evolve(core_config_handler.config, snapshots=SnapshotsScheduleConfig(snapshots={}))
    graph_manager = GraphManager(db_access, config, core_config_handler, task_handler)
    await graph_manager.start()

    # list
    assert GraphName("test_graph") in await graph_manager.list(".*")

    # copy
    await graph_manager.copy(GraphName("test_graph"), GraphName("test_graph_copy"), False, False)
    assert set(await graph_manager.list(".*")).issuperset(["test_graph", "test_graph_copy"])

    # snapshot
    now = utc()
    await graph_manager.snapshot(GraphName("test_graph"), "label", timestamp=now)
    graphs = await graph_manager.list(".*")
    for name in ["test_graph", "test_graph_copy", "snapshot-test_graph-label-.*"]:
        for graph in graphs:
            if re.match(name, graph):
                break
        else:
            raise AssertionError(f"Could not find graph with name {name} in {graphs}")

    # snapshots at specific time
    now = now + timedelta(seconds=42)
    await graph_manager.snapshot(GraphName("test_graph"), "label", timestamp=now)
    somewhere_in_the_past = now
    now = now + timedelta(seconds=42)
    await graph_manager.snapshot(GraphName("test_graph"), "label", timestamp=now)
    now = now + timedelta(seconds=42)
    await graph_manager.snapshot(GraphName("test_graph"), "label", timestamp=now)
    found = await graph_manager.snapshot_at(time=somewhere_in_the_past, graph_name=GraphName("test_graph"))
    assert found is not None

    # test snapshot cleanup
    await graph_manager._clean_outdated_snapshots(
        SnapshotsScheduleConfig(snapshots={"label": SnapshotSchedule("0 1 2 3 4", 0)})
    )
    graphs = await graph_manager.list(".*")
    for graph in graphs:
        if re.match("snapshot-test_graph-label-.*", graph):
            raise AssertionError(f"Found outdated snapshot {graph} in {graphs}")

    # no snapshots after the cleanup
    assert await graph_manager.snapshot_at(time=somewhere_in_the_past, graph_name=GraphName("test_graph")) is None

    # delete
    await graph_manager.delete(GraphName("test_graph_copy"))
    assert GraphName("test_graph_copy") not in set(await graph_manager.list(".*"))

    # periodic snapshot callback
    for job in await task_handler.list_jobs():
        await task_handler.delete_job(job.id, force=True)
    jobs = await task_handler.list_jobs()
    # let's schedule something
    await graph_manager._on_config_updated(FixCoreSnapshotsConfigId)
    jobs = await task_handler.list_jobs()
    assert len(jobs) == 5
    assert jobs[0].name == "fix:snapshots:hourly"

    # test export and import
    dump = []
    test_graph_model = await db_access.get_graph_model_db(GraphName("test_graph"))
    await test_graph_model.update_many(list(foo_model.kinds.values()))
    async for string in graph_manager.export_graph(GraphName("test_graph")):
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

        return sorted(vertices, key=lambda doc: doc["_key"])

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
        await db_access.delete_graph(graph)
        await db_access.delete_graph_model(graph)
