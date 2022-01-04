from asyncio import sleep
from contextlib import suppress
from multiprocessing import Process
from typing import AsyncIterator, List

import pytest
from _pytest.fixtures import fixture
from aiohttp import ClientSession
from arango.database import StandardDatabase

from core.__main__ import main
from core.db.model import GraphUpdate
from core.model.model import predefined_kinds, StringKind, ComplexKind, Property, Kind
from core.model.typed_model import to_js
from core.util import rnd_str, AccessJson

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import foo_kinds, test_db, create_graph
from tests.core.web.api_client import ApiClient


@fixture
async def client_session() -> AsyncIterator[ClientSession]:
    session = ClientSession()
    yield session
    await session.close()


@fixture
async def core_client(
    client_session: ClientSession, foo_kinds: List[Kind], test_db: StandardDatabase
) -> AsyncIterator[ApiClient]:
    """
    Note: adding this fixture to a test: a complete ckcore process is started.
          The fixture ensures that the underlying process has entered the ready state.
          It also ensures to clean up the process, when the test is done.
    """

    # wipe and cleanly import the test model
    test_db.collection("model").truncate()
    test_db.collection("model").insert_many([{"_key": elem.fqn, **to_js(elem)} for elem in foo_kinds])

    process = Process(
        target=main, args=(["--graphdb-database", "test", "--graphdb-username", "test", "--graphdb-password", "test"],)
    )
    process.start()
    ready = False
    count = 10
    while not ready:
        await sleep(0.5)
        with suppress(Exception):
            async with client_session.get("http://localhost:8900/system/ready"):
                ready = True
                count -= 1
                if count == 0:
                    raise AssertionError("Process does not came up as expected")
    yield ApiClient("http://localhost:8900", client_session)
    # kill the process
    process.terminate()
    process.join(5)
    process.close()


@pytest.mark.asyncio
async def test_model_api(core_client: ApiClient) -> None:

    # GET /model
    assert len((await core_client.model()).kinds) >= len(predefined_kinds)

    # PATCH /model
    update = await core_client.update_model(
        [
            StringKind("only_three", min_length=3, max_length=3),
            ComplexKind("test_cpl", [], [Property("ot", "only_three")]),
        ]
    )
    assert isinstance(update.get("only_three"), StringKind)


@pytest.mark.asyncio
async def test_graph_api(core_client: ApiClient) -> None:
    # create a new graph
    g = "graphtest"
    graph = await core_client.create_graph(g)
    assert graph.id == "root"
    assert graph.kinds == ["graph_root"]
    assert graph.reported.kind == "graph_root"

    # list all graphs
    graphs = await core_client.list_graphs()
    assert g in graphs

    # get one specific graph
    graph: AccessJson = await core_client.get_graph(g)  # type: ignore
    assert graph.id == "root"
    assert graph.kinds == ["graph_root"]
    assert graph.reported.kind == "graph_root"

    # wipe the data in the graph
    assert await core_client.delete_graph(g, truncate=True) == "Graph truncated."
    assert g in await core_client.list_graphs()

    # create a node in the graph
    uid = rnd_str()
    node = await core_client.create_node(g, "root", uid, {"identifier": uid, "kind": "child", "name": "max"})
    assert node.id == uid
    assert node.reported.name == "max"

    # update a node in the graph
    node = await core_client.patch_node(g, uid, {"name": "moritz"}, "reported")
    assert node.id == uid
    assert node.reported.name == "moritz"

    # get the node
    node = await core_client.get_node(g, uid)
    assert node.id == uid
    assert node.reported.name == "moritz"

    # delete the node
    await core_client.delete_node(g, uid)
    with pytest.raises(AttributeError):
        # node can not be found
        await core_client.get_node(g, uid)

    # batch update
    merged = await core_client.merge_graph(g, create_graph("test"))
    assert merged == GraphUpdate(112, 1, 0, 112, 0, 0)

    # update nodes
    update = [{"id": node["id"], "reported": {"name": "bruce"}} for _, node in create_graph("foo").nodes(data=True)]
    updated_nodes = await core_client.patch_nodes(g, update)
    assert len(updated_nodes) == 113
    for n in updated_nodes:
        assert n.reported.name == "bruce"

    # delete the graph
    assert await core_client.delete_graph(g) == "Graph deleted."
    assert g not in await core_client.list_graphs()
