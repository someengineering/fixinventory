from asyncio import sleep
from contextlib import suppress
from multiprocessing import Process
from typing import AsyncIterator, List

import pytest
from _pytest.fixtures import fixture
from aiohttp import ClientSession
from arango.database import StandardDatabase

from resotocore.__main__ import run
from resotocore.db import EstimatedQueryCostRating
from resotocore.db.model import GraphUpdate
from resotocore.model.model import predefined_kinds, Kind, StringKind, ComplexKind, Property
from resotocore.model.typed_model import to_js
from resotocore.task.model import Subscription
from resotocore.util import rnd_str, AccessJson

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import foo_kinds, test_db, create_graph, system_db, local_client
from tests.resotocore.web.api_client import ApiClient


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
    Note: adding this fixture to a test: a complete resotocore process is started.
          The fixture ensures that the underlying process has entered the ready state.
          It also ensures to clean up the process, when the test is done.
    """

    # wipe and cleanly import the test model
    test_db.collection("model").truncate()
    test_db.collection("model").insert_many([{"_key": elem.fqn, **to_js(elem)} for elem in foo_kinds])

    process = Process(
        target=run,
        args=(["--graphdb-database", "test", "--graphdb-username", "test", "--graphdb-password", "test", "--debug"],),
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
    # terminate the process
    process.terminate()
    process.join(5)
    # if it is still running, kill it
    if process.is_alive():
        process.kill()
        process.join()
    process.close()


g = "graphtest"


@pytest.mark.asyncio
async def test_system_api(core_client: ApiClient, client_session: ClientSession) -> None:
    assert await core_client.ping() == "pong"
    assert await core_client.ready() == "ok"
    # make sure we get redirected to the api docs
    async with client_session.get("http://localhost:8900", allow_redirects=False) as r:
        assert r.headers["location"] == "api-doc"
    # static api docs get served
    async with client_session.get("http://localhost:8900") as r:
        assert r.content_type == "text/html"


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
    # make sure we have a clean slate
    with suppress(Exception):
        await core_client.delete_graph(g)

    # create a new graph
    graph = await core_client.create_graph(g)
    assert graph.id == "root"
    assert graph.reported.kind == "graph_root"

    # list all graphs
    graphs = await core_client.list_graphs()
    assert g in graphs

    # get one specific graph
    graph: AccessJson = await core_client.get_graph(g)  # type: ignore
    assert graph.id == "root"
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

    # merge a complete graph
    merged = await core_client.merge_graph(g, create_graph("test"))
    assert merged == GraphUpdate(112, 1, 0, 212, 0, 0)

    # batch graph update and commit
    batch1_id, batch1_info = await core_client.add_to_batch(g, create_graph("hello"), "batch1")
    # assert batch1_info == GraphUpdate(0, 100, 0, 0, 0, 0)
    assert batch1_id == "batch1"
    batch_infos = await core_client.list_batches(g)
    assert len(batch_infos) == 1
    # assert batch_infos[0].id == batch1_id
    assert batch_infos[0].affected_nodes == ["collector"]  # replace node
    assert batch_infos[0].is_batch is True
    await core_client.commit_batch(g, batch1_id)

    # batch graph update and abort
    batch2_id, batch2_info = await core_client.add_to_batch(g, create_graph("bonjour"), "batch2")
    assert batch2_info == GraphUpdate(0, 100, 0, 0, 0, 0)
    assert batch2_id == "batch2"
    await core_client.abort_batch(g, batch2_id)

    # update nodes
    update = [{"id": node["id"], "reported": {"name": "bruce"}} for _, node in create_graph("foo").nodes(data=True)]
    updated_nodes = await core_client.patch_nodes(g, update)
    assert len(updated_nodes) == 113
    for n in updated_nodes:
        assert n.reported.name == "bruce"

    # create the raw search
    raw = await core_client.search_graph_raw(g, 'id("3")')
    assert raw == {
        "query": "LET filter0 = (FOR m0 in graphtest FILTER m0._key == @b0  RETURN m0) "
        'FOR result in filter0 RETURN UNSET(result, ["flat"])',
        "bind_vars": {"b0": "3"},
    }

    # estimate the search
    cost = await core_client.search_graph_explain(g, 'id("3")')
    assert cost.full_collection_scan is False
    assert cost.rating == EstimatedQueryCostRating.simple

    # search list
    result_list = await core_client.search_list(g, 'id("3") -[0:]->')
    assert len(result_list) == 11  # one parent node and 10 child nodes
    assert result_list[0].id == "3"  # first node is the parent node

    # search graph
    result_graph = await core_client.search_graph(g, 'id("3") -[0:]->')
    assert len(result_graph) == 21  # 11 nodes + 10 edges
    assert result_list[0].id == "3"  # first node is the parent node

    # aggregate
    result_aggregate = await core_client.search_aggregate(g, "aggregate(reported.kind as kind: sum(1) as count): all")
    assert {r.group.kind: r.count for r in result_aggregate} == {"bla": 100, "cloud": 1, "foo": 11, "graph_root": 1}

    # delete the graph
    assert await core_client.delete_graph(g) == "Graph deleted."
    assert g not in await core_client.list_graphs()


@pytest.mark.asyncio
async def test_subscribers(core_client: ApiClient) -> None:
    # provide a clean slate
    for subscriber in await core_client.subscribers():
        await core_client.delete_subscriber(subscriber.id)

    sub_id = rnd_str()

    # add subscription
    subscriber = await core_client.add_subscription(sub_id, Subscription("test"))
    assert subscriber.id == sub_id
    assert len(subscriber.subscriptions) == 1
    assert subscriber.subscriptions["test"] is not None

    # delete subscription
    subscriber = await core_client.delete_subscription(sub_id, Subscription("test"))
    assert subscriber.id == sub_id
    assert len(subscriber.subscriptions) == 0

    # update subscriber
    updated = await core_client.update_subscriber(sub_id, [Subscription("test"), Subscription("rest")])
    assert updated is not None
    assert updated.id == sub_id
    assert len(updated.subscriptions) == 2

    # subscriber for message type
    assert await core_client.subscribers_for_event("test") == [updated]
    assert await core_client.subscribers_for_event("rest") == [updated]
    assert await core_client.subscribers_for_event("does_not_exist") == []

    # get subscriber
    sub = await core_client.subscriber(sub_id)
    assert sub is not None


@pytest.mark.asyncio
async def test_cli(core_client: ApiClient) -> None:
    # make sure we have a clean slate
    with suppress(Exception):
        await core_client.delete_graph(g)
    await core_client.create_graph(g)
    await core_client.merge_graph(g, create_graph("test"))

    # evaluate search with count
    result = await core_client.cli_evaluate(g, "search all | count kind")
    assert len(result) == 1
    parsed, to_execute = result[0]
    assert len(parsed.commands) == 2
    assert (parsed.commands[0].cmd, parsed.commands[1].cmd) == ("search", "count")
    assert len(to_execute) == 2
    assert (to_execute[0].cmd, to_execute[1].cmd) == ("execute_search", "aggregate_to_count")

    # execute search with count
    executed = await core_client.cli_execute(g, "search is(foo) or is(bla) | count kind")
    assert executed == ["cloud: 1", "foo: 11", "bla: 100", "total matched: 112", "total unmatched: 0"]

    # list all cli commands
    info = await core_client.cli_info()
    assert len(info.commands) == 32


@pytest.mark.asyncio
async def test_config(core_client: ApiClient) -> None:
    # make sure we have a clean slate
    for config in await core_client.configs():
        await core_client.delete_config(config)

    # add/update config
    cfg_id = rnd_str()
    assert await core_client.patch_config(cfg_id, {"a": 1}) == {"a": 1}
    assert await core_client.patch_config(cfg_id, {"b": 2}) == {"a": 1, "b": 2}
    assert await core_client.patch_config(cfg_id, {"c": 3}) == {"a": 1, "b": 2, "c": 3}

    # get config
    assert await core_client.config(cfg_id) == {"a": 1, "b": 2, "c": 3}

    # list configs
    assert await core_client.configs() == [cfg_id]

    # delete config
    await core_client.delete_config(cfg_id)
    assert await core_client.configs() == []
