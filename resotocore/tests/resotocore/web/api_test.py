from asyncio import sleep
from contextlib import suppress
from multiprocessing import Process
from typing import AsyncIterator, List

import pytest
from _pytest.fixtures import fixture
from aiohttp import ClientSession
from arango.database import StandardDatabase

from resotocore.__main__ import run
from resotocore.model.model import predefined_kinds, Kind
from resotocore.model.typed_model import to_js
from resotocore.util import rnd_str, AccessJson

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import foo_kinds, test_db, create_graph, system_db, local_client
from resotoclient import ResotoClient as ApiClient
from resotoclient import models as rc
from networkx import MultiDiGraph


@fixture
async def client_session() -> AsyncIterator[ClientSession]:
    session = ClientSession()
    yield session
    await session.close()


def graph_to_json(graph: MultiDiGraph) -> List[rc.JsObject]:
    ga: List[rc.JsValue] = [{**node, "type": "node"} for _, node in graph.nodes(data=True)]
    for from_node, to_node, data in graph.edges(data=True):
        ga.append({"type": "edge", "from": from_node, "to": to_node, "edge_type": data["edge_type"]})
    return ga


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
        args=(
            [
                "--graphdb-database",
                "test",
                "--graphdb-username",
                "test",
                "--graphdb-password",
                "test",
                "--debug",
                "--no-tls",
            ],
        ),
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
    yield ApiClient("http://localhost:8900", None)
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
    assert core_client.ping() == "pong"
    assert core_client.ready() == "ok"
    # make sure we get redirected to the api docs
    async with client_session.get("http://localhost:8900", allow_redirects=False) as r:
        assert r.headers["location"] == "api-doc"
    # static api docs get served
    async with client_session.get("http://localhost:8900") as r:
        assert r.content_type == "text/html"


@pytest.mark.asyncio
async def test_model_api(core_client: ApiClient) -> None:

    # GET /model
    assert len((core_client.model()).kinds) >= len(predefined_kinds)

    # PATCH /model
    string_kind: rc.Kind = rc.Kind(fqn="only_three", runtime_kind="string", properties=None, bases=None)
    setattr(string_kind, "min_length", 3)
    setattr(string_kind, "max_length", 3)

    prop = rc.Property(name="ot", kind="only_three", required=False)
    complex_kind: rc.Kind = rc.Kind(fqn="test_cpl", runtime_kind=None, properties=[prop], bases=None)
    setattr(complex_kind, "allow_unknown_props", False)

    update = core_client.update_model([string_kind, complex_kind])
    none_kind = rc.Kind(fqn="none", runtime_kind=None, properties=None, bases=None)
    assert (update.kinds.get("only_three") or none_kind).runtime_kind == "string"


@pytest.mark.asyncio
async def test_graph_api(core_client: ApiClient) -> None:
    # make sure we have a clean slate
    with suppress(Exception):
        core_client.delete_graph(g)

    # create a new graph
    graph = AccessJson(core_client.create_graph(g))
    assert graph.id == "root"
    assert graph.reported.kind == "graph_root"

    # list all graphs
    graphs = core_client.list_graphs()
    assert g in graphs

    # get one specific graph
    graph: AccessJson = AccessJson(core_client.get_graph(g))  # type: ignore
    assert graph.id == "root"
    assert graph.reported.kind == "graph_root"

    # wipe the data in the graph
    assert core_client.delete_graph(g, truncate=True) == "Graph truncated."
    assert g in core_client.list_graphs()

    # create a node in the graph
    uid = rnd_str()
    node = AccessJson(core_client.create_node("root", uid, {"identifier": uid, "kind": "child", "name": "max"}, g))
    assert node.id == uid
    assert node.reported.name == "max"

    # update a node in the graph
    node = AccessJson(core_client.patch_node(uid, {"name": "moritz"}, "reported", g))
    assert node.id == uid
    assert node.reported.name == "moritz"

    # get the node
    node = AccessJson(core_client.get_node(uid, g))
    assert node.id == uid
    assert node.reported.name == "moritz"

    # delete the node
    core_client.delete_node(uid, g)
    with pytest.raises(AttributeError):
        # node can not be found
        core_client.get_node(uid, g)

    # merge a complete graph
    merged = core_client.merge_graph(graph_to_json(create_graph("test")), g)
    assert merged == rc.GraphUpdate(112, 1, 0, 212, 0, 0)

    # batch graph update and commit
    batch1_id, batch1_info = core_client.add_to_batch(graph_to_json(create_graph("hello")), "batch1", g)
    assert batch1_info == rc.GraphUpdate(0, 100, 0, 0, 0, 0)
    assert batch1_id == "batch1"
    batch_infos = AccessJson.wrap_list(core_client.list_batches(g))
    assert len(batch_infos) == 1
    # assert batch_infos[0].id == batch1_id
    assert batch_infos[0].affected_nodes == ["collector"]  # replace node
    assert batch_infos[0].is_batch is True
    core_client.commit_batch(batch1_id, g)

    # batch graph update and abort
    batch2_id, batch2_info = core_client.add_to_batch(graph_to_json(create_graph("bonjour")), "batch2", g)
    assert batch2_info == rc.GraphUpdate(0, 100, 0, 0, 0, 0)
    assert batch2_id == "batch2"
    core_client.abort_batch(batch2_id, g)

    # update nodes
    update = [{"id": node["id"], "reported": {"name": "bruce"}} for _, node in create_graph("foo").nodes(data=True)]
    updated_nodes = core_client.patch_nodes(update, g)
    assert len(updated_nodes) == 113
    for n in updated_nodes:
        assert n.get("reported", {}).get("name") == "bruce"

    # create the raw search
    raw = core_client.search_graph_raw('id("3")', g)
    assert raw == {
        "query": "LET filter0 = (FOR m0 in graphtest FILTER m0._key == @b0  RETURN m0) "
        'FOR result in filter0 RETURN UNSET(result, ["flat"])',
        "bind_vars": {"b0": "3"},
    }

    # estimate the search
    cost = core_client.search_graph_explain('id("3")', g)
    assert cost.full_collection_scan is False
    assert cost.rating == rc.EstimatedQueryCostRating.simple

    # search list
    result_list = list(core_client.search_list('id("3") -[0:]->', graph=g))
    assert len(result_list) == 11  # one parent node and 10 child nodes
    assert result_list[0].get("id") == "3"  # first node is the parent node

    # search graph
    result_graph = list(core_client.search_graph('id("3") -[0:]->', graph=g))
    assert len(result_graph) == 21  # 11 nodes + 10 edges
    assert result_list[0].get("id") == "3"  # first node is the parent node

    # aggregate
    result_aggregate = core_client.search_aggregate("aggregate(reported.kind as kind: sum(1) as count): all", g)
    assert {r["group"]["kind"]: r["count"] for r in result_aggregate} == {
        "bla": 100,
        "cloud": 1,
        "foo": 11,
        "graph_root": 1,
    }

    # delete the graph
    assert core_client.delete_graph(g) == "Graph deleted."
    assert g not in core_client.list_graphs()


@pytest.mark.asyncio
async def test_subscribers(core_client: ApiClient) -> None:
    # provide a clean slate
    for subscriber in core_client.subscribers():
        core_client.delete_subscriber(subscriber.id)

    sub_id = rnd_str()

    # add subscription
    subscriber = core_client.add_subscription(sub_id, rc.Subscription("test"))
    assert subscriber.id == sub_id
    assert len(subscriber.subscriptions) == 1
    assert subscriber.subscriptions["test"] is not None

    # delete subscription
    subscriber = core_client.delete_subscription(sub_id, rc.Subscription("test"))
    assert subscriber.id == sub_id
    assert len(subscriber.subscriptions) == 0

    # update subscriber
    updated = core_client.update_subscriber(sub_id, [rc.Subscription("test"), rc.Subscription("rest")])
    assert updated is not None
    assert updated.id == sub_id
    assert len(updated.subscriptions) == 2

    # subscriber for message type
    assert core_client.subscribers_for_event("test") == [updated]
    assert core_client.subscribers_for_event("rest") == [updated]
    assert core_client.subscribers_for_event("does_not_exist") == []

    # get subscriber
    sub = core_client.subscriber(sub_id)
    assert sub is not None


@pytest.mark.asyncio
async def test_cli(core_client: ApiClient) -> None:
    # make sure we have a clean slate
    with suppress(Exception):
        core_client.delete_graph(g)
    core_client.create_graph(g)
    graph_update = graph_to_json(create_graph("test"))
    core_client.merge_graph(graph_update, g)

    # evaluate search with count
    result = core_client.cli_evaluate("search all | count kind", g)
    assert len(result) == 1
    parsed, to_execute = result[0]
    assert len(parsed.commands) == 2
    assert (parsed.commands[0].cmd, parsed.commands[1].cmd) == ("search", "count")
    assert len(to_execute) == 2
    assert (to_execute[0].get("cmd"), to_execute[1].get("cmd")) == ("execute_search", "aggregate_to_count")

    # execute search with count
    executed = list(core_client.cli_execute("search is(foo) or is(bla) | count kind", g))
    assert executed == ["cloud: 1", "foo: 11", "bla: 100", "total matched: 112", "total unmatched: 0"]

    # list all cli commands
    info = AccessJson(core_client.cli_info())
    assert len(info.commands) == 35


@pytest.mark.asyncio
async def test_config(core_client: ApiClient, foo_kinds: List[rc.Kind]) -> None:
    # make sure we have a clean slate
    for config in core_client.configs():
        core_client.delete_config(config)

    # define a config model
    model = core_client.update_configs_model(foo_kinds)
    assert "foo" in model.kinds
    assert "bla" in model.kinds
    # get the config model again
    get_model = core_client.get_configs_model()
    assert len(model.kinds) == len(get_model.kinds)

    # define config validation
    validation = rc.ConfigValidation("external.validated.config", external_validation=True)
    assert core_client.put_config_validation(validation) == validation

    # get the config validation
    assert core_client.get_config_validation(validation.id) == validation

    # put config
    cfg_id = rnd_str()

    # put a config with schema that is violated
    with pytest.raises(AttributeError) as ex:
        core_client.put_config(cfg_id, {"foo": {"some_int": "abc"}})
    assert "Expected type int32 but got str" in str(ex.value)

    # put a config with schema that is violated, but turn validation off
    core_client.put_config(cfg_id, {"foo": {"some_int": "abc"}}, validate=False)

    # set a simple state
    assert core_client.put_config(cfg_id, {"a": 1}) == {"a": 1}

    # patch config
    assert core_client.patch_config(cfg_id, {"a": 1}) == {"a": 1}
    assert core_client.patch_config(cfg_id, {"b": 2}) == {"a": 1, "b": 2}
    assert core_client.patch_config(cfg_id, {"c": 3}) == {"a": 1, "b": 2, "c": 3}

    # get config
    assert core_client.config(cfg_id) == {"a": 1, "b": 2, "c": 3}

    # list configs
    assert list(core_client.configs()) == [cfg_id]

    # delete config
    core_client.delete_config(cfg_id)
    assert list(core_client.configs()) == []
