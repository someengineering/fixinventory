from asyncio import sleep
from contextlib import suppress, asynccontextmanager
from multiprocessing import Process
from typing import AsyncIterator, List, Optional
from pathlib import Path
import tempfile


import pytest
from _pytest.fixtures import fixture
from aiohttp import ClientSession, MultipartReader
from networkx import MultiDiGraph
from datetime import timedelta
from fixclient import models as rc
from fixclient.async_client import FixInventoryClient
from fixclient.json_utils import json_loadb
from fixclient.models import JsObject
from fixcore.report import ReportCheck, Benchmark

from fixlib.utils import get_free_port
from tests.fixcore import create_graph
from fixcore.__main__ import run
from fixcore.analytics import AnalyticsEvent
from fixcore.db.db_access import DbAccess
from fixcore.model.model import predefined_kinds, Kind
from fixcore.model.typed_model import to_js
from fixcore.util import rnd_str, AccessJson, utc, utc_str
from fixcore.ids import GraphName


def graph_to_json(graph: MultiDiGraph) -> List[rc.JsObject]:
    ga: List[rc.JsValue] = [{**node, "type": "node"} for _, node in graph.nodes(data=True)]
    for from_node, to_node, data in graph.edges(data=True):
        ga.append({"type": "edge", "from": from_node, "to": to_node, "edge_type": data["edge_type"]})
    return ga


@fixture
async def core_client(
    client_session: ClientSession, foo_kinds: List[Kind], db_access: DbAccess
) -> AsyncIterator[FixInventoryClient]:
    async with create_core_client(client_session, foo_kinds, db_access, None) as client:
        yield client


@fixture
async def core_client_with_psk(
    client_session: ClientSession, foo_kinds: List[Kind], db_access: DbAccess
) -> AsyncIterator[FixInventoryClient]:
    async with create_core_client(client_session, foo_kinds, db_access, psk="test") as client:
        yield client


@asynccontextmanager
async def create_core_client(
    client_session: ClientSession,
    foo_kinds: List[Kind],
    db_access: DbAccess,
    psk: Optional[str] = None,
) -> AsyncIterator[FixInventoryClient]:
    """
    Note: adding this fixture to a test: a complete fixcore process is started.
          The fixture ensures that the underlying process has entered the ready state.
          It also ensures to clean up the process, when the test is done.
    """
    http_port = get_free_port()  # use a different port than the default one
    additional_args = ["--psk", psk] if psk else []

    # wipe and cleanly import the test model
    for graph_name in [g, "test", "hello", "bonjour", "foo", "fix"]:
        db = await db_access.get_graph_model_db(GraphName(graph_name))
        await db.create_update_schema()
        await db.wipe()
        await db.update_many(foo_kinds)

    config_dir = tempfile.TemporaryDirectory()
    # todo: do not restart after the config override was loaded for the very first time and uncomment this part

    config_path = Path(config_dir.name) / "test_override_config_id.yaml"

    with config_path.open("w") as override_config:
        override_config.write(
            """
l1:
    l2: 42
        """
        )

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
                "--analytics-opt-out",
                "--no-scheduling",
                "--ignore-interrupted-tasks",
                "--override",
                f"fixcore.api.https_port=null",
                f"fixcore.api.http_port={http_port}",
                "fixcore.api.web_hosts=0.0.0.0",
                "--override-path",
                str(config_path),
                *additional_args,
            ],
        ),
    )
    process.start()
    ready = False
    count = 20
    while not ready:
        await sleep(0.5)
        with suppress(Exception):
            async with client_session.get(f"http://localhost:{http_port}/system/ready"):
                ready = True
        count -= 1
        if count == 0:
            raise AssertionError("Process does not came up as expected")
    async with FixInventoryClient(f"http://localhost:{http_port}", psk=psk) as client:
        yield client
    # terminate the process
    process.terminate()
    process.join(5)
    # if it is still running, kill it
    if process.is_alive():
        process.kill()
        process.join()
    process.close()
    config_dir.cleanup()


g = "graphtest"


@pytest.mark.asyncio
async def test_system_api(core_client: FixInventoryClient, client_session: ClientSession) -> None:
    assert await core_client.ping() == "pong"
    assert await core_client.ready() == "ok"
    # make sure we get redirected to the api docs
    async with client_session.get(core_client.fixcore_url, allow_redirects=False) as r:
        assert r.status == 200
    # analytics events can be sent to the server
    events = [AnalyticsEvent("test", "test.event", {"foo": "bar"}, {"counter": 1}, utc())]
    async with client_session.post(core_client.fixcore_url + "/analytics", json=to_js(events)) as r:
        assert r.status == 204


@pytest.mark.asyncio
async def test_model_api(core_client: FixInventoryClient, client_session: ClientSession) -> None:
    # GET /model
    assert len((await core_client.model()).kinds) >= len(predefined_kinds)

    # PATCH /model
    string_kind: rc.Kind = rc.Kind(fqn="only_three", runtime_kind="string", properties=None, bases=None)
    setattr(string_kind, "min_length", 3)
    setattr(string_kind, "max_length", 3)

    prop = rc.Property(name="ot", kind="only_three", required=False, metadata={"len": 3})
    complex_kind: rc.Kind = rc.Kind(fqn="test_cpl", runtime_kind=None, properties=[prop], bases=None, metadata={"a": 1})
    setattr(complex_kind, "allow_unknown_props", False)

    update = await core_client.update_model([string_kind, complex_kind])
    assert update.kinds["only_three"].runtime_kind == "string"
    assert update.kinds["test_cpl"].metadata["a"] == 1
    assert update.kinds["test_cpl"].properties[0].metadata["len"] == 3

    # GET /model/uml
    async with client_session.get(core_client.fixcore_url + "/model/uml", params={"output": "puml"}) as r:
        assert r.status == 200
        assert r.headers["content-type"] == "text/plain"
        puml = await r.text()
        assert puml.startswith("@startuml")
        assert puml.endswith("@enduml")


@pytest.mark.asyncio
async def test_graph_api(core_client: FixInventoryClient) -> None:
    # make sure we have a clean slate
    with suppress(Exception):
        await core_client.delete_graph(g)

    # create a new graph
    graph = AccessJson(await core_client.create_graph(g))
    assert graph.id == "root"
    assert graph.reported.kind == "graph_root"

    # list all graphs
    graphs = await core_client.list_graphs()
    assert g in graphs

    # get one specific graph
    graph: AccessJson = AccessJson(await core_client.get_graph(g))  # type: ignore
    assert graph.id == "root"
    assert graph.reported.kind == "graph_root"

    # wipe the data in the graph
    assert await core_client.delete_graph(g, truncate=True) == "Graph truncated."
    assert g in await core_client.list_graphs()

    # create a node in the graph
    uid = rnd_str()
    node = AccessJson(await core_client.create_node("root", uid, {"id": uid, "kind": "child", "name": "max"}, g))
    assert node.id == uid
    assert node.reported.name == "max"

    # update a node in the graph
    node = AccessJson(await core_client.patch_node(uid, {"name": "moritz"}, "reported", g))
    assert node.id == uid
    assert node.reported.name == "moritz"

    # update the metadata section
    node = AccessJson(await core_client.patch_node(uid, {"name": "moritz"}, "metadata", g))
    assert node.id == uid
    assert node.metadata.name == "moritz"

    # update the desired section
    node = AccessJson(await core_client.patch_node(uid, {"name": "moritz"}, "desired", g))
    assert node.id == uid
    assert node.desired.name == "moritz"

    # get the node
    node = AccessJson(await core_client.get_node(uid, g))
    assert node.id == uid
    assert node.reported.name == "moritz"

    # delete the node
    await core_client.delete_node(uid, g)
    with pytest.raises(AttributeError):
        # node can not be found
        await core_client.get_node(uid, g)

    # merge a complete graph
    merged = await core_client.merge_graph(graph_to_json(create_graph("test")), g)
    assert merged == rc.GraphUpdate(112, 1, 0, 212, 0, 0)

    # batch graph update and commit
    batch1_id, batch1_info = await core_client.add_to_batch(graph_to_json(create_graph("hello")), "batch1", g)
    assert batch1_info == rc.GraphUpdate(0, 100, 0, 0, 0, 0)
    assert batch1_id == "batch1"
    batch_infos = AccessJson.wrap_list(await core_client.list_batches(g))
    assert len(batch_infos) == 1
    # assert batch_infos[0].id == batch1_id
    assert batch_infos[0].affected_nodes == ["collector"]  # replace node
    assert batch_infos[0].is_batch is True
    await core_client.commit_batch(batch1_id, g)

    # batch graph update and abort
    batch2_id, batch2_info = await core_client.add_to_batch(graph_to_json(create_graph("bonjour")), "batch2", g)
    assert batch2_info == rc.GraphUpdate(0, 100, 0, 0, 0, 0)
    assert batch2_id == "batch2"
    await core_client.abort_batch(batch2_id, g)

    # update nodes
    update = [{"id": node["id"], "reported": {"name": "bruce"}} for _, node in create_graph("foo").nodes(data=True)]
    updated_nodes = await core_client.patch_nodes(update, g)
    assert len(updated_nodes) == 113
    for n in updated_nodes:
        assert n.get("reported", {}).get("name") == "bruce"

    # create the raw search
    raw = await core_client.search_graph_raw('id("3")', g)
    assert raw == {
        "query": "LET filter0 = (FOR m0 in `graphtest` FILTER m0._key == @b0  RETURN m0) "
        'FOR result in filter0 RETURN UNSET(result, ["flat"])',
        "bind_vars": {"b0": "3"},
    }

    # estimate the search
    cost = await core_client.search_graph_explain('id("3")', g)
    assert cost.full_collection_scan is False
    assert cost.rating == rc.EstimatedQueryCostRating.simple

    # search list
    result_list = [res async for res in core_client.search_list('id("3") -[0:]->', graph=g)]
    assert len(result_list) == 11  # one parent node and 10 child nodes
    assert result_list[0].get("id") == "3"  # first node is the parent node

    # search graph
    result_graph = [res async for res in core_client.search_graph('id("3") -[0:]->', graph=g)]
    assert len(result_graph) == 21  # 11 nodes + 10 edges
    assert result_list[0].get("id") == "3"  # first node is the parent node

    # search graph at specific timestamp
    async def search_graph_at(
        search: str, section: Optional[str] = "reported", graph: str = "fix", at: Optional[str] = None
    ) -> AsyncIterator[JsObject]:
        params = {}
        if section:
            params["section"] = section
        if at:
            params["at"] = at
        response = await core_client._post(f"/graph/{graph}/search/graph", params=params, data=search, stream=True)
        if response.status_code == 200:
            async for line in response.async_iter_lines():
                yield json_loadb(line)
        else:
            raise AttributeError(await response.text())

    with pytest.raises(AttributeError):
        # no snapshots 420 weeks ago
        result = [
            res
            async for res in search_graph_at('id("3") -[0:]->', graph=g, at=(utc() - timedelta(weeks=420)).isoformat())
        ]
        assert len(result) == 0

    # create a snapshot
    async for _ in core_client.cli_execute("graph snapshot graphtest test_label"):
        pass
    # now we should see some snapshots
    result_graph = [res async for res in search_graph_at('id("3") -[0:]->', graph=g, at=utc_str())]
    assert len(result_graph) == 21  # 11 nodes + 10 edges

    # aggregate
    result_aggregate = core_client.search_aggregate("aggregate(kind as kind: sum(1) as count): all", graph=g)
    assert {r["group"]["kind"]: r["count"] async for r in result_aggregate} == {
        "account": 1,
        "bla": 100,
        "cloud": 1,
        "foo": 10,
        "graph_root": 1,
    }

    # delete the graph
    assert await core_client.delete_graph(g) == "Graph deleted."
    assert g not in await core_client.list_graphs()


@pytest.mark.asyncio
async def test_subscribers(core_client: FixInventoryClient) -> None:
    # provide a clean slate
    for subscriber in await core_client.subscribers():
        await core_client.delete_subscriber(subscriber.id)

    sub_id = rnd_str()

    # add subscription
    subscriber = await core_client.add_subscription(sub_id, rc.Subscription("test"))
    assert subscriber.id == sub_id
    assert len(subscriber.subscriptions) == 1
    assert subscriber.subscriptions["test"] is not None

    # delete subscription
    subscriber = await core_client.delete_subscription(sub_id, rc.Subscription("test"))
    assert subscriber.id == sub_id
    assert len(subscriber.subscriptions) == 0

    # update subscriber
    updated = await core_client.update_subscriber(sub_id, [rc.Subscription("test"), rc.Subscription("rest")])
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
async def test_cli(core_client: FixInventoryClient) -> None:
    # make sure we have a clean slate
    with suppress(Exception):
        await core_client.delete_graph(g)
    await core_client.create_graph(g)
    graph_update = graph_to_json(create_graph("test"))
    await core_client.merge_graph(graph_update, g)

    # evaluate search with count
    result = await core_client.cli_evaluate("search all | count kind", g)
    assert len(result) == 1
    parsed, to_execute = result[0]
    assert len(parsed.commands) == 2
    assert (parsed.commands[0].cmd, parsed.commands[1].cmd) == ("search", "count")
    assert len(to_execute) == 3
    assert (to_execute[0].get("cmd"), to_execute[1].get("cmd")) == ("execute_search", "aggregate_to_count")

    # execute search with count
    executed = [
        result async for result in core_client.cli_execute("search (is(foo, bla)) and not is(account) | count kind", g)
    ]
    assert executed == ["cloud: 1", "foo: 10", "bla: 100", "total matched: 111", "total unmatched: 0"]

    # execute multiple commands
    response = await core_client.cli_execute_raw("echo foo; echo bar; echo bla")
    reader: MultipartReader = MultipartReader.from_response(response.undrelying)  # type: ignore
    assert [await p.text() async for p in reader] == ['"foo"', '"bar"', '"bla"']

    # list all cli commands
    info = AccessJson(await core_client.cli_info())
    assert len(info.commands) == 46


@pytest.mark.asyncio
async def test_config(core_client: FixInventoryClient, foo_kinds: List[rc.Kind]) -> None:
    # make sure we have a clean slate
    async for config in core_client.configs():
        await core_client.delete_config(config)

    # define a config model
    model = await core_client.update_configs_model(foo_kinds)
    assert "foo" in model.kinds
    assert "bla" in model.kinds
    # get the config model again
    get_model = await core_client.get_configs_model()
    assert len(model.kinds) == len(get_model.kinds)

    # define config validation
    validation = rc.ConfigValidation("external.validated.config", external_validation=True)
    assert await core_client.put_config_validation(validation) == validation

    # get the config validation
    assert await core_client.get_config_validation(validation.id) == validation

    # put config
    cfg_id = rnd_str()

    # put a config with schema that is violated
    with pytest.raises(AttributeError) as ex:
        await core_client.put_config(cfg_id, {"foo": {"some_int": "abc"}})
    assert "Expected type int32 but got str" in str(ex.value)

    # put a config with schema that is violated, but turn validation off
    await core_client.put_config(cfg_id, {"foo": {"some_int": "abc"}}, validate=False)

    # set a simple state
    assert await core_client.put_config(cfg_id, {"a": 1}) == {"a": 1}

    # patch config
    assert await core_client.patch_config(cfg_id, {"a": 1}) == {"a": 1}
    assert await core_client.patch_config(cfg_id, {"b": 2}) == {"a": 1, "b": 2}
    assert await core_client.patch_config(cfg_id, {"c": 3}) == {"a": 1, "b": 2, "c": 3}

    # get config
    assert await core_client.config(cfg_id) == {"a": 1, "b": 2, "c": 3}

    # list configs
    assert [conf async for conf in core_client.configs()] == [cfg_id]

    # delete config
    await core_client.delete_config(cfg_id)
    assert [conf async for conf in core_client.configs()] == []

    cfg_override_id = "test_override_config_id"

    # set a simple state, the override should not be applied since
    # we want to get a DB value only
    put_result = await core_client.put_config(cfg_override_id, {"l1": {"l2": 1}})
    assert put_result == {"l1": {"l2": 1}}

    # get config, override should be applied
    with_overrides = await core_client.config(cfg_override_id)
    assert with_overrides == {"l1": {"l2": 42}}

    # get config with overrides in different section
    resp = await core_client._get(
        f"/config/{cfg_override_id}", params={"separate_overrides": "true", "include_raw_config": "true"}
    )
    json = await resp.json()
    assert json == {
        "config": {"l1": {"l2": 1}},
        "overrides": {"l1": {"l2": 42}},
        "raw_config": {"l1": {"l2": 1}},
    }

    # raw config is not sent by default
    resp = await core_client._get(f"/config/{cfg_override_id}", params={"separate_overrides": "true"})
    json = await resp.json()
    assert json == {
        "config": {"l1": {"l2": 1}},
        "overrides": {"l1": {"l2": 42}},
    }


@pytest.mark.asyncio
async def test_report(
    core_client: FixInventoryClient,
    client_session: ClientSession,
    inspection_checks: List[ReportCheck],
    benchmark: Benchmark,
) -> None:
    url = core_client.fixcore_url
    # get all benchmarks (predefined)
    response = await client_session.get(
        f"{url}/report/benchmarks", params={"with_checks": "true", "short": "true", "benchmarks": "aws_cis_1_5"}
    )
    benchmarks = await response.json()
    assert len(benchmarks) == 1
    bench = benchmarks[0]
    assert bench["id"] == "aws_cis_1_5"
    assert len(bench["report_checks"]) > 50
    assert bench["report_checks"][0] == {
        "id": "aws_iam_account_maintain_current_contact_details",
        "severity": "medium",
    }
    assert bench.get("checks") is None
    assert bench.get("children") is None
    # get all checks (predefined)
    response = await client_session.get(
        f"{url}/report/checks",
        params=dict(
            provider="aws",
            service="ec2",
            category="security",
            kind="aws_ec2_instance",
            id="aws_ec2_internet_facing_with_instance_profile,aws_ec2_old_instances,aws_ec2_unused_elastic_ip",
        ),
    )
    checks = await response.json()
    assert len(checks) == 2
    assert {a["id"] for a in checks} == {"aws_ec2_internet_facing_with_instance_profile", "aws_ec2_old_instances"}
    # create custom checks
    for check in inspection_checks:
        response = await client_session.put(f"{url}/report/check/{check.id}", json=to_js(check))
        assert response.status == 200
        # get custom check
        response = await client_session.get(f"{url}/report/check/{check.id}")
        assert response.status == 200
    # create custom benchmark
    response = await client_session.put(f"{url}/report/benchmark/{benchmark.id}", json=to_js(benchmark))
    assert response.status == 200
    # get custom benchmark
    response = await client_session.get(f"{url}/report/benchmark/{benchmark.id}")
    assert response.status == 200
    # delete custom benchmark
    response = await client_session.delete(f"{url}/report/benchmark/{benchmark.id}")
    assert response.status == 204
    # delete custom benchmarks
    for check in inspection_checks:
        response = await client_session.delete(f"{url}/report/check/{check.id}")
        assert response.status == 204


@pytest.mark.asyncio
async def test_authorization(core_client_with_psk: FixInventoryClient, client_session: ClientSession) -> None:
    url = core_client_with_psk.fixcore_url
    # make sure all users are deleted
    await core_client_with_psk.delete_config("fix.users")

    # Step 1: create first user ================================

    # getting a restricted resource returns a 401
    async with client_session.get(f"{url}/authorization/user", allow_redirects=False) as resp:
        assert resp.status == 401
    # go to the login page, which is the first user creation page
    async with client_session.get(f"{url}/login") as resp:
        assert resp.status == 200
        assert resp.content_type == "text/html"
        assert "/create-first-user" in await resp.text()
    # the form is submitted
    async with client_session.post(
        f"{url}/create-first-user",
        allow_redirects=False,
        data={
            "company": "some company",
            "fullname": "John Doe",
            "email": "test@test.de",
            "password": "test",
            "password_repeat": "test",
            "redirect": "/authorization/user",
        },
    ) as resp:
        assert resp.status == 303
        # a code is added to the redirect as request parameter
        user_with_code = resp.headers["Location"]
        assert "/authorization/user?code=" in user_with_code
    # the code is used to authenticate
    async with client_session.get(f"{url}{user_with_code}", allow_redirects=False) as resp:
        assert resp.status == 200
        auth_header = resp.headers["Authorization"]
        assert auth_header.startswith("Bearer ")
    # the auth header can be used for subsequent requests
    async with client_session.get(f"{url}/authorization/user", headers={"Authorization": auth_header}) as resp:
        assert resp.status == 200
        user = await resp.json()
        assert user["email"] == "test@test.de"
        assert user["roles"] == "admin"

    # Step 2: login with existing user ================================

    # subsequent interactions need to log in
    async with client_session.get(f"{url}/authorization/user") as resp:
        assert resp.status == 401
    async with client_session.get(f"{url}/login") as resp:
        assert resp.status == 200
        assert resp.content_type == "text/html"
        assert "/authenticate" in await resp.text()
    # the login form is submitted
    async with client_session.post(
        f"{url}/authenticate",
        allow_redirects=False,
        data={"email": "test@test.de", "password": "test", "redirect": "/authorization/user"},
    ) as resp:
        assert resp.status == 303
        # a code is added to the redirect as request parameter
        user_with_code = resp.headers["Location"]
        assert "/authorization/user?code=" in user_with_code
    # the code is used to authenticate
    async with client_session.get(f"{url}{user_with_code}", allow_redirects=False) as resp:
        assert resp.status == 200
        auth_header = resp.headers["Authorization"]
        assert auth_header.startswith("Bearer ")
    # the auth header can be used for subsequent requests
    async with client_session.get(f"{url}/authorization/user", headers={"Authorization": auth_header}) as resp:
        assert resp.status == 200

    # Step 3: renew the authorization header ================================
    # the auth header can be used for subsequent requests
    async with client_session.get(f"{url}/authorization/renew", headers={"Authorization": auth_header}) as resp:
        assert resp.status == 200
        assert resp.headers["Authorization"].startswith("Bearer ")
