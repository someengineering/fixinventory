import json
import logging
import os
import shutil
import tempfile
from datetime import timedelta
from functools import partial
from pathlib import Path
from typing import List, Dict, Optional, Any, AsyncIterator, Tuple

import pytest
from _pytest.logging import LogCaptureFixture
from aiohttp import ClientTimeout
from aiohttp.hdrs import METH_ANY
from aiohttp.test_utils import TestServer
from aiohttp.web import Request, Response, Application, route
from aiostream import stream
from aiostream.core import Stream
from pytest import fixture

from resotocore import version
from resotocore.cli import is_node
from resotocore.cli.cli import CLI
from resotocore.cli.command import HttpCommand, JqCommand
from resotocore.cli.model import CLIDependencies, CLIContext
from resotocore.console_renderer import ConsoleRenderer, ConsoleColorSystem
from resotocore.db.jobdb import JobDb
from resotocore.error import CLIParseError
from resotocore.model.model import predefined_kinds
from resotocore.query.model import Template, Query
from resotocore.task.task_description import TimeTrigger, Workflow, EventTrigger
from resotocore.task.task_handler import TaskHandler
from resotocore.types import JsonElement, Json
from resotocore.util import AccessJson, utc_str
from resotocore.worker_task_queue import WorkerTask

# noinspection PyUnresolvedReferences
from tests.resotocore.analytics import event_sender

# noinspection PyUnresolvedReferences
from tests.resotocore.cli.cli_test import cli, cli_deps

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import (
    filled_graph_db,
    graph_db,
    test_db,
    local_client,
    system_db,
    foo_model,
    foo_kinds,
)

# noinspection PyUnresolvedReferences
from tests.resotocore.db.runningtaskdb_test import running_task_db

# noinspection PyUnresolvedReferences
from tests.resotocore.message_bus_test import message_bus

# noinspection PyUnresolvedReferences
from tests.resotocore.query.template_expander_test import expander

# noinspection PyUnresolvedReferences
from tests.resotocore.task.task_handler_test import (
    task_handler,
    job_db,
    subscription_handler,
    test_workflow,
    task_handler_args,
)
from tests.resotocore.util_test import not_in_path

# noinspection PyUnresolvedReferences
from tests.resotocore.worker_task_queue_test import worker, task_queue, performed_by, incoming_tasks


@fixture
def json_source() -> str:
    nums = ",".join([f'{{ "num": {a}, "inner": {{"num": {a%10}}}}}' for a in range(0, 100)])
    return "json [" + nums + "," + nums + "]"


@fixture
async def echo_http_server() -> AsyncIterator[Tuple[int, List[Tuple[Request, Json]]]]:
    requests = []

    async def add_request(request: Request) -> Response:
        requests.append((request, await request.json()))
        status = 500 if request.path.startswith("/fail") else 200
        return Response(status=status)

    app = Application()
    app.add_routes([route(METH_ANY, "/{tail:.+}", add_request)])
    server = TestServer(app)
    await server.start_server()
    yield server.port, requests  # type: ignore
    await server.close()


@pytest.mark.asyncio
async def test_echo_source(cli: CLI) -> None:
    # no arg passed to json
    result = await cli.execute_cli_command("echo", stream.list)
    assert result[0] == [""]

    # simple string passed to json
    result = await cli.execute_cli_command("echo this is a string", stream.list)
    assert result[0] == ["this is a string"]

    result = await cli.execute_cli_command('echo   "foo bla bar" ', stream.list)
    assert result[0] == ["foo bla bar"]


@pytest.mark.asyncio
async def test_json_source(cli: CLI) -> None:
    # json object passed to json
    result = await cli.execute_cli_command('json {"a": 1}', stream.list)
    assert result[0] == [{"a": 1}]

    # json array passed to json
    result = await cli.execute_cli_command('json [{"a": 1}, {"b":2}]', stream.list)
    assert result[0] == [{"a": 1}, {"b": 2}]

    # json string passed to json
    result = await cli.execute_cli_command('json "foo bla bar"', stream.list)
    assert result[0] == ["foo bla bar"]


@pytest.mark.asyncio
async def test_predecessors(cli: CLI) -> None:
    r1 = await cli.execute_cli_command("query id(4_0) | predecessors", stream.list)
    assert len(r1[0]) == 1
    r2 = await cli.execute_cli_command("query id(4_0) | predecessors --with-origin", stream.list)
    assert len(r2[0]) == 2
    r3 = await cli.execute_cli_command("query id(4_0) | predecessors --with-origin default", stream.list)
    assert len(r3[0]) == 2
    r4 = await cli.execute_cli_command("query id(4_0) | predecessors delete", stream.list)
    assert len(r4[0]) == 0


@pytest.mark.asyncio
async def test_ancestors(cli: CLI) -> None:
    r1 = await cli.execute_cli_command("query id(4_0) | ancestors", stream.list)
    assert len(r1[0]) == 4
    r2 = await cli.execute_cli_command("query id(4_0) | ancestors --with-origin", stream.list)
    assert len(r2[0]) == 5
    r3 = await cli.execute_cli_command("query id(4_0) | ancestors --with-origin default", stream.list)
    assert len(r3[0]) == 5
    r4 = await cli.execute_cli_command("query id(4_0) | ancestors delete", stream.list)
    assert len(r4[0]) == 0


@pytest.mark.asyncio
async def test_successors(cli: CLI) -> None:
    r1 = await cli.execute_cli_command("query id(4) | successors", stream.list)
    assert len(r1[0]) == 10
    r2 = await cli.execute_cli_command("query id(4) | successors --with-origin", stream.list)
    assert len(r2[0]) == 11
    r3 = await cli.execute_cli_command("query id(4) | successors --with-origin default", stream.list)
    assert len(r3[0]) == 11
    r4 = await cli.execute_cli_command("query id(4) | successors delete", stream.list)
    assert len(r4[0]) == 0


@pytest.mark.asyncio
async def test_descendants(cli: CLI) -> None:
    r1 = await cli.execute_cli_command("query id(4) | descendants", stream.list)
    assert len(r1[0]) == 10
    r2 = await cli.execute_cli_command("query id(4) | descendants --with-origin", stream.list)
    assert len(r2[0]) == 11
    r3 = await cli.execute_cli_command("query id(4) | descendants --with-origin default", stream.list)
    assert len(r3[0]) == 11
    r4 = await cli.execute_cli_command("query id(4) | descendants delete", stream.list)
    assert len(r4[0]) == 0


@pytest.mark.asyncio
async def test_query_source(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is("foo") and some_int==0 --> identifier=~"9_"', stream.list)
    assert len(result[0]) == 10
    await cli.dependencies.template_expander.put_template(
        Template("test", 'is(foo) and some_int==0 --> identifier=~"{{fid}}"')
    )
    result2 = await cli.execute_cli_command('query expand(test, fid="9_")', stream.list)
    assert len(result2[0]) == 10

    result3 = await cli.execute_cli_command("query --with-edges is(graph_root) -[0:1]->", stream.list)
    # node: graph_root
    # node: collector
    # edge: graph_root -> collector
    # -----------------------------
    # = 3 elements
    assert len(result3[0]) == 3

    result4 = await cli.execute_cli_command("query --explain --with-edges is(graph_root) -[0:1]->", stream.list)
    assert result4[0][0]["rating"] == "simple"

    # use absolute path syntax
    result5 = await cli.execute_cli_command(
        "query aggregate(/reported.kind: sum(/reported.some_int) as si): "
        "is(foo) and not(/reported.some_int!=0) "
        "{child: --> /metadata!=null} some_int==0 "
        "with(any, --> /metadata!=null) sort /reported.name asc limit 1",
        stream.list,
    )
    assert result5 == [[{"group": {"reported.kind": "foo"}, "si": 0}]]


@pytest.mark.asyncio
async def test_sleep_source(cli: CLI) -> None:
    with pytest.raises(CLIParseError):
        await cli.evaluate_cli_command("sleep forever")
    result = await cli.execute_cli_command("sleep 0.001; echo hello", stream.list)
    assert result == [[""], ["hello"]]


@pytest.mark.asyncio
async def test_count_command(cli: CLI, json_source: str) -> None:
    # count instances
    result = await cli.execute_cli_command(f"{json_source} | count", stream.list)
    assert len(result[0]) == 2
    assert result[0] == ["total matched: 200", "total unmatched: 0"]

    # count attributes
    result = await cli.execute_cli_command(f"{json_source} | count num", stream.list)
    assert len(result[0]) == 102
    assert result[0][-2] == "total matched: 200"
    assert result[0][-1] == "total unmatched: 0"

    # count attributes with path
    result = await cli.execute_cli_command(f"{json_source} | count inner.num", stream.list)
    assert len(result[0]) == 12
    assert result[0][-2] == "total matched: 200"
    assert result[0][-1] == "total unmatched: 0"

    # count unknown attributes
    result = await cli.execute_cli_command(f"{json_source} | count does_not_exist", stream.list)
    assert len(result[0]) == 2
    assert result[0] == ["total matched: 0", "total unmatched: 200"]


@pytest.mark.asyncio
async def test_head_command(cli: CLI) -> None:
    assert await cli.execute_cli_command("json [1,2,3,4,5] | head 2", stream.list) == [[1, 2]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | head -2", stream.list) == [[1, 2]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | head", stream.list) == [[1, 2, 3, 4, 5]]


@pytest.mark.asyncio
async def test_tail_command(cli: CLI) -> None:
    assert await cli.execute_cli_command("json [1,2,3,4,5] | tail 2", stream.list) == [[4, 5]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | tail -2", stream.list) == [[4, 5]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | tail", stream.list) == [[1, 2, 3, 4, 5]]


@pytest.mark.asyncio
async def test_chunk_command(cli: CLI, json_source: str) -> None:
    result: List[List[str]] = await cli.execute_cli_command(f"{json_source} | chunk 50", stream.list)
    assert len(result[0]) == 4  # 200 in chunks of 50
    for a in result[0]:
        assert len(a) == 50


@pytest.mark.asyncio
async def test_flatten_command(cli: CLI, json_source: str) -> None:
    result = await cli.execute_cli_command(f"{json_source} | chunk 50 | flatten", stream.list)
    assert len(result[0]) == 200


@pytest.mark.asyncio
async def test_uniq_command(cli: CLI, json_source: str) -> None:
    result = await cli.execute_cli_command(f"{json_source} | uniq", stream.list)
    assert len(result[0]) == 100


@pytest.mark.asyncio
async def test_set_desired_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is("foo") | set_desired a="test" b=1 c=true', stream.list)
    assert len(result[0]) == 11
    for elem in result[0]:
        assert {"a": "test", "b": 1, "c": True}.items() <= elem["desired"].items()


@pytest.mark.asyncio
async def test_set_metadata_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is("foo") | set_metadata a="test" b=1 c=true', stream.list)
    assert len(result[0]) == 11
    for elem in result[0]:
        assert {"a": "test", "b": 1, "c": True}.items() <= elem["metadata"].items()


@pytest.mark.asyncio
async def test_clean_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is("foo") | clean', stream.list)
    assert len(result[0]) == 11
    for elem in result[0]:
        assert {"clean": True}.items() <= elem["desired"].items()


@pytest.mark.asyncio
async def test_protect_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is("foo") | protect', stream.list)
    assert len(result[0]) == 11
    for elem in result[0]:
        assert {"protected": True}.items() <= elem["metadata"].items()


@pytest.mark.asyncio
async def test_list_sink(cli: CLI, cli_deps: CLIDependencies) -> None:
    result = await cli.execute_cli_command("json [1,2,3]", stream.list)
    assert result == [[1, 2, 3]]


@pytest.mark.asyncio
async def test_flat_sink(cli: CLI) -> None:
    parsed = await cli.evaluate_cli_command("json [1,2,3]; json [4,5,6]; json [7,8,9]")
    result = await stream.list(stream.concat(stream.iterate((await p.execute())[1] for p in parsed)))
    assert result == [1, 2, 3, 4, 5, 6, 7, 8, 9]


@pytest.mark.asyncio
async def test_format(cli: CLI) -> None:
    # access properties by name and path
    result = await cli.execute_cli_command(
        'json {"a":"b", "b": {"c":"d"}} | format a:{a} b:{b.c} na:{fuerty}', stream.list
    )
    assert result[0] == ["a:b b:d na:null"]

    # use correct type
    props = dict(a="a", b=True, c=False, d=None, e=12, f=1.234)
    result = await cli.execute_cli_command(f"json {json.dumps(props)}" " | format {a}:{b}:{c}:{d}:{e}:{f}", stream.list)
    assert result[0] == ["a:true:false:null:12:1.234"]
    # access deeply nested properties with dict and array
    result = await cli.execute_cli_command(
        'json {"a":{"b":{"c":{"d":[0,1,2, {"e":"f"}]}}}} | format will be an >{a.b.c.d[3].e}<',
        stream.list,
    )
    assert result[0] == ["will be an >f<"]
    # make sure any path that is not available leads to the null value
    result = await cli.execute_cli_command("json {} | format {a}:{b.c.d}:{foo.bla[23].test}", stream.list)
    assert result[0] == ["null:null:null"]

    # Queries that use the reported section, also interpret the format in the reported section
    result = await cli.execute_cli_command(
        "query id(sub_root) limit 1 | format {{aa}} {some_string} test}} {some_int} {/metadata.node_id} {{",
        stream.list,
    )
    assert result[0] == ["{aa} hello test} 0 sub_root {"]


@pytest.mark.asyncio
async def test_workflows_command(cli: CLI, task_handler: TaskHandlerService, test_workflow: Workflow) -> None:
    async def execute(cmd: str) -> List[JsonElement]:
        ctx = CLIContext(cli.cli_env)
        return (await cli.execute_cli_command(cmd, stream.list, ctx))[0]  # type: ignore

    assert await execute("workflows list") == ["test_workflow"]
    assert await execute("workflows show test_workflow") == [to_js(test_workflow)]
    wf = await execute("workflows run test_workflow")
    assert wf[0].startswith("Workflow test_workflow started with id")  # type: ignore
    assert len(await execute("workflows running")) == 1


@pytest.mark.asyncio
async def test_jobs_command(cli: CLI, task_handler: TaskHandlerService, job_db: JobDb) -> None:
    async def execute(cmd: str) -> List[List[JsonElement]]:
        ctx = CLIContext(cli.cli_env)
        return await cli.execute_cli_command(cmd, stream.list, ctx)

    # add job with schedule
    result = await execute('jobs add --id hello --schedule "23 1 * * *" echo Hello World @NOW@')
    assert result == [["Job hello added."]]
    job = await job_db.get("hello")
    assert job is not None
    assert job.command.command == "echo Hello World @NOW@"
    assert job.trigger == TimeTrigger("23 1 * * *")
    assert job.wait is None
    assert job in task_handler.task_descriptions
    assert job.environment == {"graph": "ns", "section": "reported"}

    # add job with schedule and event
    with_event = await execute('jobs add --id timed_hi --schedule "23 1 * * *" --wait-for-event foo echo Hello World')
    assert with_event == [["Job timed_hi added."]]
    job_with_event: Job = await job_db.get("timed_hi")  # type: ignore
    assert job_with_event.wait is not None
    event_trigger, timeout = job_with_event.wait
    assert event_trigger.message_type == "foo"
    assert timeout == timedelta(hours=1)
    assert job_with_event.environment == {"graph": "ns", "section": "reported"}
    assert job_with_event in task_handler.task_descriptions

    # add job with event
    only_event = await execute("jobs add --id only_event --wait-for-event foo echo Hello World")
    assert only_event == [["Job only_event added."]]
    job_only_event: Job = await job_db.get("only_event")  # type: ignore
    assert job_only_event.trigger == EventTrigger("foo")
    assert job_only_event.wait is None
    assert job_only_event.environment == {"graph": "ns", "section": "reported"}
    assert job_only_event in task_handler.task_descriptions

    # add job without any trigger
    no_trigger = await execute("jobs add --id no_trigger echo Hello World")
    assert no_trigger == [["Job no_trigger added."]]
    job_no_trigger: Job = await job_db.get("no_trigger")  # type: ignore
    assert job_no_trigger.wait is None
    assert job_no_trigger.environment == {"graph": "ns", "section": "reported"}
    assert job_no_trigger in task_handler.task_descriptions

    # deactivate timed_hi
    deactivated = await execute("jobs deactivate timed_hi")
    assert deactivated[0][0]["active"] is False  # type: ignore

    # activate timed_hi
    activated = await execute("jobs activate timed_hi")
    assert activated[0][0]["active"] is True  # type: ignore

    # show specific job
    no_trigger_show = await execute("jobs show no_trigger")
    assert len(no_trigger_show[0]) == 1

    # show all jobs
    all_jobs = await execute("jobs list")
    assert len(all_jobs[0]) == 4

    # start the job
    run_hello = await execute("jobs run timed_hi")
    assert run_hello[0][0].startswith("Job timed_hi started with id")  # type: ignore
    assert [t for t in await task_handler.running_tasks() if t.descriptor.id == "timed_hi"]

    # list all running jobs
    all_running = await execute("jobs running")
    assert [r["job"] for r in all_running[0]] == ["timed_hi"]  # type: ignore

    # delete a job
    deleted = await execute("jobs delete timed_hi")
    assert deleted == [["Job timed_hi deleted."]]


@pytest.mark.asyncio
async def test_tag_command(
    cli: CLI, performed_by: Dict[str, List[str]], incoming_tasks: List[WorkerTask], caplog: LogCaptureFixture
) -> None:
    counter = 0

    def nr_of_performed() -> int:
        nonlocal counter
        performed = len(performed_by)
        increase = performed - counter
        counter = performed
        return increase

    nr_of_performed()  # reset to 0

    assert await cli.execute_cli_command("echo id_does_not_exist | tag update foo bla", stream.list) == [[]]
    assert nr_of_performed() == 0
    res1 = await cli.execute_cli_command(
        'json ["root", "collector"] | tag update foo "bla_{reported.some_int}"', stream.list
    )
    assert nr_of_performed() == 2
    assert {a["id"] for a in res1[0]} == {"root", "collector"}
    assert len(incoming_tasks) == 2
    # check that the worker task data is correct
    data = AccessJson(incoming_tasks[0].data)
    assert data["update"] is not None  # tag update -> data.update is defined
    assert not data.node.reported.is_none  # the node reported section is defined
    assert not data.node.metadata.is_none  # the node metadata section is defined
    assert not data.node.ancestors.cloud.reported.is_none  # the ancestors cloud section is defineda
    assert data["update"].foo == "bla_0"  # using the renderer bla_{reported.some_int}

    res2 = await cli.execute_cli_command('query is("foo") | tag update foo bla', stream.list)
    assert nr_of_performed() == 11
    assert len(res2[0]) == 11
    res3 = await cli.execute_cli_command('query is("foo") | tag delete foo', stream.list)
    assert nr_of_performed() == 11
    assert len(res3[0]) == 11
    with caplog.at_level(logging.WARNING):
        caplog.clear()
        res4 = await cli.execute_cli_command('query is("bla") limit 2 | tag delete foo', stream.list)
        assert nr_of_performed() == 2
        assert len(res4[0]) == 2
        # make sure that 2 warnings are emitted
        assert len(caplog.records) == 2
        for res in caplog.records:
            assert res.message.startswith("Tag update not reflected in db. Wait until next collector run.")
    # tag updates can be put into background
    res6 = await cli.execute_cli_command('json ["root", "collector"] | tag update --nowait foo bla', stream.list)
    assert cli.dependencies.forked_tasks.qsize() == 2
    for res in res6[0]:
        # in this case a message with the task id is emitted
        assert res.startswith("Spawned WorkerTask tag:")  # type:ignore
        # and the real result is found when the forked task is awaited, which happens by the CLI reaper
        awaitable, info = await cli.dependencies.forked_tasks.get()
        assert (await awaitable)["id"] in ["root", "collector"]  # type:ignore


@pytest.mark.asyncio
async def test_kind_command(cli: CLI) -> None:
    result = await cli.execute_cli_command("kind", stream.list)
    for kind in predefined_kinds:
        assert kind.fqn in result[0]
    result = await cli.execute_cli_command("kind string", stream.list)
    assert result[0][0] == {"name": "string", "runtime_kind": "string"}
    result = await cli.execute_cli_command("kind -p reported.ctime", stream.list)
    assert result[0][0] == {"name": "datetime", "runtime_kind": "datetime"}
    with pytest.raises(Exception):
        await cli.execute_cli_command("kind foo bla bar", stream.list)


@pytest.mark.asyncio
async def test_list_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is (foo) and identifier=="4" | list', stream.list)
    assert len(result[0]) == 1
    assert result[0][0].startswith("kind=foo, identifier=4, age=")
    list_cmd = "list some_int as si, some_string"
    result = await cli.execute_cli_command(f'query is (foo) and identifier=="4" | {list_cmd}', stream.list)
    assert result[0] == ["si=0, some_string=hello"]

    # List is using the correct type
    props = dict(id="test", a="a", b=True, c=False, d=None, e=12, f=1.234, reported={})
    result = await cli.execute_cli_command(f"json {json.dumps(props)}" " | list a,b,c,d,e,f", stream.list)
    assert result[0] == ["a=a, b=true, c=false, e=12, f=1.234"]

    # Queries that use the reported section, also interpret the list format in the reported section
    result = await cli.execute_cli_command(
        "query id(sub_root) limit 1 | list some_string, some_int, /metadata.node_id", stream.list
    )
    assert result[0] == ["some_string=hello, some_int=0, node_id=sub_root"]


@pytest.mark.asyncio
async def test_jq_command(cli: CLI) -> None:
    ctx = CLIContext(env={"section": "reported"}, query=Query.by("test"))
    # .test -> .reported.test
    assert JqCommand.rewrite_props(".a,.b", ctx) == ".reported.a,.reported.b"
    # absolute paths are rewritten correctly
    assert JqCommand.rewrite_props("./reported", ctx) == ".reported"
    # object construction is supported
    assert JqCommand.rewrite_props("{a:.a, b:.b}", ctx) == "{a:.reported.a, b:.reported.b}"
    # no replacement after pipe
    assert JqCommand.rewrite_props("map(.color) | {a:.a, b:.b}", ctx) == "map(.reported.color) | {a:.a, b:.b}"

    result = await cli.execute_cli_command('json {"a":{"b":1}} | jq ".a.b"', stream.list)
    assert len(result[0]) == 1
    assert result[0][0] == 1

    # allow absolute paths as json path
    result = await cli.execute_cli_command('json {"id":"123", "reported":{"b":1}} | jq "./reported"', stream.list)
    assert result == [[{"b": 1}]]

    # jq .kind is rewritten as .reported.kind
    result = await cli.execute_cli_command("query is(foo) limit 2 | jq .kind", stream.list)
    assert result[0] == ["foo", "foo"]


@pytest.mark.asyncio
async def test_aggregation_to_count_command(cli: CLI) -> None:
    r = await cli.execute_cli_command("query all | count kind", stream.list)
    assert set(r[0]) == {
        "graph_root: 1",
        "cloud: 1",
        "foo: 11",
        "bla: 100",
        "total matched: 113",
        "total unmatched: 0",
    }
    # exactly the same command as above (above query would be rewritten as this)
    r = await cli.execute_cli_command(
        "execute_query aggregate(reported.kind as name: sum(1) as count):all sort count asc | aggregate_to_count",
        stream.list,
    )
    assert set(r[0]) == {
        "graph_root: 1",
        "cloud: 1",
        "foo: 11",
        "bla: 100",
        "total matched: 113",
        "total unmatched: 0",
    }


@pytest.mark.skipif(not_in_path("arangodump"), reason="requires arangodump to be in path")
@pytest.mark.asyncio
async def test_system_backup_command(cli: CLI) -> None:
    async def check_backup(res: Stream) -> None:
        async with res.stream() as streamer:
            only_one = True
            async for s in streamer:
                assert isinstance(s, str)
                assert os.path.exists(s)
                # backup should have size between 30k and 200k (adjust size if necessary)
                assert 30000 < os.path.getsize(s) < 200000
                assert only_one
                only_one = False

    await cli.execute_cli_command("system backup create", check_backup)


@pytest.mark.asyncio
async def test_system_info_command(cli: CLI) -> None:
    info = AccessJson.wrap_object((await cli.execute_cli_command("system info", stream.list))[0][0])
    assert info.version == version()
    assert info.name == "resotocore"
    assert info.cpus > 0


@pytest.mark.skipif(
    not_in_path("arangodump", "arangorestore"),
    reason="requires arangodump and arangorestore",
)
@pytest.mark.asyncio
async def test_system_restore_command(cli: CLI) -> None:
    tmp_dir: Optional[str] = None
    try:
        tmp_dir = tempfile.mkdtemp()
        backup = os.path.join(tmp_dir, "backup")

        async def move_backup(res: Stream) -> None:
            async with res.stream() as streamer:
                async for s in streamer:
                    os.rename(s, backup)

        await cli.execute_cli_command("system backup create", move_backup)
        ctx = CLIContext(uploaded_files={"backup": backup})
        restore = await cli.execute_cli_command(
            f"BACKUP_NO_SYS_EXIT=true system backup restore {backup}", stream.list, ctx
        )
        assert restore == [
            [
                "Database has been restored successfully!",
                "Since all data has changed in the database eventually, this service needs to be restarted!",
            ]
        ]
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir)


@pytest.mark.asyncio
async def test_templates_command(cli: CLI) -> None:
    result = await cli.execute_cli_command("templates test kind=volume is({{kind}})", stream.list)
    assert result == [["is(volume)"]]
    result = await cli.execute_cli_command("templates add filter_kind is({{kind}})", stream.list)
    assert result == [["Template filter_kind added to the query library.\nis({{kind}})"]]
    result = await cli.execute_cli_command("templates", stream.list)
    assert result == [["filter_kind: is({{kind}})"]]
    result = await cli.execute_cli_command("templates filter_kind", stream.list)
    assert result == [["is({{kind}})"]]
    result = await cli.execute_cli_command("templates delete filter_kind", stream.list)
    assert result == [["Template filter_kind deleted from the query library."]]


@pytest.mark.asyncio
async def test_write_command(cli: CLI) -> None:
    async def check_file(res: Stream, check_content: Optional[str] = None) -> None:
        async with res.stream() as streamer:
            only_one = True
            async for s in streamer:
                assert isinstance(s, str)
                p = Path(s)
                assert p.exists() and p.is_file()
                assert 1 < p.stat().st_size < 100000
                assert p.name.startswith("write_test")
                assert only_one
                only_one = False
                if check_content:
                    with open(s, "r") as file:
                        data = file.read()
                        assert data == check_content

    # result can be read as json
    await cli.execute_cli_command("query all limit 3 | format --json | write write_test.json ", check_file)
    # result can be read as yaml
    await cli.execute_cli_command("query all limit 3 | format --yaml | write write_test.yaml ", check_file)
    # write enforces unescaped output.
    env = {"now": utc_str()}  # fix the time, so that replacements will stay equal
    truecolor = CLIContext(console_renderer=ConsoleRenderer(80, 25, ConsoleColorSystem.truecolor, True), env=env)
    monochrome = CLIContext(console_renderer=ConsoleRenderer.default_renderer(), env=env)
    # Make sure, that the truecolor output is different from monochrome output
    mono_out = await cli.execute_cli_command("help", stream.list, monochrome)
    assert await cli.execute_cli_command("help", stream.list, truecolor) != mono_out
    # We expect the content of the written file to contain monochrome output.
    assert await cli.execute_cli_command(
        "help | write write_test.txt", partial(check_file, check_content="".join(mono_out[0]) + "\n"), truecolor
    )


@pytest.mark.asyncio
async def test_http_command(cli: CLI, echo_http_server: Tuple[int, List[Tuple[Request, Json]]]) -> None:
    port, requests = echo_http_server

    def test_arg(
        arg_str: str,
        method: Optional[str] = None,
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[ClientTimeout] = None,
        compress: Optional[bool] = None,
    ) -> None:
        def test_if_set(prop: Any, value: Any) -> None:
            if prop is not None:
                assert prop == value, f"{prop} is not {value}"

        arg = HttpCommand.parse_args("https", arg_str)
        test_if_set(method, arg.method)
        test_if_set(url, arg.url)
        test_if_set(headers, arg.headers)
        test_if_set(params, arg.params)
        test_if_set(compress, arg.compress)
        test_if_set(timeout, arg.timeout)

    test_arg(":123", "POST", "https://localhost:123", {}, {}, ClientTimeout(30), False)
    test_arg("GET :123", "GET", "https://localhost:123")
    test_arg("://foo:123", "POST", "https://foo:123")
    test_arg("foo:123/bla", "POST", "https://foo:123/bla")
    test_arg("foo:123/bla", "POST", "https://foo:123/bla")
    test_arg("foo/bla", "POST", "https://foo/bla")
    test_arg(
        '--compress --timeout 24 POST :123 "hdr1: test" qp==123  hdr2:fest "qp2 == 321"',
        headers={"hdr1": "test", "hdr2": "fest"},
        params={"qp": "123", "qp2": "321"},
        compress=True,
        timeout=ClientTimeout(24),
    )

    # take 3 instance of type bla and send it to the echo server
    result = await cli.execute_cli_command(f"query is(bla) limit 3 | http :{port}/test", stream.list)
    # one line is returned to the user with a summary of the response types.
    assert result == [["3 requests with status 200 sent."]]
    # make sure all 3 requests have been received - the body is the complete json node
    assert len(requests) == 3
    for ar in (AccessJson(content) for _, content in requests):
        assert is_node(ar)
        assert ar.reported.kind == "bla"

    # failing requests are retried
    requests.clear()
    await cli.execute_cli_command(f"query is(bla) limit 1 | http --backoff-base 0.001 :{port}/fail", stream.list)
    # 1 request + 3 retries => 4 requests
    assert len(requests) == 4
