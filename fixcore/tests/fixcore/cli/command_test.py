import asyncio
import json
import logging
import os
import sqlite3
from datetime import timedelta
from functools import partial
from typing import List, Dict, Optional, Any, Tuple, Type, TypeVar, cast, Callable, Set

import pytest
import yaml
from _pytest.logging import LogCaptureFixture
from aiohttp import ClientTimeout
from aiohttp.web import Request
from aiostream import stream, pipe
from attrs import evolve
from pytest import fixture
from fixcore import version
from fixcore.cli import is_node, JsStream, list_sink
from fixcore.cli.cli import CLIService
from fixcore.cli.command import (
    HttpCommand,
    JqCommand,
    AggregateCommand,
    all_commands,
    ResourceRefinement,
    ResourceRefinementMatch,
)
from fixcore.cli.model import CLIContext, WorkerCustomCommand, CLI, FilePath
from fixcore.cli.tip_of_the_day import generic_tips
from fixcore.console_renderer import ConsoleRenderer, ConsoleColorSystem
from fixcore.db.graphdb import ArangoGraphDB
from fixcore.db.jobdb import JobDb
from fixcore.dependencies import TenantDependencies
from fixcore.error import CLIParseError
from fixcore.graph_manager.graph_manager import GraphManager
from fixcore.ids import InfraAppName, GraphName
from fixcore.infra_apps.package_manager import PackageManager
from fixcore.infra_apps.runtime import Runtime
from fixcore.model.model import Model, PropertyPath
from fixcore.model.typed_model import to_js
from fixcore.query.model import Template, Query
from fixcore.report import Inspector
from fixcore.task.task_description import TimeTrigger, Workflow, EventTrigger
from fixcore.task.task_handler import TaskHandlerService
from fixcore.types import JsonElement, Json
from fixcore.user import UsersConfigId
from fixcore.util import AccessJson, utc_str, utc
from fixcore.worker_task_queue import WorkerTask
from tests.fixcore.util_test import not_in_path


@fixture
def json_source() -> str:
    nums = ",".join([f'{{ "num": {a}, "inner": {{"num": {a%10}}}}}' for a in range(0, 100)])
    return "json [" + nums + "," + nums + "]"


def test_known_category(dependencies: TenantDependencies) -> None:
    allowed_categories = {"search", "format", "action", "setup", "misc"}
    for cmd in all_commands(dependencies):
        assert cmd.category in allowed_categories, f"Unknown category {cmd.category} for command {cmd.name}"


@pytest.mark.asyncio
async def test_echo_source(cli: CLI) -> None:
    # no arg passed to json
    result = await cli.execute_cli_command("echo", list_sink)
    assert result[0] == [""]

    # simple string passed to json
    result = await cli.execute_cli_command("echo this is a string", list_sink)
    assert result[0] == ["this is a string"]

    result = await cli.execute_cli_command('echo   "foo bla bar" ', list_sink)
    assert result[0] == ["foo bla bar"]


@pytest.mark.asyncio
async def test_json_source(cli: CLI) -> None:
    # json object passed to json
    result = await cli.execute_cli_command('json {"a": 1}', list_sink)
    assert result[0] == [{"a": 1}]

    # json array passed to json
    result = await cli.execute_cli_command('json [{"a": 1}, {"b":2}]', list_sink)
    assert result[0] == [{"a": 1}, {"b": 2}]

    # json string passed to json
    result = await cli.execute_cli_command('json "foo bla bar"', list_sink)
    assert result[0] == ["foo bla bar"]


@pytest.mark.asyncio
async def test_predecessors(cli: CLI) -> None:
    r1 = await cli.execute_cli_command("search id(4_0) | predecessors", list_sink)
    assert len(r1[0]) == 1
    r2 = await cli.execute_cli_command("search id(4_0) | predecessors --with-origin", list_sink)
    assert len(r2[0]) == 2
    r3 = await cli.execute_cli_command("search id(4_0) | predecessors --with-origin default", list_sink)
    assert len(r3[0]) == 2
    r4 = await cli.execute_cli_command("search id(4_0) | predecessors delete", list_sink)
    assert len(r4[0]) == 0


@pytest.mark.asyncio
async def test_ancestors(cli: CLI) -> None:
    r1 = await cli.execute_cli_command("search id(4_0) | ancestors", list_sink)
    assert len(r1[0]) == 4
    r2 = await cli.execute_cli_command("search id(4_0) | ancestors --with-origin", list_sink)
    assert len(r2[0]) == 5
    r3 = await cli.execute_cli_command("search id(4_0) | ancestors --with-origin default", list_sink)
    assert len(r3[0]) == 5
    r4 = await cli.execute_cli_command("search id(4_0) | ancestors delete", list_sink)
    assert len(r4[0]) == 0


@pytest.mark.asyncio
async def test_successors(cli: CLI) -> None:
    r1 = await cli.execute_cli_command("search id(4) | successors", list_sink)
    assert len(r1[0]) == 10
    r2 = await cli.execute_cli_command("search id(4) | successors --with-origin", list_sink)
    assert len(r2[0]) == 11
    r3 = await cli.execute_cli_command("search id(4) | successors --with-origin default", list_sink)
    assert len(r3[0]) == 11
    r4 = await cli.execute_cli_command("search id(4) | successors delete", list_sink)
    assert len(r4[0]) == 0


@pytest.mark.asyncio
async def test_descendants(cli: CLI) -> None:
    r1 = await cli.execute_cli_command("search id(4) | descendants", list_sink)
    assert len(r1[0]) == 10
    r2 = await cli.execute_cli_command("search id(4) | descendants --with-origin", list_sink)
    assert len(r2[0]) == 11
    r3 = await cli.execute_cli_command("search id(4) | descendants --with-origin default", list_sink)
    assert len(r3[0]) == 11
    r4 = await cli.execute_cli_command("search id(4) | descendants delete", list_sink)
    assert len(r4[0]) == 0


@pytest.mark.asyncio
async def test_search_source(cli: CLIService) -> None:
    result = await cli.execute_cli_command('search is("foo") and some_int==0 --> id=~"9_"', list_sink)
    assert len(result[0]) == 10
    await cli.dependencies.template_expander.put_template(Template("test", 'is(foo) and some_int==0 --> id=~"{{fid}}"'))
    result2 = await cli.execute_cli_command('search expand(test, fid="9_")', list_sink)
    assert len(result2[0]) == 10

    result3 = await cli.execute_cli_command("search --with-edges is(graph_root) -[0:1]->", list_sink)
    # node: graph_root
    # node: collector
    # edge: graph_root -> collector
    # -----------------------------
    # = 3 elements
    assert len(result3[0]) == 3

    result4 = await cli.execute_cli_command("search --explain --with-edges is(graph_root) -[0:1]->", list_sink)
    assert result4[0][0]["rating"] == "simple"

    # use absolute path syntax
    result5 = await cli.execute_cli_command(
        "search aggregate(/reported.kind: sum(/reported.some_int) as si): "
        "is(foo) and not(/reported.some_int!=0) "
        "{child: --> /metadata!=null} some_int==0 "
        "with(any, --> /metadata!=null) sort /reported.name asc limit 1",
        list_sink,
    )
    assert result5 == [["kind=foo, si=0"]]


@pytest.mark.asyncio
async def test_sleep_source(cli: CLI) -> None:
    with pytest.raises(CLIParseError):
        await cli.evaluate_cli_command("sleep forever")
    result = await cli.execute_cli_command("sleep 0.001; echo hello", list_sink)
    assert result == [[""], ["hello"]]


@pytest.mark.asyncio
async def test_count_command(cli: CLI, json_source: str) -> None:
    # count instances
    result = await cli.execute_cli_command(f"{json_source} | count", list_sink)
    assert len(result[0]) == 2
    assert result[0] == ["total matched: 200", "total unmatched: 0"]

    # count attributes
    result = await cli.execute_cli_command(f"{json_source} | count num", list_sink)
    assert len(result[0]) == 102
    assert result[0][-2] == "total matched: 200"
    assert result[0][-1] == "total unmatched: 0"

    # count attributes with path
    result = await cli.execute_cli_command(f"{json_source} | count inner.num", list_sink)
    assert len(result[0]) == 12
    assert result[0][-2] == "total matched: 200"
    assert result[0][-1] == "total unmatched: 0"

    # count unknown attributes
    result = await cli.execute_cli_command(f"{json_source} | count does_not_exist", list_sink)
    assert len(result[0]) == 2
    assert result[0] == ["total matched: 0", "total unmatched: 200"]


@pytest.mark.asyncio
async def test_head_command(cli: CLI) -> None:
    assert await cli.execute_cli_command("json [1,2,3,4,5] | head 2 | dump", list_sink) == [[1, 2]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | head -2 | dump", list_sink) == [[1, 2]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | head | dump", list_sink) == [[1, 2, 3, 4, 5]]


@pytest.mark.asyncio
async def test_tail_command(cli: CLI) -> None:
    assert await cli.execute_cli_command("json [1,2,3,4,5] | tail 2 | dump", list_sink) == [[4, 5]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | tail -2 | dump", list_sink) == [[4, 5]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | tail | dump", list_sink) == [[1, 2, 3, 4, 5]]


@pytest.mark.asyncio
async def test_chunk_command(cli: CLI, json_source: str) -> None:
    result: List[List[str]] = await cli.execute_cli_command(f"{json_source} | chunk 50 | dump", list_sink)
    assert len(result[0]) == 4  # 200 in chunks of 50
    for a in result[0]:
        assert len(a) == 50


@pytest.mark.asyncio
async def test_flatten_command(cli: CLI, json_source: str) -> None:
    result = await cli.execute_cli_command(f"{json_source} | chunk 50 | flatten", list_sink)
    assert len(result[0]) == 200


@pytest.mark.asyncio
async def test_uniq_command(cli: CLI, json_source: str) -> None:
    result = await cli.execute_cli_command(f"{json_source} | uniq", list_sink)
    assert len(result[0]) == 100


@pytest.mark.asyncio
async def test_set_desired_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('search is("foo") | set_desired a="test" b=1 c=true | dump', list_sink)
    assert len(result[0]) == 10
    for elem in result[0]:
        assert {"a": "test", "b": 1, "c": True}.items() <= elem["desired"].items()


@pytest.mark.asyncio
async def test_set_metadata_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('search is("foo") | set_metadata a="test" b=1 c=true | dump', list_sink)
    assert len(result[0]) == 10
    for elem in result[0]:
        assert {"a": "test", "b": 1, "c": True}.items() <= elem["metadata"].items()


@pytest.mark.asyncio
async def test_clean_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('search is("foo") | clean | dump', list_sink)
    assert len(result[0]) == 10
    for elem in result[0]:
        assert {"clean": True}.items() <= elem["desired"].items()


@pytest.mark.asyncio
async def test_protect_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('search is("foo") | protect | dump', list_sink)
    assert len(result[0]) == 10
    for elem in result[0]:
        assert {"protected": True}.items() <= elem["metadata"].items()


@pytest.mark.asyncio
async def test_list_sink(cli: CLI, dependencies: TenantDependencies) -> None:
    result = await cli.execute_cli_command("json [1,2,3] | dump", list_sink)
    assert result == [[1, 2, 3]]


@pytest.mark.asyncio
async def test_flat_sink(cli: CLI) -> None:
    parsed = await cli.evaluate_cli_command("json [1,2,3] | dump; json [4,5,6] | dump; json [7,8,9] | dump")
    expected = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert await stream.list(stream.iterate((await p.execute())[1] for p in parsed) | pipe.concat()) == expected


@pytest.mark.asyncio
async def test_format(cli: CLI) -> None:
    # access properties by name and path
    result = await cli.execute_cli_command(
        'json {"a":"b", "b": {"c":"d"}} | format a:{a} b:{b.c} na:{fuerty}', list_sink
    )
    assert result[0] == ["a:b b:d na:null"]

    # use correct type
    props = dict(a="a", b=True, c=False, d=None, e=12, f=1.234)
    result = await cli.execute_cli_command(f"json {json.dumps(props)}" " | format {a}:{b}:{c}:{d}:{e}:{f}", list_sink)
    assert result[0] == ["a:true:false:null:12:1.234"]
    # access deeply nested properties with dict and array
    result = await cli.execute_cli_command(
        'json {"a":{"b":{"c":{"d":[0,1,2, {"e":"f"}]}}}} | format will be an >{a.b.c.d[3].e}<', list_sink
    )
    assert result[0] == ["will be an >f<"]
    # make sure any path that is not available leads to the null value
    result = await cli.execute_cli_command("json {} | format {a}:{b.c.d}:{foo.bla[23].test}", list_sink)
    assert result[0] == ["null:null:null"]

    # Queries that use the reported section, also interpret the format in the reported section
    result = await cli.execute_cli_command(
        "search id(sub_root) limit 1 | format {{aa}} {some_string} test}} {some_int} {/metadata.node_id} {{",
        list_sink,
    )
    assert result[0] == ["{aa} hello test} 0 sub_root {"]


@pytest.mark.asyncio
async def test_workflows_command(cli: CLIService, task_handler: TaskHandlerService, test_workflow: Workflow) -> None:
    async def execute(cmd: str) -> List[JsonElement]:
        ctx = CLIContext(cli.cli_env)
        return (await cli.execute_cli_command(cmd, list_sink, ctx))[0]  # type: ignore

    assert await execute("workflows list") == ["sleep_workflow", "wait_for_collect_done", "test_workflow"]
    assert await execute("workflows show test_workflow") == [to_js(test_workflow)]
    wf = await execute("workflows run test_workflow")
    assert wf[0].startswith("Workflow test_workflow started with id")  # type: ignore
    running = await execute("workflows running")
    assert len(running) == 1

    # executing an already running workflow will give a specific message
    await execute("workflows run sleep_workflow")
    sf = await execute("workflows run sleep_workflow")
    assert sf[0].startswith("Workflow sleep_workflow already running with id ")  # type: ignore

    # a workflow task can be stopped
    task_id = running[0]["task-id"]  # type: ignore
    af = await execute(f"workflows stop {task_id}")
    assert af[0] == f"Workflow Task {task_id} stopped."

    # make sure to wait for all tasks to finish
    for rt in await task_handler.running_tasks():
        await task_handler.delete_running_task(rt)

    # access the history of all workflows
    history = AccessJson.wrap_list(await execute("workflows history"))
    assert len(history) == 1
    assert history[0].sleep_workflow.count == 1
    assert history[0].test_workflow.count == 1

    # access the history of a specific workflow
    history_test = AccessJson.wrap_list(await execute("workflows history test_workflow"))
    assert len(history_test) == 1
    wf_run = history_test[0]
    assert all(n in wf_run for n in ["id", "task_started_at", "duration"])

    # access the log of a specific workflow run
    task_log = await execute(f"workflows log {wf_run['id']}")
    assert len(task_log) == 1


@pytest.mark.asyncio
async def test_jobs_command(cli: CLIService, task_handler: TaskHandlerService, job_db: JobDb) -> None:
    async def execute(cmd: str) -> List[List[JsonElement]]:
        ctx = CLIContext(cli.cli_env)
        return await cli.execute_cli_command(cmd, list_sink, ctx)

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
    cli: CLIService, performed_by: Dict[str, List[str]], incoming_tasks: List[WorkerTask], caplog: LogCaptureFixture
) -> None:
    counter = 0

    def nr_of_performed() -> int:
        nonlocal counter
        performed = len(performed_by)
        increase = performed - counter
        counter = performed
        return increase

    nr_of_performed()  # reset to 0

    assert await cli.execute_cli_command("echo id_does_not_exist | tag update foo bla", list_sink) == [[]]
    assert nr_of_performed() == 0
    res1 = await cli.execute_cli_command(
        'json ["root", "collector"] | tag update foo "bla_{reported.some_int}" | dump', list_sink
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
    res2 = await cli.execute_cli_command('search is("foo") | tag update foo bla', list_sink)
    assert nr_of_performed() == 10
    assert len(res2[0]) == 10
    res2_tag_no_val = await cli.execute_cli_command('search is("foo") | tag update foobar', list_sink)
    assert nr_of_performed() == 10
    assert len(res2_tag_no_val[0]) == 10
    res3 = await cli.execute_cli_command('search is("foo") | tag delete foo', list_sink)
    assert nr_of_performed() == 10
    assert len(res3[0]) == 10
    with caplog.at_level(logging.WARNING):
        caplog.clear()
        res4 = await cli.execute_cli_command('search is("bla") limit 2 | tag delete foo', list_sink)
        assert nr_of_performed() == 2
        assert len(res4[0]) == 2
        # make sure that 2 warnings are emitted
        assert len(caplog.records) == 2
        for res in caplog.records:
            assert res.message.startswith("Update not reflected in db. Wait until next collector run.")
    # tag updates can be put into background
    res6 = await cli.execute_cli_command('json ["root", "collector"] | tag update --nowait foo bla', list_sink)
    assert cli.dependencies.forked_tasks.qsize() == 2
    for res in res6[0]:
        # in this case a message with the task id is emitted
        assert res.startswith("Spawned WorkerTask tag:")  # type:ignore
        # and the real result is found when the forked task is awaited, which happens by the CLI reaper
        awaitable, info = await cli.dependencies.forked_tasks.get()
        assert (await awaitable)["id"] in ["root", "collector"]  # type:ignore


@pytest.mark.asyncio
async def test_kinds_command(cli: CLI, foo_model: Model) -> None:
    result = await cli.execute_cli_command("kind", list_sink)
    for kind in ["account", "bla", "child", "cloud", "parent", "region", "some_complex"]:
        assert kind in result[0]
    result = await cli.execute_cli_command("kind foo", list_sink)
    assert result[0][0] == {
        "name": "foo",
        "bases": ["base"],
        "properties": {
            "age": "duration",
            "ctime": "datetime",
            "id": "string",
            "kind": "string",
            "name": "string",
            "now_is": "datetime",
            "some_int": "int32",
            "some_string": "string",
        },
        "successors": ["bla"],
    }
    result = await cli.execute_cli_command("kind string", list_sink)
    assert result[0][0] == {"name": "string", "runtime_kind": "string"}
    result = await cli.execute_cli_command("kind -p reported.ctime", list_sink)
    assert result[0][0] == {
        "name": "datetime",
        "runtime_kind": "datetime",
        "appears_in": [
            "base",
            "foo",
            "bla",
            "cloud",
            "account",
            "region",
            "parent",
            "child",
            "some_complex",
            "predefined_properties",
        ],
    }
    with pytest.raises(Exception):
        await cli.execute_cli_command("kind foo bla bar", list_sink)


@pytest.mark.asyncio
async def test_sort_command(cli: CLI) -> None:
    async def identifiers(query: str) -> List[str]:
        result = await cli.execute_cli_command(query + " | dump", list_sink)
        return [r["reported"]["id"] for r in result[0]]

    id_wo = await identifiers("search is(bla) | sort id")
    id_asc = await identifiers("search is(bla) | sort id asc")
    id_desc = await identifiers("search is(bla) | sort id desc")
    id_kind = await identifiers("search is(bla) | sort id | sort kind")
    assert id_wo == id_asc
    assert id_wo == id_kind
    assert id_asc == list(reversed(id_desc))


@pytest.mark.asyncio
async def test_limit_command(cli: CLI) -> None:
    async def identifiers(query: str) -> List[str]:
        result = await cli.execute_cli_command(query + " | dump", list_sink)
        return [r["reported"]["id"] for r in result[0]]

    assert await identifiers("search is(bla) sort id | limit 1") == ["0_0"]
    assert await identifiers("search is(bla) sort id | limit 2") == ["0_0", "0_1"]
    assert await identifiers("search is(bla) sort id | limit 2, 2") == ["0_2", "0_3"]
    assert await identifiers("search is(bla) sort id | limit 10, 2") == ["1_0", "1_1"]
    assert await identifiers("search is(bla) sort id | limit 100, 2") == []


@pytest.mark.asyncio
async def test_list_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('search is (foo) and id=="4" sort some_int | list', list_sink)
    assert len(result[0]) == 1
    assert result[0][0].startswith("kind=foo, id=4, some_int=0, age=")
    list_cmd = "list some_int as si, some_string"
    result = await cli.execute_cli_command(f'search is (foo) and id=="4" | {list_cmd}', list_sink)
    assert result[0] == ["si=0, some_string=hello"]

    # list is added automatically when no output renderer is defined and has the same behaviour as if it was given
    result = await cli.execute_cli_command('search is (foo) and id=="4" sort some_int', list_sink)
    assert result[0][0].startswith("kind=foo, id=4, some_int=0, age=")

    # List is using the correct type
    props = dict(id="test", a="a", b=True, c=False, d=None, e=12, f=1.234, reported={})
    result = await cli.execute_cli_command(f"json {json.dumps(props)} | list a,b,c,d,e,f", list_sink)
    assert result[0] == ["a=a, b=true, c=false, e=12, f=1.234"]

    # Queries that use the reported section, also interpret the list format in the reported section
    result = await cli.execute_cli_command(
        "search id(sub_root) limit 1 | list some_string, some_int, /metadata.node_id", list_sink
    )
    assert result[0] == ["some_string=hello, some_int=0, node_id=sub_root"]

    # List supports csv output
    result = await cli.execute_cli_command(
        f"json {json.dumps(props)} | list --csv a,`b`,c,`d`,e,`f`,non_existent", list_sink
    )
    assert result[0] == ['"a","b","c","d","e","f","non_existent"', '"a",True,False,"",12,1.234,""']

    # List supports markdown output
    result = await cli.execute_cli_command(
        f"json {json.dumps(props)} | list --markdown a,b,c,d,e,f,non_existent", list_sink
    )
    assert result[0] == [
        "|a|b   |c    |d   |e |f    |non_existent|",
        "|-|----|-----|----|--|-----|------------|",
        "|a|true|false|null|12|1.234|null        |",
    ]

    # List supports json table output
    result = await cli.execute_cli_command(
        'json {"id": "foo", "reported":{}, "name": "a", "some_int": 1, "tags": {"foo․bla․bar.test.rest.best.":"yup"}} | list --json-table name, some_int, tags.`foo․bla․bar.test.rest.best.`',
        list_sink,
    )
    assert result[0] == [
        {
            "columns": [
                {"display": "Name", "kind": "string", "name": "name", "path": "/name"},
                {"display": "Some Int", "kind": "int32", "name": "some_int", "path": "/some_int"},
                {
                    "display": "Foo․bla․bar.test.rest.best.",
                    "kind": "string",
                    "name": "foo․bla․bar.test.rest.best.",
                    "path": "/tags.`foo․bla․bar.test.rest.best.`",
                },
            ],
        },
        {"id": "foo", "row": {"foo․bla․bar.test.rest.best.": "yup", "name": "a", "some_int": 1}},
    ]

    # Default columns for json table view
    result = await cli.execute_cli_command('json {"id": "foo", "reported":{}} | list --json-table', list_sink)
    expected = ["Kind", "Id", "Name", "Age", "Cloud", "Account", "Region / Zone"]
    assert [c["display"] for c in result[0][0]["columns"]] == expected

    # List supports only markdown or csv, but not both at the same time
    with pytest.raises(CLIParseError):
        await cli.execute_cli_command(f"json {json.dumps(props)}" " | list --csv --markdown", list_sink)

    # List command will make sure to make the column name unique
    props = dict(id="123", reported=props, ancestors={"account": {"reported": props}})
    result = await cli.execute_cli_command(
        f"json {json.dumps(props)} | list reported.a, reported.b as a, reported.c as a, reported.c, "
        f"ancestors.account.reported.a, ancestors.account.reported.a, ancestors.account.reported.a as foo",
        list_sink,
    )
    # b as a ==> b, c as a ==> c, c ==> c_1, ancestors.account.reported.a ==> account_a, again ==> _1
    assert result[0][0] == "a=a, b=true, c=false, c_1=false, account_a=a, account_a_1=a, foo=a"
    # source context is passed correctly
    parsed = await cli.evaluate_cli_command("search is (bla) | head 10 | list")
    src_ctx, gen = await parsed[0].execute()
    assert src_ctx.count == 10
    assert src_ctx.total_count == 100

    # aggregates are rendered correctly
    result = await cli.execute_cli_command("search is (foo) | aggregate kind: sum(1) as count | list", list_sink)
    assert result[0][0] == "kind=foo, count=10"


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

    assert (
        JqCommand.rewrite_props(".pod_status.container_statuses[].image_id", ctx)
        == ".reported.pod_status.container_statuses[].image_id"
    )

    result = await cli.execute_cli_command('json {"a":{"b":1}} | jq ".a.b"', list_sink)
    assert len(result[0]) == 1
    assert result[0][0] == 1

    # allow absolute paths as json path
    result = await cli.execute_cli_command('json {"id":"123", "reported":{"b":1}} | jq "./reported"', list_sink)
    assert result == [[{"b": 1}]]

    # jq .kind is rewritten as .reported.kind
    result = await cli.execute_cli_command("search is(foo) limit 2 | jq .kind", list_sink)
    assert result[0] == ["foo", "foo"]


@pytest.mark.asyncio
async def test_execute_search_command(cli: CLI) -> None:
    # regression test: this used to fail because the arg could not be parsed
    await cli.execute_cli_command('execute_search (b= "0")', list_sink)


@pytest.mark.asyncio
async def test_aggregation_to_count_command(cli: CLI) -> None:
    r = await cli.execute_cli_command("search all | count kind", list_sink)
    assert set(r[0]) == {
        "graph_root: 1",
        "cloud: 1",
        "account: 1",
        "foo: 10",
        "bla: 100",
        "total matched: 113",
        "total unmatched: 0",
    }
    # exactly the same command as above (above search would be rewritten as this)
    r = await cli.execute_cli_command(
        "execute_search aggregate(reported.kind as name: sum(1) as count):all sort count asc | aggregate_to_count",
        list_sink,
    )
    assert set(r[0]) == {
        "graph_root: 1",
        "cloud: 1",
        "account: 1",
        "foo: 10",
        "bla: 100",
        "total matched: 113",
        "total unmatched: 0",
    }


@pytest.mark.skipif(not_in_path("arangodump"), reason="requires arangodump to be in path")
@pytest.mark.asyncio
async def test_system_backup_command(cli: CLI) -> None:
    async def check_backup(res: JsStream) -> None:
        async with res.stream() as streamer:
            only_one = True
            async for s in streamer:
                path = FilePath.from_path(s)
                assert path.local.exists()
                # backup should have size between 30k and 1500k (adjust size if necessary)
                assert 30000 < path.local.stat().st_size < 1500000
                assert only_one
                only_one = False

    await cli.execute_cli_command("system backup create", check_backup)


@pytest.mark.asyncio
async def test_system_info_command(cli: CLI) -> None:
    info = AccessJson.wrap_object((await cli.execute_cli_command("system info", list_sink))[0][0])
    assert info.version == version()
    assert info.name == "fixcore"
    assert info.cpus > 0


@pytest.mark.skipif(not_in_path("arangodump", "arangorestore"), reason="requires arangodump and arangorestore")
@pytest.mark.asyncio
async def test_system_restore_command(cli: CLI, tmp_directory: str) -> None:
    backup = os.path.join(tmp_directory, "backup")

    async def move_backup(res: JsStream) -> None:
        async with res.stream() as streamer:
            async for s in streamer:
                path = FilePath.from_path(s)
                os.rename(path.local, backup)

    await cli.execute_cli_command("system backup create", move_backup)
    ctx = CLIContext(uploaded_files={"backup": backup})
    restore = await cli.execute_cli_command(f"BACKUP_NO_SYS_EXIT=true system backup restore {backup}", list_sink, ctx)
    assert restore == [
        [
            "Database has been restored successfully!",
            "Since all data has changed in the database eventually, this service needs to be restarted!",
        ]
    ]


@pytest.mark.asyncio
async def test_configs_command(cli: CLI, tmp_directory: str) -> None:
    config_file = os.path.join(tmp_directory, "config.yml")

    async def check_file_is_yaml(res: JsStream) -> None:
        async with res.stream() as streamer:
            async for s in streamer:
                assert isinstance(s, str)
                with open(s, "r") as file:
                    yaml.safe_load(file.read())

    # create a new config entry
    create_result = await cli.execute_cli_command("configs set test_config t1=1, t2=2, t3=3 ", list_sink)
    assert create_result[0][0] == "t1: 1\nt2: 2\nt3: 3\n"
    # show the entry - should be the same as the created one
    show_result = await cli.execute_cli_command("configs show test_config", list_sink)
    assert show_result[0][0] == "t1: 1\nt2: 2\nt3: 3\n"
    # list all configs: only one is defined
    list_result = await cli.execute_cli_command("configs list", list_sink)
    assert list_result[0] == ["test_config"]

    # copy the config
    await cli.execute_cli_command("configs copy test_config test_config_copy", list_sink)
    list_result = await cli.execute_cli_command("configs list", list_sink)
    assert list_result[0] == ["test_config", "test_config_copy"]

    # edit the config: will make the config available as file
    await cli.execute_cli_command("configs edit test_config", check_file_is_yaml)
    # update the config
    update_doc = "a: '1'\nb: 2\nc: true\nd: null\n"
    with open(config_file, "w") as file:
        file.write(update_doc)
    ctx = CLIContext(uploaded_files={"config.yaml": config_file})
    update_result = await cli.execute_cli_command(f"configs update test_config {config_file}", list_sink, ctx)
    assert update_result == [[]]
    # show the entry - should be the same as the created one
    show_updated_result = await cli.execute_cli_command("configs show test_config", list_sink)
    assert show_updated_result[0][0] == update_doc
    # write a env var substitution to the config
    env_var_update = "foo: $(FOO)\n"
    with open(config_file, "w") as file:
        file.write(env_var_update)
    ctx = CLIContext(uploaded_files={"config.yaml": config_file})
    update_result = await cli.execute_cli_command(f"configs update test_config {config_file}", list_sink, ctx)
    # provide the env var
    os.environ["FOO"] = "bar"
    # check the configs: the env var should stay here and not be resolved when the user views the config
    show_updated_result = await cli.execute_cli_command("configs show test_config", list_sink)
    assert show_updated_result[0][0] == env_var_update


@pytest.mark.asyncio
async def test_templates_command(cli: CLI) -> None:
    result = await cli.execute_cli_command("templates test kind=volume is({{kind}})", list_sink)
    assert result == [["is(volume)"]]
    result = await cli.execute_cli_command("templates add filter_kind is({{kind}})", list_sink)
    assert result == [["Template filter_kind added to the search library.\nis({{kind}})"]]
    result = await cli.execute_cli_command("templates", list_sink)
    assert result == [["filter_kind: is({{kind}})"]]
    result = await cli.execute_cli_command("templates filter_kind", list_sink)
    assert result == [["is({{kind}})"]]
    result = await cli.execute_cli_command("templates delete filter_kind", list_sink)
    assert result == [["Template filter_kind deleted from the search library."]]


@pytest.mark.asyncio
async def test_write_command(cli: CLI) -> None:
    async def check_file(res: JsStream, check_content: Optional[str] = None) -> None:
        async with res.stream() as streamer:
            only_one = True
            async for s in streamer:
                fp = FilePath.from_path(s)
                assert fp.local.exists() and fp.local.is_file()
                assert 1 < fp.local.stat().st_size < 100000
                assert fp.user.name.startswith("write_test")
                assert only_one
                only_one = False
                if check_content:
                    with open(fp.local, "r") as file:
                        data = file.read()
                        assert data == check_content

    # result can be read as json
    await cli.execute_cli_command("search all limit 3 | format --json | write write_test.json ", check_file)
    # result can be read as yaml
    await cli.execute_cli_command("search all limit 3 | format --yaml | write write_test.yaml ", check_file)
    # throw an exception
    with pytest.raises(Exception):
        await cli.execute_cli_command("echo hello | write", list_sink)  # missing filename
    # write enforces unescaped output.
    env = {"now": utc_str()}  # fix the time, so that replacements will stay equal
    truecolor = CLIContext(console_renderer=ConsoleRenderer(80, 25, ConsoleColorSystem.truecolor, True), env=env)
    monochrome = CLIContext(console_renderer=ConsoleRenderer.default_renderer(), env=env)
    # Make sure, that the truecolor output is different from monochrome output
    mono_out = await cli.execute_cli_command("help", list_sink, monochrome)
    assert await cli.execute_cli_command("help", list_sink, truecolor) != mono_out
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
    result = await cli.execute_cli_command(f"search is(bla) limit 3 | http :{port}/test", list_sink)
    # one line is returned to the user with a summary of the response types.
    assert result == [["3 requests with status 200 sent."]]
    # make sure all 3 requests have been received - the body is the complete json node
    assert len(requests) == 3
    for ar in (AccessJson(content) for _, content in requests):
        assert is_node(ar)
        assert ar.reported.kind == "bla"

    # failing requests are retried
    requests.clear()
    await cli.execute_cli_command(f"search is(bla) limit 1 | http --backoff-base 0.001 :{port}/fail", list_sink)
    # 1 request + 3 retries => 4 requests
    assert len(requests) == 4


@pytest.mark.asyncio
async def test_jira_alias(cli: CLI, echo_http_server: Tuple[int, List[Tuple[Request, Json]]]) -> None:
    port, requests = echo_http_server
    result = await cli.execute_cli_command(
        f'search is(bla) | jira --url "http://localhost:{port}/success" --title test --message "test message" --username test --token test --project_id 10000 --reporter_id test',
        list_sink,
    )
    assert result == [["1 requests with status 200 sent."]]
    assert len(requests) == 1
    print(requests[0][1])
    assert requests[0][1] == {
        "fields": {
            "summary": "test",
            "issuetype": {"id": "10001"},
            "project": {"id": "10000"},
            "description": "test message\n\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\nbla: yes or no\n... (results truncated)\n\nIssue created by Fix",
            "reporter": {"id": "test"},
            "labels": ["created-by-fix"],
        }
    }


@pytest.mark.asyncio
async def test_pagerduty_alias(cli: CLI, echo_http_server: Tuple[int, List[Tuple[Request, Json]]]) -> None:
    port, requests = echo_http_server
    result = await cli.execute_cli_command(
        f'search id(0_0) | pagerduty --webhook-url "http://localhost:{port}/success" --summary test --routing-key 123 --dedup-key 234',
        list_sink,
    )
    assert result == [["1 requests with status 200 sent."]]
    assert len(requests) == 1
    response = requests[0][1]
    # override timestamp
    assert response["payload"]["timestamp"] is not None
    response["payload"]["timestamp"] = "2023-02-10T15:03:33Z"
    assert requests[0][1] == {
        "payload": {
            "summary": "test",
            "timestamp": "2023-02-10T15:03:33Z",
            "source": "Fix",
            "severity": "warning",
            "component": "Fix",
            "custom_details": {
                "collector": {"sub_root": {"no-region": {"0_0": {"id": "0_0", "name": "yes or no", "kind": "bla"}}}}
            },
        },
        "routing_key": "123",
        "dedup_key": "234",
        "images": [
            {
                "src": "https://cdn.some.engineering/assets/fix-illustrations/small/fix-alert.png",
                "href": "https://inventory.fix.security/",
                "alt": "Fix Home Page",
            }
        ],
        "links": [],
        "event_action": "trigger",
        "client": "Fix Service",
        "client_url": "https://inventory.fix.security",
    }


@pytest.mark.asyncio
async def test_welcome(cli: CLI) -> None:
    ctx = CLIContext(console_renderer=ConsoleRenderer.default_renderer())
    result = await cli.execute_cli_command(f"welcome", list_sink, ctx)
    assert "Fix" in result[0][0]


@pytest.mark.asyncio
async def test_tip_of_the_day(cli: CLI) -> None:
    ctx = CLIContext(console_renderer=ConsoleRenderer.default_renderer())
    result = await cli.execute_cli_command(f"totd", list_sink, ctx)
    assert generic_tips[0].command_line in result[0][0]


@pytest.mark.asyncio
async def test_certificate(cli: CLI) -> None:
    result = await cli.execute_cli_command(
        f"certificate create --common-name foo.inventory.fix.security --dns-names bla --ip-addresses 1.2.3.4 --days-valid 1",
        list_sink,
    )
    # will create 2 files
    assert len(result[0]) == 2
    assert [a.rsplit("/")[-1] for a in result[0]] == [
        "foo.inventory.fix.security.key",
        "foo.inventory.fix.security.crt",
    ]


@pytest.mark.asyncio
async def test_execute_task(cli: CLI) -> None:
    # translate a custom command to an alias template
    command = WorkerCustomCommand("name", "info", {"a": "b"}, "description").to_template()
    assert command.name == "name"
    assert command.info == "info"
    assert command.description == "description"
    assert command.args_description == {"a": "b"}
    assert command.template == "execute-task --no-node-result --command 'name' --arg '{{args}}'"

    # execute-task in source position
    source_result = await cli.execute_cli_command(
        f'execute-task --command success_task --arg "--foo bla test"', list_sink
    )
    assert len(source_result[0]) == 1
    assert source_result[0] == [{"result": "done!"}]

    # execute task in flow position: every incoming node creates a new task
    flow_result = await cli.execute_cli_command(
        f'search all limit 3 | execute-task --command success_task --arg "--t {{id}}"', list_sink
    )
    assert len(flow_result[0]) == 3


@pytest.mark.asyncio
async def test_history(cli: CLI, filled_graph_db: ArangoGraphDB) -> None:
    async def history_count(cmd: str) -> int:
        result = await cli.execute_cli_command(cmd, list_sink)
        return len(result[0])

    now = utc()
    five_min_ago = utc_str(now - timedelta(minutes=5))
    five_min_later = utc_str(now + timedelta(minutes=5))
    assert await history_count("history") == 112  # 112 inserts for the filled graph db
    assert await history_count(f"history --after {five_min_ago}") == 112
    assert await history_count(f"history --after 5m") == 112
    assert await history_count(f"history --after {five_min_later}") == 0
    assert await history_count(f"history --before {five_min_ago}") == 0
    assert await history_count(f"history --before 5m") == 0
    assert await history_count(f"history --change node_created") == 112
    assert await history_count(f"history --change node_updated") == 0
    assert await history_count(f"history --change node_deleted") == 0
    assert await history_count(f"history --change node_created --change node_updated --change node_deleted") == 112
    assert await history_count(f"history is(foo)") == 10
    # combine all selectors
    assert await history_count(f"history --after 5m --before {five_min_later} --change node_created is(foo)") == 10


@pytest.mark.asyncio
async def test_aggregate(dependencies: TenantDependencies) -> None:
    in_stream = stream.iterate(
        [{"a": 1, "b": 1, "c": 1}, {"a": 2, "b": 1, "c": 1}, {"a": 3, "b": 2, "c": 1}, {"a": 4, "b": 2, "c": 1}]
    )

    async def aggregate(agg_str: str) -> List[JsonElement]:  # type: ignore
        res = AggregateCommand(dependencies).parse(agg_str)
        async with (await res.flow(in_stream)).stream() as flow:
            return [s async for s in flow]

    assert await aggregate("b as bla, c, r.d.f.name: sum(1) as count, min(a) as min, max(a) as max") == [
        {"group": {"bla": 1, "c": 1, "r.d.f.name": None}, "count": 2, "min": 1, "max": 2},
        {"group": {"bla": 2, "c": 1, "r.d.f.name": None}, "count": 2, "min": 3, "max": 4},
    ]
    assert await aggregate("b as nb, c as nc: avg(a) as a, avg(b) as b, avg(c) as c") == [
        {"group": {"nb": 1, "nc": 1}, "a": 1.5, "b": 1, "c": 1},
        {"group": {"nb": 2, "nc": 1}, "a": 3.5, "b": 2, "c": 1},
    ]
    assert await aggregate("b: sum(1) as count") == [
        {"group": {"b": 1}, "count": 2},
        {"group": {"b": 2}, "count": 2},
    ]
    assert await aggregate('"{b}_{c}_{does_not_exist}" as name: sum(1) as count') == [
        {"group": {"name": "1_1_null"}, "count": 2},
        {"group": {"name": "2_1_null"}, "count": 2},
    ]


@pytest.mark.asyncio
async def test_report(cli: CLI, inspector_service: Inspector) -> None:
    T = TypeVar("T")

    async def execute(cmd: str, _: Type[T]) -> List[T]:
        result = await cli.execute_cli_command(cmd, list_sink)
        return cast(List[T], result[0])

    # all benchmarks are listed
    assert "test" in await execute("report benchmark list", str)
    assert "test" in await execute("report benchmarks list", str)
    # all checks are listed
    assert "test_test_search" in await execute("report check list", str)
    assert "test_test_cmd" in await execute("report checks list", str)
    # the whole benchmark is printed to the user
    assert "Section 1" in (await execute("report benchmark show test", str))[0]
    # a single check is executed and produces a benchmark result: benchmark_node, check_node, edge == 3
    assert len(await execute("report check run test_test_search | dump", Json)) == 3
    # without output transformer, a markdown report is generated
    assert len((await execute("report check run test_test_search", str))) == 1
    # execute the test benchmark
    assert len((await execute("report benchmark run test --sync-security-section | dump", Json))) == 9
    assert len((await execute("report benchmark run test --only-failing | dump", Json))) == 9
    assert len((await execute("report benchmark run test --severity critical | dump", Json))) == 5
    # load the benchmark from the last sync
    assert len((await execute("report benchmark load test | dump", Json))) == 9
    # list failing resources for a specific check
    assert len((await execute("report check failing-resources test_test_search", Json))) == 10


@pytest.mark.asyncio
async def test_apps(cli: CLI, package_manager: PackageManager, infra_apps_runtime: Runtime, tmp_directory: str) -> None:
    T = TypeVar("T")

    async def execute(cmd: str, _: Type[T]) -> List[T]:
        result = await cli.execute_cli_command(cmd, list_sink)
        return cast(List[T], result[0])

    async def check_file_is_yaml(res: JsStream) -> None:
        async with res.stream() as streamer:
            async for s in streamer:
                assert isinstance(s, str)
                with open(s, "r") as file:
                    yaml.safe_load(file.read())

    # install a package
    assert "installed successfully" in (await execute("apps install cleanup-untagged", str))[0]
    manifest = await package_manager.get_manifest(InfraAppName("cleanup-untagged"))
    assert manifest is not None
    assert manifest.name == "cleanup-untagged"
    # install discord app
    assert "installed successfully" in (await execute("apps install discord", str))[0]

    # info about the app
    info_json = (await execute("apps info cleanup-untagged", Json))[0]
    assert info_json["name"] == "cleanup-untagged"

    # run the app
    result = await execute("apps run cleanup-untagged --dry-run", str)
    assert result[0].startswith("search /metadata.protected == false and /metadata.phantom")

    # run the app with stdin
    result = await execute("echo foo | apps run cleanup-untagged --dry-run", str)
    assert result[0].startswith("search /metadata.protected == false and /metadata.phantom")

    # run discord app with stdin
    result = await execute("search is(graph_root) | apps run discord --title foo --dry-run", str)
    assert "http POST https://discordapp.com" in result[0]
    await execute("apps uninstall discord", str)

    # update the app
    assert (
        "App cleanup-untagged updated sucessfully to the latest version"
        in (await execute("apps update cleanup-untagged", str))[0]
    )

    # update all apps
    assert (
        "App cleanup-untagged updated sucessfully to the latest version"
        in (await execute("apps update cleanup-untagged", str))[0]
    )

    # edit the manifest: will make the manifest available as file
    manifest_file = os.path.join(tmp_directory, "manifest.yml")
    old_manifest = await cli.dependencies.infra_apps_package_manager.get_manifest(InfraAppName("cleanup-untagged"))
    assert old_manifest is not None
    await cli.execute_cli_command("apps edit cleanup-untagged", check_file_is_yaml)
    # update the manifest
    updated_manifest = evolve(old_manifest, version="42")
    updated_manifest_str = yaml.dump(to_js(updated_manifest))
    with open(manifest_file, "w", encoding="utf-8") as file:
        file.write(updated_manifest_str)
    ctx = CLIContext(uploaded_files={"manifest.yaml": manifest_file})
    update_result = await cli.execute_cli_command(f"apps update cleanup-untagged {manifest_file}", list_sink, ctx)
    assert update_result == [[]]
    # show the manifest - should be the same as the created one
    updated_result = await cli.dependencies.infra_apps_package_manager.get_manifest(InfraAppName("cleanup-untagged"))
    assert updated_result == updated_manifest

    # list all apps
    result = await execute("apps list", str)
    assert result == ["cleanup-untagged"]

    # uninstall the app
    await execute("apps uninstall cleanup-untagged", str)
    result = await execute("apps list", str)
    assert result == []


@pytest.mark.asyncio
async def test_user(cli: CLI) -> None:
    async def execute(cmd: str) -> List[JsonElement]:
        all_results = await cli.execute_cli_command(cmd, list_sink)
        return all_results[0]  # type: ignore

    # remove all existing users
    await cli.dependencies.config_handler.delete_config(UsersConfigId)

    # create new user
    result = await execute('user add john@test.de --fullname "John Doe" --password test --role readonly')
    assert result == [{"email": "john@test.de", "fullname": "John Doe", "roles": ["readonly"]}]

    # get user
    result = await execute("user show john@test.de")
    assert result == [{"email": "john@test.de", "fullname": "John Doe", "roles": ["readonly"]}]

    # add role to user
    result = await execute("user role add john@test.de readwrite")
    roles = set(result[0]["roles"])  # type: ignore
    assert roles == {"readonly", "readwrite"}

    # remove role from user
    result = await execute("user role delete john@test.de readwrite")
    assert result == [{"email": "john@test.de", "fullname": "John Doe", "roles": ["readonly"]}]

    # Change password
    result = await execute("user password john@test.de bombproof")
    assert result == ["Password for john@test.de updated"]

    # create another user
    result = await execute('user add jane@test.de --fullname "Jane Doe" --password test --role admin')
    assert result == [{"email": "jane@test.de", "fullname": "Jane Doe", "roles": ["admin"]}]

    # list users
    result = await execute("user list")
    assert result == ["john@test.de", "jane@test.de"]

    # delete user
    result = await execute("user delete john@test.de")
    assert result == ["User john@test.de deleted"]

    # list users
    result = await execute("user list")
    assert result == ["jane@test.de"]


@pytest.mark.asyncio
async def test_graph(cli: CLI, graph_manager: GraphManager, tmp_directory: str) -> None:
    T = TypeVar("T")

    await graph_manager.delete(GraphName("graphtest2"))
    await graph_manager.delete(GraphName("graphtest_import"))

    async def execute(cmd: str, _: Type[T]) -> List[T]:
        result = await cli.execute_cli_command(cmd, list_sink)
        return cast(List[T], result[0])

    # cleanup everything
    for graph in await graph_manager.list(None):
        await graph_manager.delete(graph)

    # create a graph
    await graph_manager.db_access.create_graph(GraphName("graphtest"))
    await graph_manager.db_access.create_graph(GraphName("ns"))

    # list all graphs
    graphs = await execute("graph list", str)
    assert set(graphs) == {"graphtest", "ns"}

    # list via regex
    graphs = await execute("graph list .*apht.*", str)
    assert set(graphs) == {"graphtest"}

    # copy a graph
    await execute("graph copy graphtest graphtest2", str)
    graph_names = await graph_manager.list(None)
    assert set(graph_names) == {"ns", "graphtest", "graphtest2"}

    # copy to the existing graph without --force
    with pytest.raises(Exception):
        await execute("graph copy graphtest graphtest2", str)

    # copy to the existing graph with --force
    await execute("graph copy graphtest graphtest2 --force", str)
    graph_names = await graph_manager.list(None)
    assert set(graph_names) == {"ns", "graphtest", "graphtest2"}

    # implicitly copy the current graph to the new one
    await execute("graph copy graphtest3", str)
    graph_names = await graph_manager.list(None)
    assert set(graph_names) == {"ns", "graphtest", "graphtest2", "graphtest3"}

    # make a snapshot
    await execute("graph snapshot graphtest foo", str)
    snapshots = await graph_manager.list("snapshot.*")
    assert len(snapshots) == 1
    # implicitly use the current graph as a source
    await execute("graph snapshot foobar", str)
    snapshots = await graph_manager.list("snapshot.*")
    assert len(snapshots) == 2
    assert snapshots[0].startswith("snapshot")
    await asyncio.sleep(1.1)

    # search using a timestamp
    at_timestamp = await execute(f"search is(graph_root) --at {utc_str()}", str)
    assert at_timestamp == ["kind=graph_root, name=root"]
    # search using timedelta
    assert await execute("search is(graph_root) --at 0s", str) == ["kind=graph_root, name=root"]

    for snapshot in snapshots:
        await graph_manager.delete(GraphName(snapshot))

    with pytest.raises(Exception):
        await execute(f"search is(graph_root) --at {utc_str()}", str)

    # delete a graph
    await execute("graph delete graphtest2", str)
    graph_names = await graph_manager.list(None)
    assert set(graph_names) == {"ns", "graphtest", "graphtest3"}

    dump = os.path.join(tmp_directory, "dump")

    async def move_dump(res: JsStream) -> None:
        async with res.stream() as streamer:
            async for s in streamer:
                fp = FilePath.from_path(s)
                os.rename(fp.local, dump)

    # graph export works
    await cli.execute_cli_command("graph export graphtest dump", move_dump)

    ctx = CLIContext(uploaded_files={"dump": dump})

    # graph import works too
    await cli.execute_cli_command("graph import graphtest_import graphtest.backup", list_sink, ctx)
    assert await graph_manager.list(GraphName("graphtest_import")) == [GraphName("graphtest_import")]

    # clean up
    await graph_manager.delete(GraphName("graphtest3"))
    await graph_manager.delete(GraphName("graphtest_import"))


@pytest.mark.asyncio
async def test_db(cli: CLI) -> None:
    db_file = "test_db"

    async def sync_and_check(
        cmd: str,
        *,
        expected_table: Optional[Callable[[str, int], bool]] = None,
        expected_tables: Optional[Set[str]] = None,
        expected_table_count: Optional[int] = None,
    ) -> Json:
        result: List[Json] = []

        async def check(in_: JsStream) -> None:
            async with in_.stream() as streamer:
                async for s in streamer:
                    assert isinstance(s, dict)
                    path = FilePath.from_path(s)
                    # open sqlite database
                    conn = sqlite3.connect(path.local)
                    c = conn.cursor()
                    tables = {
                        row[0] for row in c.execute("SELECT tbl_name FROM sqlite_master WHERE type='table'").fetchall()
                    }
                    if expected_tables is not None:
                        assert tables == expected_tables
                    if expected_table_count is not None:
                        assert len(tables) == expected_table_count
                    if expected_table is not None:
                        for table in tables:
                            count = c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                            assert expected_table(table, count), f"Table {table} has {count} rows"
                    c.close()
                    conn.close()
                    result.append(s)

        await cli.execute_cli_command(cmd, check)
        assert len(result) == 1
        return result[0]

    # search | db sync
    await sync_and_check(
        f"search --with-edges is(foo) -[0:1]-> | db sync sqlite --database {db_file}",
        expected_table=lambda table, count: count > 0 if not table.startswith("link_") else True,
        expected_tables={"foo", "bla", "link_bla_bla", "link_foo_bla"},
    )

    # db sync synchronizes the whole graph
    await sync_and_check(
        f"db sync sqlite --database {db_file}",
        expected_table=lambda table, count: count > 0 if not table.startswith("link_") else True,
        expected_tables={"foo", "bla", "link_bla_bla", "link_foo_bla"},
    )

    # db sync with complete schema synchronizes the whole graph and created tables for all kinds even if they are empty
    await sync_and_check(f"db sync sqlite --complete-schema --database {db_file}", expected_table_count=11)

    # support write after db sync (not required for simple files, but we want to support s3 etc. in the future)
    path_result = await sync_and_check(f"db sync sqlite --database {db_file} | write out.db")
    assert FilePath.from_path(path_result).user.name == "out.db"

    # search with aggregation does not export anything
    with pytest.raises(Exception):
        await sync_and_check(f"search all | aggregate kind:sum(1) | db sync sqlite --database foo")

    # define all parameters and check the connection string
    with pytest.raises(Exception) as ex:
        await sync_and_check(
            f"db sync sqlite --database db --host bla --port 1234 --user test --password check --arg foo=bla foo2=bla2",
            expected_table_count=11,
        )
    assert "sqlite://test:check@bla:1234" in str(ex.value)
    assert "?foo=bla&foo2=bla2" in str(ex.value)

    # calling db without command will yield an error
    with pytest.raises(Exception) as ex:
        db_res = await cli.execute_cli_command("db", list_sink)
    assert "Execute `help db` to get more information." in str(ex.value)

    # make sure argsinfo is available
    assert "sync" in cli.direct_commands["db"].args_info()


@pytest.mark.asyncio
async def test_timeseries(cli: CLI) -> None:
    async def exec(cmd: str) -> List[JsonElement]:
        res = await cli.execute_cli_command(cmd, list_sink)
        return cast(List[JsonElement], res[0])

    tsdb = cli.dependencies.db_access.time_series_db
    await tsdb.wipe()  # create a clean slate
    now = utc()
    in_one_min = utc_str(now + timedelta(minutes=1))
    one_min_ago = utc_str(now - timedelta(minutes=1))
    # Create a time series based on all foo entries
    res = await exec("timeseries snapshot --name test 'search aggregate(reported.some_int, reported.id: sum(1)): is(foo)'")  # fmt: skip
    assert res[0] == "10 entries added to time series test."
    # Get the time series combined with each complete group
    res = await exec(f"timeseries get --name test --start {one_min_ago} --end {in_one_min}")
    assert len(res) == 10
    # Get the time series combined over all groups --> only one entry for one timestamp
    res = await exec(f"timeseries get --name test --start {one_min_ago} --end {in_one_min} --group")
    assert len(res) == 1
    # Combine over some_int (which has only one) --> only one entry for one timestamp
    res = await exec(f"timeseries get --name test --start {one_min_ago} --end {in_one_min} --group some_int")
    assert len(res) == 1
    # Combine over id (which is unique for each entry) --> 10 entries for one timestamp
    res = await exec(f"timeseries get --name test --start {one_min_ago} --end {in_one_min} --group id")
    assert len(res) == 10
    # Combine over id (which is unique for each entry), filter for id==2 --> 1 entry for one timestamp
    res = await exec(f'timeseries get --name test --start {one_min_ago} --end {in_one_min} --group id --filter id=="2"')  # fmt: skip
    assert len(res) == 1


@pytest.mark.asyncio
async def test_refine_resource_data(cli: CLI) -> None:
    from fixcore.cli import command

    # override the default resource refinements for testing
    command.ResourceRefinements = [
        ResourceRefinement(
            kind="foo",
            matches=ResourceRefinementMatch(PropertyPath.from_list(["id"]), value="c"),
            path=["reported", "name"],
            value="some",
        ),
    ]

    async def exec(js: Json) -> List[JsonElement]:
        res = await cli.execute_cli_command(f"json {json.dumps(js)} | refine-resource-data | dump", list_sink)
        return cast(List[JsonElement], res[0])

    base = {"id": "a", "reported": {"id": "a", "name": "b", "kind": "foo"}}
    assert await exec(base) == [base]
    assert await exec({**base, "id": "c"}) == [{"id": "c", "reported": {"id": "a", "name": "some", "kind": "foo"}}]

    # assert await exec(base) == [{"id": "a", "reported": {"id": "b", "name": "d", "kind": "foo"}}]


@pytest.mark.asyncio
async def test_detect_secrets(cli: CLI) -> None:
    async def detect(to_check: JsonElement) -> List[JsonElement]:
        res = await cli.execute_cli_command(f"json {json.dumps(to_check)} | detect-secrets --with-secrets", list_sink)
        return cast(List[JsonElement], res[0])

    assert await detect({"foo": 'AWS_SECRET_ACCESS_KEY="aeDrhaA3tXjkwIVJ43PHmkCi5"'}) == [
        {
            "foo": 'AWS_SECRET_ACCESS_KEY="aeDrhaA3tXjkwIVJ43PHmkCi5"',
            "info": {
                "potential_secret": 'AWS_SECRET_ACCESS_KEY="aeDrhaA3tXjkwIVJ43PHmkCi5"',
                "secret_detected": True,
                "secret_type": "Secret Keyword",
            },
        }
    ]
    assert await detect({"foo": "innocent string"}) == []
