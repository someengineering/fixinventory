import logging
import re
from datetime import timedelta

import pytest
from _pytest.logging import LogCaptureFixture
from aiostream import stream
from pytest import fixture

from core.cli.cli import CLI, CLIDependencies

# noinspection PyUnresolvedReferences
from core.cli.command import ListSink
from core.db.jobdb import JobDb
from core.error import CLIParseError
from core.model.model import predefined_kinds
from core.task.task_description import TimeTrigger, Workflow
from core.task.task_handler import TaskHandler
from core.types import Json
from core.util import first, exist, AccessJson

# noinspection PyUnresolvedReferences
from tests.core.cli.cli_test import cli, cli_deps

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import filled_graph_db, graph_db, test_db, foo_model

# noinspection PyUnresolvedReferences
from tests.core.db.runningtaskdb_test import running_task_db

# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus

# noinspection PyUnresolvedReferences
from tests.core.task.task_handler_test import (
    task_handler,
    job_db,
    subscription_handler,
    test_workflow,
    task_handler_args,
)

# noinspection PyUnresolvedReferences
from tests.core.worker_task_queue_test import worker, task_queue, performed_by


@fixture
def json_source() -> str:
    nums = ",".join([f'{{ "num": {a}, "inner": {{"num": {a}}}}}' for a in range(0, 100)])
    return "json [" + nums + "," + nums + "]"


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
async def test_query_source(cli: CLI) -> None:
    result = await cli.execute_cli_command(
        'query is("foo") and reported.some_int==0 --> reported.identifier=~"9_"', stream.list
    )
    assert len(result[0]) == 10


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
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 200, "not_matched": 0}

    # count attributes
    result = await cli.execute_cli_command(f"{json_source} | count num", stream.list)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 9900, "not_matched": 0}

    # count attributes with path
    result = await cli.execute_cli_command(f"{json_source} | count inner.num", stream.list)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 9900, "not_matched": 0}

    # count unknown attributes
    result = await cli.execute_cli_command(f"{json_source} | count does_not_exist", stream.list)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 0, "not_matched": 200}


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
    result: list[list[str]] = await cli.execute_cli_command(f"{json_source} | chunk 50", stream.list)
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
    assert len(result[0]) == 13
    for elem in result[0]:
        assert {"a": "test", "b": 1, "c": True}.items() <= elem["desired"].items()


@pytest.mark.asyncio
async def test_set_metadata_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is("foo") | set_metadata a="test" b=1 c=true', stream.list)
    assert len(result[0]) == 13
    for elem in result[0]:
        assert {"a": "test", "b": 1, "c": True}.items() <= elem["metadata"].items()


@pytest.mark.asyncio
async def test_clean_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is("foo") | clean', stream.list)
    assert len(result[0]) == 13
    for elem in result[0]:
        assert {"clean": True}.items() <= elem["desired"].items()


@pytest.mark.asyncio
async def test_protect_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query is("foo") | protect', stream.list)
    assert len(result[0]) == 13
    for elem in result[0]:
        assert {"protected": True}.items() <= elem["metadata"].items()


@pytest.mark.asyncio
async def test_list_sink(cli: CLI, cli_deps: CLIDependencies) -> None:
    result = await cli.execute_cli_command("json [1,2,3]", stream.list)
    assert result == [[1, 2, 3]]


@pytest.mark.asyncio
async def test_flat_sink(cli: CLI) -> None:
    parsed = await cli.evaluate_cli_command("json [1,2,3]; json [4,5,6]; json [7,8,9]")
    result = await stream.list(stream.concat(stream.iterate(p.generator for p in parsed)))
    assert result == [1, 2, 3, 4, 5, 6, 7, 8, 9]


@pytest.mark.asyncio
async def test_format(cli: CLI) -> None:
    # access properties by name and path
    result = await cli.execute_cli_command(
        'json {"a":"b", "b": {"c":"d"}} | format a:{a} b:{b.c} na:{fuerty}', stream.list
    )
    assert result[0] == ["a:b b:d na:null"]
    # access deeply nested properties with dict and array
    result = await cli.execute_cli_command(
        'json {"a":{"b":{"c":{"d":[0,1,2, {"e":"f"}]}}}} | format will be an >{a.b.c.d[3].e}<', stream.list
    )
    assert result[0] == ["will be an >f<"]
    # make sure any path that is not available leads to the null value
    result = await cli.execute_cli_command("json {} | format {a}:{b.c.d}:{foo.bla[23].test}", stream.list)
    assert result[0] == ["null:null:null"]


@pytest.mark.asyncio
async def test_add_job_command(cli: CLI, task_handler: TaskHandler, job_db: JobDb) -> None:
    result = await cli.execute_cli_command("add_job 23 1 * * * echo Hello World @NOW@", stream.list)
    assert result == [["Job c6f602e8 added."]]
    job = await job_db.get("c6f602e8")
    assert job is not None
    assert job.command.command == "echo Hello World @NOW@"
    assert job.trigger == TimeTrigger("23 1 * * *")
    assert job.wait is None
    assert job in task_handler.task_descriptions
    with_event = await cli.execute_cli_command("add_job 23 1 * * * foo : echo Hello World", stream.list)
    assert with_event == [["Job 86ecb12c added."]]
    job_with_event: Job = await job_db.get("86ecb12c")  # type: ignore
    assert job_with_event.wait is not None
    event_trigger, timeout = job_with_event.wait
    assert event_trigger.message_type == "foo"
    assert timeout == timedelta(hours=24)
    assert job_with_event in task_handler.task_descriptions


@pytest.mark.asyncio
async def test_delete_job_command(cli: CLI, task_handler: TaskHandler, job_db: JobDb) -> None:
    await cli.execute_cli_command("add_job 23 1 * * * echo Hello World", stream.list)
    assert await job_db.get("c0fa3076") is not None
    result = await cli.execute_cli_command("delete_job c0fa3076", stream.list)
    assert result == [["Job c0fa3076 deleted."]]
    assert await job_db.get("c0fa3076") is None
    assert not exist(lambda x: x.id == "c0fa3076", task_handler.task_descriptions)


@pytest.mark.asyncio
async def test_jobs_command(cli: CLI, task_handler: TaskHandler, job_db: JobDb) -> None:
    await cli.execute_cli_command("add_job 23 1 * * * echo Hello World", stream.list)
    result: list[Json] = (await cli.execute_cli_command("jobs", stream.list))[0]
    job = first(lambda x: x.get("id") == "c0fa3076", result)
    assert job is not None
    assert job["trigger"] == {"cron_expression": "23 1 * * *"}
    assert job["command"] == "echo Hello World"


@pytest.mark.asyncio
async def test_tag_command(cli: CLI, performed_by: dict[str, list[str]], caplog: LogCaptureFixture) -> None:
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
    res1 = await cli.execute_cli_command('json ["root", "collector"] | tag update foo bla', stream.list)
    assert nr_of_performed() == 2
    assert {a["id"] for a in res1[0]} == {"root", "collector"}
    res2 = await cli.execute_cli_command('query is("foo") | tag update foo bla', stream.list)
    assert nr_of_performed() == 13
    assert len(res2[0]) == 13
    res3 = await cli.execute_cli_command('query is("foo") | tag delete foo', stream.list)
    assert nr_of_performed() == 13
    assert len(res3[0]) == 13
    captured = {a.message for a in caplog.records}
    res4 = await cli.execute_cli_command('query is("bla") limit 2 | tag delete foo', stream.list)
    assert nr_of_performed() == 2
    assert len(res4[0]) == 2
    # make sure that 2 warnings are emitted
    res = [a for a in caplog.records if a.levelno == logging.WARNING and a.message not in captured]
    assert len(res) == 2
    for a in res:
        assert a.message.startswith("Tag update not reflected in db. Wait until next collector run.")


@pytest.mark.asyncio
async def test_start_task_command(cli: CLI, task_handler: TaskHandler, test_workflow: Workflow) -> None:
    result = await cli.execute_cli_command(f"start_task {test_workflow.id}", stream.list)
    assert len(result[0]) == 1
    assert re.match("Task .+ has been started", result[0][0])


@pytest.mark.asyncio
async def test_tasks_command(cli: CLI, task_handler: TaskHandler, test_workflow: Workflow) -> None:
    await task_handler.start_task(test_workflow)
    result = await cli.execute_cli_command("tasks", stream.list)
    assert len(result[0]) == 1
    task = AccessJson(result[0][0])
    assert task.descriptor.id == "test_workflow"


@pytest.mark.asyncio
async def test_kind_command(cli: CLI) -> None:
    result = await cli.execute_cli_command("kind", stream.list)
    for kind in predefined_kinds:
        assert kind.fqn in result[0][0]
    result = await cli.execute_cli_command("kind string", stream.list)
    assert result[0][0] == {"name": "string", "runtime_kind": "string"}
    result = await cli.execute_cli_command("kind -p reported.ctime", stream.list)
    assert result[0][0] == {"name": "datetime", "runtime_kind": "datetime"}
    with pytest.raises(Exception):
        await cli.execute_cli_command("kind foo bla bar", stream.list)
