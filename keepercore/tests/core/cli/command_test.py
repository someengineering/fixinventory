import pytest
from aiostream import stream
from datetime import timedelta
from pytest import fixture

from core.cli.cli import CLI, CLIDependencies
from core.db.jobdb import JobDb
from core.error import CLIParseError
from core.task.task_description import TimeTrigger
from core.task.task_handler import TaskHandler

from core.types import Json
from core.util import first, exist

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import filled_graph_db, graph_db, test_db, foo_model

# noinspection PyUnresolvedReferences
from core.cli.command import ListSink

# noinspection PyUnresolvedReferences
from tests.core.cli.cli_test import cli, cli_deps

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
from tests.core.db.runningtaskdb_test import running_task_db


@fixture
def json_source() -> str:
    nums = ",".join([f'{{ "num": {a}}}' for a in range(0, 100)])
    return "json [" + nums + "," + nums + "]"


@pytest.mark.asyncio
async def test_echo_source(cli: CLI) -> None:
    # no arg passed to json
    result = await cli.execute_cli_command("echo", stream.list)
    assert result[0] == [""]

    # simple string passed to json
    result = await cli.execute_cli_command("echo this is a string", stream.list)
    assert result[0] == ["this is a string"]

    result = await cli.execute_cli_command('echo "foo bla bar"', stream.list)
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
        'query isinstance("foo") and reported.some_int==0 --> reported.identifier=~"9_"', stream.list
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

    # count unknown attributes
    result = await cli.execute_cli_command(f"{json_source} | count does_not_exist", stream.list)
    assert len(result[0]) == 1
    assert result[0][0] == {"matched": 0, "not_matched": 200}


@pytest.mark.asyncio
async def test_head_command(cli: CLI) -> None:
    assert await cli.execute_cli_command("json [1,2,3,4,5] | head 2", stream.list) == [[1, 2]]
    assert await cli.execute_cli_command("json [1,2,3,4,5] | head", stream.list) == [[1, 2, 3, 4, 5]]


@pytest.mark.asyncio
async def test_tail_command(cli: CLI) -> None:
    assert await cli.execute_cli_command("json [1,2,3,4,5] | tail 2", stream.list) == [[4, 5]]
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
async def test_desire_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query isinstance("foo") | desire a="test" b=1 c=true', stream.list)
    assert len(result[0]) == 13
    for elem in result[0]:
        assert elem["desired"] == {"a": "test", "b": 1, "c": True}


@pytest.mark.asyncio
async def test_clean_command(cli: CLI) -> None:
    result = await cli.execute_cli_command('query isinstance("foo") | clean', stream.list)
    assert len(result[0]) == 13
    for elem in result[0]:
        assert elem["desired"] == {"clean": True}


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
