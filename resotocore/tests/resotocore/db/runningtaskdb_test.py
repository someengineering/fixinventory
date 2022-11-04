from datetime import timedelta

import pytest
from arango.database import StandardDatabase
from typing import List, Dict, Tuple, Any

from resotocore.db import runningtaskdb
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.runningtaskdb import RunningTaskData, RunningTaskDb, RunningTaskStepInfo
from resotocore.message_bus import ActionDone
from resotocore.util import utc
from resotocore.task.model import Subscriber
from resotocore.ids import TaskId, SubscriberId, TaskDescriptorId

from resotocore.task.task_description import RunningTask

# noinspection PyUnresolvedReferences
from tests.resotocore.task.task_description_test import workflow_instance, test_workflow

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import test_db, local_client, system_db

# noinspection PyUnresolvedReferences
from tests.resotocore.message_bus_test import message_bus, all_events


@pytest.fixture
async def running_task_db(test_db: StandardDatabase) -> RunningTaskDb:
    async_db = AsyncArangoDB(test_db)
    task_db = runningtaskdb.running_task_db(async_db, "running_task")
    await task_db.create_update_schema()
    await task_db.wipe()
    return task_db


@pytest.fixture
def instances() -> List[RunningTaskData]:
    messages = [ActionDone(str(a), TaskId("test"), "bla", SubscriberId("sf")) for a in range(0, 10)]
    state_data = {"test": 1}
    return [
        RunningTaskData(
            TaskId(f"task_{a}"),
            TaskDescriptorId(str(a)),
            "task_123",
            messages,
            "start",
            state_data,
            [RunningTaskStepInfo(f"step_{a}", False, utc(), utc()) for a in range(0, 3)],
            task_started_at=utc(),
            task_duration=timedelta(seconds=10),
            done=a > 5,
            has_info=a > 6,
            has_error=a > 7,
        )
        for a in range(0, 10)
    ]


@pytest.mark.asyncio
async def test_load_running(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)
    not_done = list(filter(lambda x: not x.done, instances))
    assert not_done.sort() == [sub async for sub in running_task_db.all_running()].sort()


@pytest.mark.asyncio
async def test_load(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)
    loaded = [sub async for sub in running_task_db.all()]
    assert instances.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_filtered(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)

    async def filtered_list(**kwargs: Any) -> List[TaskId]:
        async with await running_task_db.filtered(**kwargs) as crsr:
            return [elem.id async for elem in crsr]

    assert len(await filtered_list()) == len(instances)
    assert len(await filtered_list(limit=1)) == 1
    assert len(await filtered_list(descriptor_name="task_123")) == len(instances)
    assert await filtered_list(task_id=TaskId("task_1")) == [TaskId("task_1")]
    assert len(await filtered_list(started_from=utc() + timedelta(minutes=1))) == 0
    assert len(await filtered_list(started_from=utc() - timedelta(minutes=1))) == 10
    assert len(await filtered_list(started_until=utc() + timedelta(minutes=1))) == 10
    assert len(await filtered_list(started_until=utc() - timedelta(minutes=1))) == 0
    assert len(await filtered_list(with_info=True)) == 3
    assert len(await filtered_list(with_info=False)) == 7
    assert len(await filtered_list(with_error=True)) == 2
    assert len(await filtered_list(with_error=False)) == 8


@pytest.mark.asyncio
async def test_update(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    # multiple updates should work as expected
    await running_task_db.update_many(instances)
    await running_task_db.update_many(instances)
    await running_task_db.update_many(instances)
    loaded = [sub async for sub in running_task_db.all()]
    assert instances.sort() == loaded.sort()


@pytest.mark.asyncio
async def test_delete(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)
    remaining = list(instances)
    for _ in instances:
        sub = remaining.pop()
        await running_task_db.delete_value(sub)
        loaded = [sub async for sub in running_task_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in running_task_db.all()]) == 0


@pytest.mark.asyncio
async def test_update_state(
    running_task_db: RunningTaskDb,
    workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]],
) -> None:
    wi, _, _, _ = workflow_instance
    task_id = TaskId("test")
    subscriber_id = SubscriberId("sf")
    first = ActionDone("start_collect", task_id, "bla", subscriber_id)
    second = ActionDone("collect", task_id, "bla", subscriber_id)
    third = ActionDone("collect_done", task_id, "bla", subscriber_id)

    async def assert_state(current: str, message_count: int) -> RunningTaskData:
        state: RunningTaskData = await running_task_db.get(wi.id)  # type: ignore
        assert state.current_state_name == current
        assert len(state.received_messages) == message_count
        return state

    await running_task_db.insert(wi)
    await assert_state(wi.current_state.name, 6)

    wi.machine.set_state("start")
    await running_task_db.update_state(wi, first)
    await assert_state("start", 7)

    wi.machine.set_state("collect")
    await running_task_db.update_state(wi, second)
    await assert_state("collect", 8)

    wi.machine.set_state("done")
    await running_task_db.update_state(wi, third)
    last = await assert_state("done", 9)

    assert last.received_messages[-3:] == [first, second, third]
