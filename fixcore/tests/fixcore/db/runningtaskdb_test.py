from datetime import timedelta
from typing import List, Dict, Tuple, Any

from pytest import fixture, mark

from fixcore.db.runningtaskdb import RunningTaskData, RunningTaskDb, RunningTaskStepInfo
from fixcore.ids import TaskId, SubscriberId, TaskDescriptorId
from fixcore.message_bus import ActionDone
from fixcore.task.model import Subscriber
from fixcore.task.task_description import RunningTask, Workflow
from fixcore.util import utc, utc_str

now = utc()


@fixture
def instances() -> List[RunningTaskData]:
    messages = [ActionDone(str(a), TaskId("test"), "bla", SubscriberId("sf")) for a in range(0, 10)]
    state_data = {"test": 1}
    return [
        RunningTaskData(
            TaskId(f"task_{a}"),
            TaskDescriptorId("task_123"),
            "task_123",
            Workflow.__name__,
            messages,
            "start",
            state_data,
            [RunningTaskStepInfo(f"step_{a}", False, now, now) for a in range(0, 3)],
            task_started_at=now,
            task_duration=timedelta(seconds=10),
            done=a > 5,
            has_info=a > 6,
            has_error=a > 7,
        )
        for a in range(0, 10)
    ]


@mark.asyncio
async def test_load_running(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)
    not_done = list(filter(lambda x: not x.done, instances))
    assert not_done.sort() == [sub async for sub in running_task_db.all_running()].sort()


@mark.asyncio
async def test_last(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)
    running_tasks = list(filter(lambda x: x.done, instances))
    running_tasks.sort(key=lambda x: x.task_started_at, reverse=True)
    done_task = next(iter(running_tasks), None)
    assert done_task
    last_done = await running_task_db.last(descriptor_id=done_task.task_descriptor_id)
    assert last_done
    assert done_task.id == last_done.id

    assert await running_task_db.last()


@mark.asyncio
async def test_load(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)
    loaded = [sub async for sub in running_task_db.all()]
    assert instances.sort() == loaded.sort()


@mark.asyncio
async def test_filtered(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)

    async def filtered_list(**kwargs: Any) -> List[TaskId]:
        async with await running_task_db.filtered(**kwargs) as crsr:
            return [elem.id async for elem in crsr]

    assert len(await filtered_list()) == len(instances)
    assert len(await filtered_list(limit=1)) == 1
    assert len(await filtered_list(descriptor_id="task_123")) == len(instances)
    assert await filtered_list(task_id=TaskId("task_1")) == [TaskId("task_1")]
    assert len(await filtered_list(started_after=now + timedelta(minutes=1))) == 0
    assert len(await filtered_list(started_after=now - timedelta(minutes=1))) == 10
    assert len(await filtered_list(started_before=now + timedelta(minutes=1))) == 10
    assert len(await filtered_list(started_before=now - timedelta(minutes=1))) == 0
    assert len(await filtered_list(with_info=True)) == 3
    assert len(await filtered_list(with_info=False)) == 7
    assert len(await filtered_list(with_error=True)) == 2
    assert len(await filtered_list(with_error=False)) == 8


@mark.asyncio
async def test_aggregated(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)
    res = await running_task_db.aggregated_history()
    assert res == {
        "task_123": {"count": 10, "last_run": utc_str(now), "runs_with_errors": 2, "average_duration": "10s"}
    }


@mark.asyncio
async def test_update(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    # multiple updates should work as expected
    await running_task_db.update_many(instances)
    await running_task_db.update_many(instances)
    await running_task_db.update_many(instances)
    loaded = [sub async for sub in running_task_db.all()]
    assert instances.sort() == loaded.sort()


@mark.asyncio
async def test_delete(running_task_db: RunningTaskDb, instances: List[RunningTaskData]) -> None:
    await running_task_db.update_many(instances)
    remaining = list(instances)
    for _ in instances:
        sub = remaining.pop()
        await running_task_db.delete_value(sub)
        loaded = [sub async for sub in running_task_db.all()]
        assert remaining.sort() == loaded.sort()
    assert len([sub async for sub in running_task_db.all()]) == 0


@mark.asyncio
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
