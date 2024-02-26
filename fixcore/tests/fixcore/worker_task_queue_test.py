import asyncio
from datetime import timedelta
from typing import Dict, List, Tuple

from pytest import mark

from fixcore.ids import TaskId
from fixcore.util import group_by
from fixcore.worker_task_queue import WorkerTaskDescription, WorkerTaskQueue, WorkerTask


@mark.asyncio
async def test_handle_work_successfully(
    task_queue: WorkerTaskQueue,
    worker: Tuple[WorkerTaskDescription, WorkerTaskDescription, WorkerTaskDescription],
    performed_by: Dict[str, List[str]],
) -> None:
    success_task, _, _ = worker

    all_tasks = [create_task(str(n), success_task.name) for n in range(0, 20)]
    for t in all_tasks:
        await task_queue.add_task(t)

    results = await asyncio.gather(*[a.callback for a in all_tasks])
    assert results == [{"result": "done!"} for _ in range(0, 20)]

    # make sure the work is split equally between all workers: 20 work items by 4 workers: 5 work items each
    by_worker = group_by(lambda x: x, (item for sublist in performed_by.values() for item in sublist))
    assert len(by_worker) == 4
    for work_done in by_worker.values():
        assert len(work_done) == 5


@mark.asyncio
async def test_handle_failure(
    task_queue: WorkerTaskQueue, worker: Tuple[WorkerTaskDescription, WorkerTaskDescription, WorkerTaskDescription]
) -> None:
    _, fail_task, _ = worker

    all_tasks = [create_task(str(n), fail_task.name) for n in range(0, 20)]
    for t in all_tasks:
        await task_queue.add_task(t)

    results = await asyncio.gather(*[a.callback for a in all_tasks], return_exceptions=True)
    # make sure all results are failures
    for r in results:
        assert isinstance(r, Exception)


@mark.asyncio
async def test_handle_outdated(
    task_queue: WorkerTaskQueue,
    worker: Tuple[WorkerTaskDescription, WorkerTaskDescription, WorkerTaskDescription],
    performed_by: Dict[str, List[str]],
) -> None:
    _, _, outdated_task = worker

    all_tasks = [create_task(str(n), outdated_task.name) for n in range(0, 20)]
    for t in all_tasks:
        await task_queue.add_task(t, retry_count=3)

    await asyncio.sleep(0)

    count_outstanding = 0
    while task_queue.outstanding_tasks:
        await task_queue.check_outdated_unassigned_tasks()
        count_outstanding += 1

    # every message is retried 3 times ==> 4 times to get rid of all messages
    assert count_outstanding == 4

    results = await asyncio.gather(*[a.callback for a in all_tasks], return_exceptions=True)
    # make sure all results are failures
    for r in results:
        assert isinstance(r, Exception)

    # 20 work items by 4 workers: 5 work items each + retried 3 times (15) => 20
    by_worker = group_by(lambda x: x, (item for sublist in performed_by.values() for item in sublist))
    assert len(by_worker) == 4
    for work_done in by_worker.values():
        assert len(work_done) == 20


def create_task(uid: str, name: str) -> WorkerTask:
    return WorkerTask(TaskId(uid), name, {}, {}, asyncio.get_event_loop().create_future(), timedelta())
