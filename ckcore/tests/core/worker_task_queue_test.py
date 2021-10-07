import asyncio
from collections import defaultdict
from datetime import timedelta
from typing import AsyncGenerator, Dict, List, Tuple

from pytest import fixture, mark

from core.model.graph_access import Section
from core.model.resolve_in_graph import GraphResolver, NodePath
from core.util import group_by, identity, value_in_path
from core.worker_task_queue import WorkerTaskDescription, WorkerTaskQueue, WorkerTask


@fixture
def task_queue() -> WorkerTaskQueue:
    return WorkerTaskQueue()


@fixture
def performed_by() -> Dict[str, List[str]]:
    return defaultdict(list)


@fixture
async def worker(
    task_queue: WorkerTaskQueue, performed_by: Dict[str, List[str]]
) -> AsyncGenerator[Tuple[WorkerTaskDescription, WorkerTaskDescription, WorkerTaskDescription], None]:
    success = WorkerTaskDescription("success_task")
    fail = WorkerTaskDescription("fail_task")
    wait = WorkerTaskDescription("wait_task")
    tag = WorkerTaskDescription("tag")

    async def do_work(worker_id: str, task_descriptions: List[WorkerTaskDescription]) -> None:
        async with task_queue.attach(worker_id, task_descriptions) as tasks:
            while True:
                task: WorkerTask = await tasks.get()
                performed_by[task.id].append(worker_id)
                if task.name == success.name:
                    await task_queue.acknowledge_task(worker_id, task.id, {"result": "done!"})
                elif task.name == fail.name:
                    await task_queue.error_task(worker_id, task.id, ";)")
                elif task.name == wait.name:
                    # if we come here, neither success nor failure was given, ignore the task
                    pass
                elif task.name == "tag":
                    node = task.data["node"]
                    for key in GraphResolver.resolved_ancestors.keys():
                        for section in Section.all:
                            if section in node:
                                node[section].pop(key, None)

                    # update or delete tags
                    if "tags" not in node:
                        node["tags"] = {}

                    if task.data.get("delete"):
                        for a in task.data.get("delete"):  # type: ignore
                            node["tags"].pop(a, None)
                            continue
                    elif task.data.get("update"):
                        for k, v in task.data.get("update").items():  # type: ignore
                            node["tags"][k] = v
                            continue

                    # for testing purposes: change revision number
                    kind: str = value_in_path(node, NodePath.reported_kind)  # type: ignore
                    if kind == "bla":
                        node["revision"] = "changed"

                    await task_queue.acknowledge_task(worker_id, task.id, node)

    workers = [asyncio.create_task(do_work(f"w{a}", [success, fail, wait, tag])) for a in range(0, 4)]
    await asyncio.sleep(0)

    yield success, fail, wait
    for worker in workers:
        worker.cancel()


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
    by_worker = group_by(identity, (item for sublist in performed_by.values() for item in sublist))
    assert len(by_worker) == 4
    for work_done in by_worker.values():
        assert len(work_done) == 5


@mark.asyncio
async def test_handle_failure(
    task_queue: WorkerTaskQueue,
    worker: Tuple[WorkerTaskDescription, WorkerTaskDescription, WorkerTaskDescription],
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
        await task_queue.add_task(t)

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
    by_worker = group_by(identity, (item for sublist in performed_by.values() for item in sublist))
    assert len(by_worker) == 4
    for work_done in by_worker.values():
        assert len(work_done) == 20


def create_task(uid: str, name: str) -> WorkerTask:
    return WorkerTask(uid, name, {}, {}, asyncio.get_event_loop().create_future(), timedelta())
