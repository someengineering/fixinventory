from __future__ import annotations

import asyncio
import logging
from asyncio import Queue, Future
from collections import defaultdict
from contextlib import asynccontextmanager
from attrs import define, field
from datetime import timedelta, datetime
from functools import reduce
from typing import Any, Optional, AsyncGenerator, Dict, List

from resotocore.types import Json, JsonElement
from resotocore.util import utc, Periodic, set_future_result
from resotocore.ids import TaskId, WorkerId

log = logging.getLogger(__name__)


class WorkerTaskName:
    tag = "tag"
    validate_config = "validate_config"


@define(eq=False, frozen=True)
class WorkerTask:
    id: TaskId  # the unique id of the task
    name: str  # the well known name of the task to perform: the worker attaches to this name
    attrs: Dict[str, str]  # all worker attributes need to match those attrs (but the task can define more)
    data: Json
    callback: Future[Json]  # the callers callback. Notify the caller once the task is dones
    timeout: timedelta  # timeout of this task to be performed

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, WorkerTask) and other.id == self.id

    def __hash__(self) -> int:
        return hash(self.id)

    def to_json(self) -> Json:
        return {"task_id": self.id, "task_name": self.name, "data": self.data, "attrs": self.attrs}


@define(order=True, hash=True)
class WorkerTaskResult:
    task_id: TaskId
    result: str
    data: Optional[JsonElement] = None
    error: Optional[str] = None


@define(order=True, hash=True)
class WorkerTaskInProgress:
    task: WorkerTask
    worker: WorkerTaskSubscription
    retry_counter: int
    deadline: datetime


@define(order=True, hash=True)
class WorkerTaskOnHold:
    task: WorkerTask
    retry_counter: int
    deadline: datetime


@define(order=True, hash=True, frozen=True)
class WorkerTaskDescription:
    name: str
    filter: Dict[str, List[str]] = field(factory=dict)


@define(order=True, hash=True, frozen=True)
class WorkerTaskSubscription:
    worker_id: WorkerId
    task: WorkerTaskDescription
    queue: Queue[WorkerTask]

    def __len__(self) -> int:
        return self.queue.qsize()


class WorkerTaskQueue:
    """
    This class implements a simple task queue.
    """

    def __init__(self) -> None:
        # key is the task_name, value is the list of worker subscriptions
        self.worker_by_task_name: Dict[str, List[WorkerTaskSubscription]] = defaultdict(list)
        self.work_count: Dict[str, int] = defaultdict(lambda: 0)
        self.outstanding_tasks: Dict[str, WorkerTaskInProgress] = {}
        self.unassigned_tasks: Dict[str, WorkerTaskOnHold] = {}
        self.lock = asyncio.Lock()  # note: this lock is not reentrant!
        self.outdated_checker: Periodic = Periodic(
            "check_outdated_tasks", self.check_outdated_unassigned_tasks, timedelta(seconds=5)
        )

    async def start(self) -> None:
        await self.outdated_checker.start()

    async def stop(self) -> None:
        await self.outdated_checker.stop()

    @asynccontextmanager
    async def attach(
        self, worker_id: WorkerId, task_descriptions: List[WorkerTaskDescription], queue_size: int = 0
    ) -> AsyncGenerator[Queue[WorkerTask], None]:
        queue: Queue[WorkerTask] = Queue(queue_size)
        subscriptions = [WorkerTaskSubscription(worker_id, td, queue) for td in task_descriptions]

        if len(task_descriptions) == 0:
            raise AttributeError("Need at least one task description to attach!")
        try:
            async with self.lock:
                self.work_count[worker_id] = 0
                for subscription in subscriptions:
                    self.worker_by_task_name[subscription.task.name].append(subscription)
            log.info(f"Worker {worker_id} added to following task queues: {task_descriptions}")
            yield queue
        finally:
            log.info(f"Remove worker: {worker_id}")
            async with self.lock:
                # remove all subscriptions
                for subscription in subscriptions:
                    self.worker_by_task_name[subscription.task.name].remove(subscription)
                # remove counter
                self.work_count.pop(worker_id, None)
                # reschedule open tasks
                open_tasks = [task for task in self.outstanding_tasks.values() if task.worker.worker_id == worker_id]
                await self.__retry_tasks(open_tasks)

    async def add_task(self, task: WorkerTask, retry_count: int = 0) -> None:
        async with self.lock:
            await self.__add_task(task, retry_count)

    async def acknowledge_task(
        self, worker_id: WorkerId, task_id: TaskId, result: Optional[JsonElement] = None
    ) -> None:
        async with self.lock:
            await self.__acknowledge_task(worker_id, task_id, result)

    async def error_task(self, worker_id: WorkerId, task_id: TaskId, message: str) -> None:
        async with self.lock:
            await self.__error_task(worker_id, task_id, message)

    async def check_outdated_unassigned_tasks(self) -> None:
        now = utc()
        outstanding = [ip for ip in self.outstanding_tasks.values() if ip.deadline < now]
        not_started_outdated = [ns for ns in self.unassigned_tasks.values() if ns.deadline < now]
        async with self.lock:
            await self.__retry_tasks(outstanding)
            for ns in not_started_outdated:
                log.info(f"No worker for task: {ns.task.id}. Give up.")
                set_future_result(ns.task.callback, Exception(f"No worker for task: {ns.task.name}"))
                self.unassigned_tasks.pop(ns.task.id, None)
            # unassigned_task now only holds valid tasks
            for ns in list(self.unassigned_tasks.values()):
                if await self.__add_task(ns.task, ns.retry_counter):
                    self.unassigned_tasks.pop(ns.task.id, None)

    async def __add_task(self, task: WorkerTask, retry_count: int) -> bool:
        def outstanding_tasks(subscription: WorkerTaskSubscription) -> int:
            return self.work_count[subscription.worker_id]

        def can_perform(subscription: WorkerTaskSubscription) -> bool:
            # the filter criteria in the subscription needs to be matched by the task attributes
            # note: the task can define more attributes, that would be ignored
            def matches_task_filter(name: str, filter_list: List[str]) -> bool:
                value = task.attrs.get(name)
                return value in filter_list if value else False

            return all(matches_task_filter(n, f) for n, f in subscription.task.filter.items())

        # all workers that match the task filter
        matching_subscriptions = [wt for wt in self.worker_by_task_name[task.name] if can_perform(wt)]
        if matching_subscriptions:
            # filter the list for worker with the most specific filter (==most task filter)
            max_filter_len = reduce(lambda res, x: max(res, len(x.task.filter)), matching_subscriptions, 0)
            same_filter_len = (a for a in matching_subscriptions if len(a.task.filter) == max_filter_len)
            # sort and use the one with the least amount of outstanding tasks
            subscriptions = sorted(same_filter_len, key=outstanding_tasks)
            sub = subscriptions[0]  # this is the worker with the least amount of work
            # todo: store task in db
            self.outstanding_tasks[task.id] = WorkerTaskInProgress(task, sub, retry_count, utc() + task.timeout)
            await sub.queue.put(task)
            self.work_count[sub.worker_id] = self.work_count[sub.worker_id] + 1
            return True
        else:
            self.outstanding_tasks.pop(task.id, None)
            if task.id not in self.unassigned_tasks:
                self.unassigned_tasks[task.id] = WorkerTaskOnHold(task, retry_count, utc() + task.timeout)
            return False

    async def __acknowledge_task(self, worker_id: WorkerId, task_id: TaskId, result: Optional[JsonElement]) -> None:
        # remove task from internal list
        in_progress = self.outstanding_tasks.get(task_id, None)
        if in_progress:
            if in_progress.worker.worker_id == worker_id:
                self.outstanding_tasks.pop(task_id, None)
                self.work_count[worker_id] = self.work_count[worker_id] - 1
                set_future_result(in_progress.task.callback, result)
                # todo: remove task from database
            else:
                log.info(f"Got result for task {task_id} from wrong worker {worker_id}. outdated?")

    async def __error_task(self, worker_id: WorkerId, task_id: TaskId, message: str) -> None:
        log.warning(f"Task {task_id} yielded an error: {message}")
        in_progress = self.outstanding_tasks.get(task_id, None)
        if in_progress:
            if in_progress.worker.worker_id == worker_id:
                self.outstanding_tasks.pop(task_id, None)
                self.work_count[worker_id] = self.work_count[worker_id] - 1
                set_future_result(in_progress.task.callback, AttributeError(f"Error executing task: {message}"))
                # todo: remove task from database
            else:
                log.info(f"Got error for task {task_id} from wrong worker {worker_id}. outdated?")

    async def __retry_tasks(self, tasks: List[WorkerTaskInProgress]) -> None:
        for task in tasks:
            if task.retry_counter > 0:
                # todo: maybe it still in the queue of the worker?
                # reschedule
                await self.__add_task(task.task, task.retry_counter - 1)
            else:
                log.warning(f"Too many retried executing task {task.task.id}. Give up.")
                self.outstanding_tasks.pop(task.task.id, None)
                self.work_count[task.worker.worker_id] = self.work_count[task.worker.worker_id] - 1
                set_future_result(task.task.callback, TimeoutError("Could not finish the task."))
