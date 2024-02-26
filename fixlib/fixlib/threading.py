from __future__ import annotations

import concurrent
from collections import defaultdict, deque
from concurrent.futures import Executor, Future
from functools import reduce
from threading import Event, Lock
from typing import Any, Callable, Deque, Dict, List, Tuple, TypeVar, Optional

from attr import field
from attrs import define

from fixlib.logger import log

T = TypeVar("T")


class CancelOnFirstError(Exception):
    pass


class GatherFutures:
    def __init__(self, futures: List[Future[Any]]) -> None:
        self._futures = futures
        self._lock = Lock()
        self._to_wait = len(futures)
        self._when_done: Future[None] = Future()
        for future in futures:
            future.add_done_callback(self._on_future_done)

    def _on_future_done(self, _: Future[Any]) -> None:
        with self._lock:
            self._to_wait -= 1
            if self._to_wait == 0:
                self._when_done.set_result(None)

    @staticmethod
    def all(futures: List[Future[Any]]) -> Future[None]:
        return GatherFutures(futures)._when_done


@define
class ExecutorQueueTask:
    key: Any
    fn: Callable[..., T]
    args: Tuple[Any, ...]
    kwargs: Dict[str, Any]
    future: Future[Any]

    def __call__(self) -> T:  # type: ignore
        try:
            result: T = self.fn(*self.args, **self.kwargs)
            self.future.set_result(result)
            return result
        except Exception as e:
            self.future.set_exception(e)
            raise


@define
class ExecutorQueue:
    """
    Use an underlying executor to perform work in parallel, but limit the number of tasks per key.
    If fail_on_first_exception_in_group is True, then the first exception in a group
    will not execute any more tasks in the same group.
    """

    executor: Executor
    name: str
    tasks_per_key: Optional[Callable[[str], int]] = None
    fail_on_first_exception_in_group: bool = False
    _tasks_lock: Lock = Lock()
    _tasks: Dict[str, Deque[ExecutorQueueTask]] = field(factory=lambda: defaultdict(deque))
    _in_progress: Dict[str, int] = field(factory=lambda: defaultdict(int))
    _futures: List[Future[Any]] = field(factory=list)
    _exceptions: Dict[Any, Exception] = field(factory=dict)
    _task_finished: Event = Event()

    def submit_work(self, key: Any, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        future = Future[T]()
        task = ExecutorQueueTask(key=key, fn=fn, args=args, kwargs=kwargs, future=future)
        self.__append_work(task)
        return future

    def __append_work(self, task: ExecutorQueueTask) -> None:
        with self._tasks_lock:
            self._tasks[task.key].appendleft(task)
            self.__check_queue(task.key)

    def __check_queue(self, key: Any) -> None:
        # note: this method is not thread safe, it should only be called from within a lock
        in_progress = self._in_progress[key]
        tasks = self._tasks[key]

        if self.fail_on_first_exception_in_group and self._exceptions.get(key) is not None:
            # Fail all tasks in this group
            ex = CancelOnFirstError("Exception happened in another thread. Do not start work.")
            for task in tasks:
                task.future.set_exception(ex)
            # Clear the queue, so we don't execute them
            # Clear the queue, so we don't execute them
            tasks.clear()

        if ((self.tasks_per_key is None) or (in_progress < self.tasks_per_key(key))) and tasks:
            task = tasks.pop()
            self._in_progress[key] += 1
            self.__perform_task(task)

    def __perform_task(self, task: ExecutorQueueTask) -> Future[T]:
        def only_start_when_no_error() -> T:
            # in case of exception let's fail fast and do not execute the function
            if self._exceptions.get(task.key) is None:
                try:
                    return task()
                except Exception as e:
                    # only store the first exception if we should fail on first future
                    if self._exceptions.get(task.key) is None:
                        self._exceptions[task.key] = e
                    raise e
            else:
                raise CancelOnFirstError(
                    "Exception happened in another thread. Do not start work."
                ) from self._exceptions[task.key]

        def execute() -> T:
            try:
                return only_start_when_no_error() if self.fail_on_first_exception_in_group else task()
            finally:
                with self._tasks_lock:
                    self._in_progress[task.key] -= 1
                    self._task_finished.set()
                    self.__check_queue(task.key)

        future = self.executor.submit(execute)

        self._futures.append(future)
        return future

    def wait_for_submitted_work(self) -> None:
        # wait until all futures are complete
        to_wait = []

        # step 1: wait until all tasks are committed to the executor
        while True:
            with self._tasks_lock:
                ip = reduce(lambda x, y: x + y, self._in_progress.values(), 0)
                if ip == 0:
                    to_wait = self._futures
                    self._futures = []
                    break
                else:
                    # safe inside the lock. clear this event and check when next task is done
                    self._task_finished.clear()
            self._task_finished.wait()

        # step 2: wait for all tasks to complete
        for future in concurrent.futures.as_completed(to_wait):
            try:
                future.result()
            except CancelOnFirstError:
                pass
            except Exception as ex:
                log.exception(f"Unhandled exception in {self.name}: {ex}")
                raise
