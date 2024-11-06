from __future__ import annotations

import asyncio
from asyncio import TaskGroup, Task
from collections import deque
from typing import AsyncIterable, AsyncIterator, TypeVar, Optional, List, Dict, Callable, Generic, ParamSpec, TypeAlias
from typing import Iterable, Awaitable, Never, Tuple, Union

T = TypeVar("T")
R = TypeVar("R", covariant=True)
P = ParamSpec("P")

DirectOrAwaitable: TypeAlias = Union[T, Awaitable[T]]
IterOrAsyncIter: TypeAlias = Union[Iterable[T], AsyncIterable[T]]

DefaultTaskLimit = 1


def _async_iter(x: Iterable[T]) -> AsyncIterator[T]:
    async def gen() -> AsyncIterator[T]:
        for item in x:
            yield item

    return gen()


def _to_async_iter(x: IterOrAsyncIter[T]) -> AsyncIterable[T]:
    if isinstance(x, AsyncIterable):
        return x
    else:
        return _async_iter(x)


def _flatmap(
    source: AsyncIterable[IterOrAsyncIter[DirectOrAwaitable[T]]],
    task_limit: Optional[int],
    ordered: bool,
) -> AsyncIterator[T]:
    if ordered:
        return _flatmap_ordered(source, task_limit)
    else:
        return _flatmap_unordered(source, task_limit)


async def _flatmap_unordered(
    source: AsyncIterable[IterOrAsyncIter[DirectOrAwaitable[T]]],
    task_limit: Optional[int] = None,
) -> AsyncIterator[T]:
    semaphore = asyncio.Semaphore(task_limit or DefaultTaskLimit)
    queue: asyncio.Queue[T | Exception] = asyncio.Queue()
    tasks_in_flight = 0

    async def worker(sub_iter: IterOrAsyncIter[DirectOrAwaitable[T]]) -> None:
        nonlocal tasks_in_flight
        try:
            if isinstance(sub_iter, AsyncIterable):
                async for si in sub_iter:
                    if isinstance(si, Awaitable):
                        si = await si
                    await queue.put(si)
            else:
                for si in sub_iter:
                    if isinstance(si, Awaitable):
                        si = await si
                    await queue.put(si)
        except Exception as e:
            await queue.put(e)  # exception: put it in the queue to be handled
        finally:
            semaphore.release()
            tasks_in_flight -= 1

    async with TaskGroup() as tg:
        # Start worker tasks
        async for src in source:
            await semaphore.acquire()
            tg.create_task(worker(src))
            tasks_in_flight += 1

        # Consume items from the queue and yield them
        while True:
            if tasks_in_flight == 0 and queue.empty():
                break
            try:
                item = await queue.get()
                if isinstance(item, Exception):
                    raise item
                yield item
            except asyncio.CancelledError:
                break


async def _flatmap_ordered(
    source: AsyncIterable[IterOrAsyncIter[DirectOrAwaitable[T]]],
    task_limit: Optional[int] = None,
) -> AsyncIterator[T]:
    tlf = task_limit or DefaultTaskLimit
    semaphore = asyncio.Semaphore(tlf)
    tasks: Dict[int, Task[None]] = {}
    results: Dict[int, List[T] | Exception] = {}
    next_index_to_yield = 0
    source_iter = aiter(source)
    max_index_started = -1  # Highest index of tasks started
    source_exhausted = False

    async def worker(sub_iter: IterOrAsyncIter[T | Awaitable[T]], index: int) -> None:
        items = []
        try:
            if isinstance(sub_iter, AsyncIterable):
                async for item in sub_iter:
                    if isinstance(item, Awaitable):
                        item = await item
                    items.append(item)
            else:
                for item in sub_iter:
                    if isinstance(item, Awaitable):
                        item = await item
                    items.append(item)
            results[index] = items
        except Exception as e:
            results[index] = e  # Store exception to be raised later
        finally:
            semaphore.release()

    while True:
        # Start new tasks up to task_limit ahead of next_index_to_yield
        while not source_exhausted and (max_index_started - next_index_to_yield + 1) < tlf:
            try:
                await semaphore.acquire()
                si = await anext(source_iter)
                max_index_started += 1
                tasks[max_index_started] = asyncio.create_task(worker(_to_async_iter(si), max_index_started))
            except StopAsyncIteration:
                source_exhausted = True
                break

        if next_index_to_yield in results:
            result = results.pop(next_index_to_yield)
            if isinstance(result, Exception):
                raise result
            else:
                for res in result:
                    yield res
            # Remove completed task
            tasks.pop(next_index_to_yield, None)  # noqa
            next_index_to_yield += 1
        else:
            # Wait for the next task to complete
            if next_index_to_yield in tasks:
                task = tasks[next_index_to_yield]
                await asyncio.wait({task})
            elif not tasks and source_exhausted:
                # No more tasks to process
                break
            else:
                # Yield control to the event loop
                await asyncio.sleep(0.01)


class Stream(Generic[T], AsyncIterator[T]):
    def __init__(self, iterator: AsyncIterator[T]):
        self.iterator = iterator

    def __aiter__(self) -> AsyncIterator[T]:
        return self

    async def __anext__(self) -> T:
        return await anext(self.iterator)

    def filter(self, fn: Callable[[T], DirectOrAwaitable[bool]]) -> Stream[T]:
        async def gen() -> AsyncIterator[T]:
            async for item in self:
                af = fn(item)
                flag = await af if isinstance(af, Awaitable) else af
                if flag:
                    yield item

        return Stream(gen())

    def starmap(
        self,
        fn: Callable[..., DirectOrAwaitable[R]],
        task_limit: Optional[int] = None,
        ordered: bool = True,
    ) -> Stream[R]:
        return self.map(lambda args: fn(*args), task_limit, ordered)  # type: ignore

    def map(
        self,
        fn: Callable[[T], DirectOrAwaitable[R]],
        task_limit: Optional[int] = None,
        ordered: bool = True,
    ) -> Stream[R]:
        async def gen() -> AsyncIterator[AsyncIterator[R | Awaitable[R]]]:
            async for item in self:
                res = fn(item)
                yield _async_iter([res])

        return Stream(_flatmap(gen(), task_limit, ordered))

    def flatmap(
        self,
        fn: Callable[[T], DirectOrAwaitable[IterOrAsyncIter[R]]],
        task_limit: Optional[int] = None,
        ordered: bool = True,
    ) -> Stream[R]:
        async def gen() -> AsyncIterator[IterOrAsyncIter[R]]:
            async for item in self:
                res = fn(item)
                if isinstance(res, Awaitable):
                    res = await res
                yield res

        return Stream(_flatmap(gen(), task_limit, ordered))

    def concat(self: Stream[Stream[T]], task_limit: Optional[int] = None, ordered: bool = True) -> Stream[T]:
        return self.flatmap(lambda x: x, task_limit, ordered)

    def skip(self, num: int) -> Stream[T]:
        async def gen() -> AsyncIterator[T]:
            count = 0
            async for item in self:
                if count < num:
                    count += 1
                    continue
                yield item

        return Stream(gen())

    def take(self, num: int) -> Stream[T]:
        async def gen() -> AsyncIterator[T]:
            count = 0
            async for item in self:
                if count >= num:
                    break
                yield item
                count += 1

        return Stream(gen())

    def take_last(self, num: int) -> Stream[T]:
        async def gen() -> AsyncIterator[T]:
            queue: deque[T] = deque(maxlen=num)
            async for item in self:
                queue.append(item)
            for item in queue:
                yield item

        return Stream(gen())

    def enumerate(self) -> Stream[Tuple[int, T]]:
        async def gen() -> AsyncIterator[Tuple[int, T]]:
            i = 0
            async for item in self:
                yield i, item
                i += 1

        return Stream(gen())

    def chunks(self, num: int) -> Stream[Stream[T]]:
        def take_n(iterator: AsyncIterator[T], n: int) -> AsyncIterator[T]:
            async def n_gen() -> AsyncIterator[T]:
                count = 0
                try:
                    while count < n:
                        item = await anext(iterator)
                        yield item
                        count += 1
                except StopAsyncIteration:
                    return

            return n_gen()

        async def gen() -> AsyncIterator[Stream[T]]:
            iterator = aiter(self.iterator)
            while True:
                chunk_iterator = take_n(iterator, num)
                try:
                    first_item = await anext(chunk_iterator)
                except StopAsyncIteration:
                    break  # No more items

                async def chunk_with_first() -> AsyncIterator[T]:
                    yield first_item
                    async for item in chunk_iterator:
                        yield item

                yield Stream(chunk_with_first())

        return Stream(gen())

    def flatten(self) -> Stream[T]:
        async def gen() -> AsyncIterator[T]:
            async for item in self:
                if isinstance(item, AsyncIterator) or hasattr(item, "__aiter__"):
                    async for subitem in item:
                        yield subitem
                elif isinstance(item, Iterable):
                    for subitem in item:
                        yield subitem
                else:
                    yield item

        return Stream(gen())

    def cycle(self) -> Stream[T]:
        async def gen() -> AsyncIterator[T]:
            items = []
            async for item in self:
                yield item
                items.append(item)
            while items:
                for item in items:
                    yield item

        return Stream(gen())

    async def collect(self) -> List[T]:
        return [item async for item in self]

    @staticmethod
    def just(x: T | Awaitable[T]) -> Stream[T]:
        async def gen() -> AsyncIterator[T]:
            if isinstance(x, Awaitable):
                yield await x
            else:
                yield x

        return Stream(gen())

    @staticmethod
    def iterate(x: Iterable[T] | AsyncIterable[T] | AsyncIterator[T]) -> Stream[T]:
        if isinstance(x, AsyncIterator):
            return Stream(x)
        elif isinstance(x, AsyncIterable):
            return Stream(aiter(x))
        else:
            return Stream(_async_iter(x))

    @staticmethod
    def empty() -> Stream[T]:
        async def empty() -> AsyncIterator[Never]:
            if False:
                yield  # noqa

        return Stream(empty())

    @staticmethod
    def for_ever(fn: Callable[[], T]) -> Stream[T]:
        async def gen() -> AsyncIterator[T]:
            while True:
                yield fn()

        return Stream(gen())

    @staticmethod
    def call(fn: Callable[P, Awaitable[R]] | Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> Stream[R]:
        async def gen() -> AsyncIterator[R]:
            if asyncio.iscoroutinefunction(fn):
                yield await fn(*args, **kwargs)
            else:
                yield fn(*args, **kwargs)  # type: ignore

        return Stream(gen())

    @staticmethod
    async def as_list(x: Iterable[T] | AsyncIterable[T] | AsyncIterator[T]) -> List[T]:
        if isinstance(x, AsyncIterator):
            return [item async for item in x]
        elif isinstance(x, AsyncIterable):
            return [item async for item in aiter(x)]
        else:
            return [item for item in x]
