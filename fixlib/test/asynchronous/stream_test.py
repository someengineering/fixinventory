import asyncio
from typing import AsyncIterator, Iterator

from fixlib.asynchronous.stream import Stream


async def example_gen() -> AsyncIterator[int]:
    for i in range(5, 0, -1):
        yield i


def example_stream() -> Stream:
    return Stream(example_gen())


async def test_just() -> None:
    assert await Stream.just(1).collect() == [1]


async def test_iterate() -> None:
    assert await Stream.iterate([1, 2, 3]).collect() == [1, 2, 3]
    assert await Stream.iterate(example_gen()).collect() == [5, 4, 3, 2, 1]
    assert await Stream.iterate(example_stream()).collect() == [5, 4, 3, 2, 1]


async def test_filter() -> None:
    assert await example_stream().filter(lambda x: x % 2).collect() == [5, 3, 1]
    assert await example_stream().filter(lambda x: x is None).collect() == []
    assert await example_stream().filter(lambda x: True).collect() == [5, 4, 3, 2, 1]


async def test_map() -> None:
    invoked = 0
    max_invoked = 0

    def sync_fn(x: int) -> int:
        return x * 2

    async def async_fn(x: int) -> int:
        await asyncio.sleep(x / 100)
        return x * 2

    async def count_invoked_fn(x: int) -> int:
        nonlocal invoked, max_invoked
        invoked += 1
        await asyncio.sleep(0.003)
        max_invoked = max(max_invoked, invoked)
        await asyncio.sleep(0.003)
        invoked -= 1
        return x

    assert await example_stream().map(lambda x: x * 2).collect() == [10, 8, 6, 4, 2]
    assert await example_stream().map(sync_fn).collect() == [10, 8, 6, 4, 2]
    assert await example_stream().map(async_fn).collect() == [10, 8, 6, 4, 2]
    # The function will wait depending on the streamed value.
    # Since we start from biggest to smallest, the result should be reversed
    # High chance of being flaky, since it relies on timing.
    assert await example_stream().map(async_fn, task_limit=100, ordered=False).collect() == [2, 4, 6, 8, 10]
    # All items are processed in parallel, while the order is preserved.
    assert await example_stream().map(async_fn, task_limit=100, ordered=True).collect() == [10, 8, 6, 4, 2]
    # Make sure all items are processed in parallel.
    max_invoked = invoked = 0
    assert await example_stream().map(count_invoked_fn, task_limit=100, ordered=False).collect()
    assert max_invoked == 5
    # Limit the number of parallel tasks to 2.
    max_invoked = invoked = 0
    assert await example_stream().map(count_invoked_fn, task_limit=2, ordered=False).collect()
    assert max_invoked == 2
    # Make sure all items are processed in parallel.
    max_invoked = invoked = 0
    assert await example_stream().map(count_invoked_fn, task_limit=100, ordered=True).collect()
    assert max_invoked == 5
    # Limit the number of parallel tasks to 2.
    max_invoked = invoked = 0
    assert await example_stream().map(count_invoked_fn, task_limit=2, ordered=True).collect()
    assert max_invoked == 2


async def test_flatmap() -> None:
    def sync_gen(x: int) -> Iterator[int]:
        for i in range(2):
            yield x * 2

    async def async_gen(x: int) -> AsyncIterator[int]:
        await asyncio.sleep(0)
        for i in range(2):
            yield x * 2

    assert await example_stream().flatmap(sync_gen).collect() == [10, 10, 8, 8, 6, 6, 4, 4, 2, 2]
    assert await example_stream().flatmap(async_gen).collect() == [10, 10, 8, 8, 6, 6, 4, 4, 2, 2]
    assert await Stream.empty().flatmap(sync_gen).collect() == []
    assert await Stream.empty().flatmap(async_gen).collect() == []
    assert await Stream.iterate([]).flatmap(sync_gen).collect() == []
    assert await Stream.iterate([]).flatmap(async_gen).collect() == []


async def test_take() -> None:
    assert await example_stream().take(3).collect() == [5, 4, 3]


async def test_take_last() -> None:
    assert await example_stream().take_last(3).collect() == [3, 2, 1]


async def test_skip() -> None:
    assert await example_stream().skip(2).collect() == [3, 2, 1]
    assert await example_stream().skip(10).collect() == []


async def test_call() -> None:
    def fn(foo: int, bla: str) -> int:
        return 123

    def with_int(foo: int) -> int:
        return foo + 1

    assert await Stream.call(fn, 1, "bla").map(with_int).collect() == [124]


async def test_chunks() -> None:
    assert len([chunk async for chunk in example_stream().chunks(2)]) == 3
    assert [chunk async for chunk in example_stream().chunks(2)] == await example_stream().chunks(2).collect()
    assert await example_stream().chunks(2).map(Stream.as_list).collect() == [[5, 4], [3, 2], [1]]
