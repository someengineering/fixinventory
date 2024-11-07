import asyncio
from typing import AsyncIterator

from fixlib.asynchronous.stream import Stream


async def example_gen() -> AsyncIterator[int]:
    for i in range(5):
        yield i


def example_stream() -> Stream:
    return Stream(example_gen())


async def test_just() -> None:
    assert await Stream.just(1).collect() == [1]


async def test_iterate() -> None:
    assert await Stream.iterate([1, 2, 3]).collect() == [1, 2, 3]
    assert await Stream.iterate(example_gen()).collect() == [0, 1, 2, 3, 4]
    assert await Stream.iterate(example_stream()).collect() == [0, 1, 2, 3, 4]


async def test_filter() -> None:
    assert await example_stream().filter(lambda x: x % 2).collect() == [1, 3]


async def test_map() -> None:
    async def fn(x: int) -> int:
        await asyncio.sleep(0)
        return x * 2

    assert await example_stream().map(lambda x: x * 2).collect() == [0, 2, 4, 6, 8]
    assert await example_stream().map(fn).collect() == [0, 2, 4, 6, 8]


async def test_flatmap() -> None:
    async def gen(x: int):
        await asyncio.sleep(0)
        for i in range(2):
            yield x * 2

    assert await example_stream().flatmap(gen).collect() == [0, 0, 2, 2, 4, 4, 6, 6, 8, 8]


async def test_take() -> None:
    assert await example_stream().take(3).collect() == [0, 1, 2]


async def test_take_last() -> None:
    assert await example_stream().take_last(3).collect() == [2, 3, 4]


async def test_skip() -> None:
    assert await example_stream().skip(2).collect() == [2, 3, 4]
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
    assert await example_stream().chunks(2).map(Stream.as_list).collect() == [[0, 1], [2, 3], [4]]
