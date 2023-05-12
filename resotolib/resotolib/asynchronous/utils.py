import sys
import select
import asyncio
from typing import AsyncIterator


async def async_lines(async_iterator: AsyncIterator[str]) -> AsyncIterator[str]:
    buffer = ""
    async for chunk in async_iterator:
        buffer += chunk
        lines = buffer.split("\n")
        for line in lines[:-1]:
            yield line.rstrip("\r\n")
        buffer = lines[-1]
    if buffer:
        yield buffer


async def stdin_generator() -> AsyncIterator[str]:
    has_data = await asyncio.to_thread(lambda: select.select([sys.stdin], [], [], 0.0)[0])

    if has_data:
        for line in iter(sys.stdin.readline, ""):
            yield line.rstrip("\r\n")
