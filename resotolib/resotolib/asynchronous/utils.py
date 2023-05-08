from typing import AsyncIterator


async def async_lines(async_iterator: AsyncIterator[str]) -> AsyncIterator[str]:
    buffer = ""
    async for chunk in async_iterator:
        buffer += chunk
        lines = buffer.split("\n")
        for line in lines[:-1]:
            yield line
        buffer = lines[-1]
    if buffer:
        yield buffer
