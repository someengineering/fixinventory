from typing import AsyncGenerator

async def async_lines(async_generator: AsyncGenerator[str, None]) -> AsyncGenerator[str, None]:
    buffer = ""
    async for chunk in async_generator:
        buffer += chunk
        lines = buffer.split("\n")
        for line in lines[:-1]:
            yield line
        buffer = lines[-1]
    if buffer:
        yield buffer
