import pytest
import sys
import tempfile
from contextlib import contextmanager
from fixlib.asynchronous.utils import async_lines, stdin_generator


class SimpleAsyncIterator:
    def __init__(self, data):
        self.data = data
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index < len(self.data):
            value = self.data[self.index]
            self.index += 1
            return value
        else:
            raise StopAsyncIteration


@pytest.mark.parametrize(
    "input_data, expected_output",
    [
        ("line1\nline2\nline3", ["line1", "line2", "line3"]),
        ("line1\r\nline2\r\nline3", ["line1", "line2", "line3"]),
        ("line1\nline2\nline3\n", ["line1", "line2", "line3"]),
        ("line1\r\nline2\r\nline3\r\n", ["line1", "line2", "line3"]),
        ("", []),
    ],
)
@pytest.mark.asyncio
async def test_async_lines(input_data, expected_output):
    iterator = SimpleAsyncIterator(input_data)
    output = [line async for line in async_lines(iterator)]
    assert output == expected_output


@contextmanager
def replace_stdin(input_data: str):
    with tempfile.TemporaryFile(mode="w+t") as temp_file:
        temp_file.write(input_data)
        temp_file.seek(0)
        original_stdin = sys.stdin
        sys.stdin = temp_file
        try:
            yield
        finally:
            sys.stdin = original_stdin


@pytest.mark.parametrize(
    "input_data, expected_output",
    [
        ("line1\nline2\nline3", ["line1", "line2", "line3"]),
        ("line1\r\nline2\r\nline3", ["line1", "line2", "line3"]),
        ("", []),
    ],
)
@pytest.mark.asyncio
async def test_async_stdin_generator(input_data, expected_output):
    with replace_stdin(input_data):
        output = [line async for line in stdin_generator()]
    assert output == expected_output
