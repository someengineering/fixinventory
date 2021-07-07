import asyncio
import logging
from asyncio import Task
from collections.abc import Iterable
from contextlib import suppress
from datetime import timedelta
from typing import Any, Callable, Optional, Awaitable

log = logging.getLogger(__name__)


def exist(f: Callable[[Any], bool], iterable: Iterable[Any]) -> bool:
    """
    Items are passed to the callable as long as it returns False.
    Return True once the callable finds one True, otherwise return False.
    :param f: the callable that needs to accept items from Iterable.
    :param iterable: walk over this iterable
    :return: True if the item exist, otherwise False.
    """
    for a in iterable:
        if f(a):
            return True
    return False


def first(f: Callable[[Any], bool], iterable: Iterable[Any]) -> Optional[Any]:
    for a in iterable:
        if f(a):
            return a
    return None


def if_set(x: Optional[Any], func: Callable[[Any], Any], if_not: Any = None) -> Any:
    """
    Conditional execute based if the option is defined.
    :param x: the value to check.
    :param func: the function to call if the item is defined.
    :param if_not: the value to return if the item is not defined.
    :return: the result of the function or if_not
    """
    return func(x) if x is not None else if_not


class Periodic:
    """
    Periodic execution of a function based on a defined frequency that can be started and stopped.
    """

    def __init__(self, name: str, func: Callable[[], Any], frequency: timedelta):
        self.name = name
        self.func = func
        self.frequency = frequency
        self._task: Optional[Task[Any]] = None

    async def start(self) -> None:
        if self._task is None:
            # Start task to call func periodically:
            self._task = asyncio.ensure_future(self._run())
            log.info(f"Periodic task {self.name} has been started.")

    async def stop(self) -> None:
        # Stop task and await it stopped:
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self.frequency.seconds)
            log.debug(f"Execute periodic task {self.name}.")
            result = self.func()
            if isinstance(result, Awaitable):
                await result
