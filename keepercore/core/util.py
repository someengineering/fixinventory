import asyncio
import logging
from asyncio import Task
from collections import defaultdict
from collections.abc import Iterable
from contextlib import suppress
from datetime import timedelta, datetime, timezone
from typing import Any, Callable, Optional, Awaitable, Dict, TypeVar, List, Tuple, Mapping, MutableSequence

log = logging.getLogger(__name__)

AnyT = TypeVar("AnyT")
AnyR = TypeVar("AnyR")


def identity(o: AnyT) -> AnyT:
    return o


def pop_keys(d: dict[AnyT, AnyR], keys: list[AnyT]) -> dict[AnyT, AnyR]:
    res = d.copy()
    for key in keys:
        res.pop(key, None)  # type: ignore
    return res


UTC_Date_Format = "%Y-%m-%dT%H:%M:%SZ"


def utc() -> datetime:
    return datetime.now(timezone.utc)


def utc_str(dt: datetime = utc()) -> str:
    return dt.strftime(UTC_Date_Format)


def group_by(f: Callable[[AnyT], AnyR], iterable: Iterable[AnyT]) -> Dict[AnyR, List[AnyT]]:
    """
    Group iterable by key provided by given key function.
    :param f: the function to be applied on every element that yields the key.
    :param iterable: the iterable to walk.
    :return: a dictionary with the keys provided by the key function and the values from the iterable.
    """
    v = defaultdict(list)
    for item in iterable:
        key = f(item)
        v[key].append(item)
    return v


def non_empty(el: Iterable[AnyT]) -> bool:
    return bool(el)


def empty(el: Iterable[AnyT]) -> bool:
    return not non_empty(el)


def interleave(elements: List[AnyT]) -> List[Tuple[AnyT, AnyT]]:
    if len(elements) < 2:
        return []
    else:
        nxt = iter(elements)
        next(nxt)
        return list(zip(elements, nxt))


def exist(f: Callable[[AnyT], bool], iterable: Iterable[AnyT]) -> bool:
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


def first(f: Callable[[AnyT], bool], iterable: Iterable[AnyT]) -> Optional[AnyT]:
    for a in iterable:
        if f(a):
            return a
    return None


def if_set(x: Optional[AnyT], func: Callable[[AnyT], Any], if_not: Any = None) -> Any:
    """
    Conditional execute based if the option is defined.
    :param x: the value to check.
    :param func: the function to call if the item is defined.
    :param if_not: the value to return if the item is not defined.
    :return: the result of the function or if_not
    """
    return func(x) if x is not None else if_not


def split_esc(s: str, delim: str) -> List[str]:
    """Split with support for delimiter escaping

    Via: https://stackoverflow.com/a/29107566
    """
    i = 0
    res: List[str] = []
    buf = ""
    while True:
        j, e = s.find(delim, i), 0
        if j < 0:  # end reached
            return res + [buf + s[i:]]  # add remainder
        while j - e and s[j - e - 1] == "\\":
            e += 1  # number of escapes
        d = e // 2  # number of double escapes
        if e != d * 2:  # odd number of escapes
            buf += s[i : j - d - 1] + s[j]  # noqa: E203 add the escaped char.
            i = j + 1  # and skip it
            continue  # add more to buf
        res.append(buf + s[i : j - d])  # noqa: E203
        i, buf = j + len(delim), ""  # start after delim


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
            try:
                result = self.func()
                if isinstance(result, Awaitable):
                    await result
            except Exception as ex:
                log.warning(f"Periodic function {self.name} caught an exception: {ex}")


class AccessNone:
    def __init__(self, not_existent: Any = None):
        self.__not_existent = not_existent

    def __getitem__(self, item: Any) -> Any:
        return self

    def __getattr__(self, name: Any) -> Any:
        return self

    def __str__(self) -> str:
        return str(self.__not_existent)


class AccessJson(dict[Any, Any]):
    """
    Extend dict in order to allow python like property access
    as well as exception safe access for non existent properties.
    """

    def __init__(self, mapping: Mapping[Any, Any], not_existent: Any = None) -> None:
        super().__init__(mapping)
        self.__not_existent = AccessNone(not_existent)

    def __getitem__(self, item: Any) -> Any:
        return AccessJson.wrap(super().__getitem__(item), self.__not_existent) if item in self else self.__not_existent

    def __getattr__(self, name: Any) -> Any:
        return AccessJson.wrap(self[name], self.__not_existent) if name in self else self.__not_existent

    @staticmethod
    def wrap(obj: Any, not_existent: Any) -> Any:
        # dict like data structure -> wrap whole element
        if isinstance(obj, AccessJson):
            return obj
        elif isinstance(obj, Mapping):
            return AccessJson(obj, not_existent)
        # list like data structure -> wrap all elements
        elif isinstance(obj, MutableSequence):
            return [AccessJson.wrap(item, not_existent) for item in obj]
        # simply return the object
        else:
            return obj
