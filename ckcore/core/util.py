import asyncio
import logging
import random
import string
import sys
import uuid
from asyncio import Task, Future
from collections import defaultdict
from collections.abc import Iterable
from contextlib import suppress
from datetime import timedelta, datetime, timezone
from typing import (
    Any,
    Callable,
    Optional,
    Awaitable,
    TypeVar,
    Mapping,
    MutableSequence,
    AsyncGenerator,
    Dict,
    List,
    Tuple,
    cast,
)

from dateutil.parser import isoparse
from frozendict import frozendict

from core.types import JsonElement, Json

log = logging.getLogger(__name__)

AnyT = TypeVar("AnyT")
AnyR = TypeVar("AnyR")


def identity(o: Any) -> Any:
    return o


def freeze(d: Dict[AnyT, AnyR]) -> Dict[AnyT, AnyR]:
    result = {}
    for k, v in d.items():
        sk = freeze(k) if isinstance(k, dict) else k
        sv = freeze(v) if isinstance(v, dict) else v
        result[sk] = sv
    return cast(Dict[AnyT, AnyR], frozendict(result))


def pop_keys(d: Dict[AnyT, AnyR], keys: List[AnyT]) -> Dict[AnyT, AnyR]:
    res = dict(d)
    for key in keys:
        res.pop(key, None)  # type: ignore
    return res


UTC_Date_Format = "%Y-%m-%dT%H:%M:%SZ"


def rnd_str(str_len: int = 10) -> str:
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(str_len))


def utc() -> datetime:
    return datetime.now(timezone.utc)


def utc_str(dt: datetime = utc()) -> str:
    return dt.strftime(UTC_Date_Format)


def from_utc(date_string: str) -> datetime:
    return isoparse(date_string)


def uuid_str(from_object: Optional[Any] = None) -> str:
    if from_object:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, from_object))
    else:
        return str(uuid.uuid1())


def group_by(f: Callable[[AnyT], AnyR], iterable: Iterable) -> Dict[AnyR, List[AnyT]]:  # type: ignore # pypy
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


def non_empty(el: Iterable) -> bool:  # type: ignore # pypy
    return bool(el)


def empty(el: Iterable) -> bool:  # type: ignore # pypy
    return not non_empty(el)


def combine_optional(
    left: Optional[AnyT], right: Optional[AnyT], combine: Callable[[AnyT, AnyT], AnyT]
) -> Optional[AnyT]:
    if left and right:
        return combine(left, right)
    elif left:
        return left
    else:
        return right


def interleave(elements: List[AnyT]) -> List[Tuple[AnyT, AnyT]]:
    if len(elements) < 2:
        return []
    else:
        nxt = iter(elements)
        next(nxt)
        return list(zip(elements, nxt))


def exist(f: Callable[[Any], bool], iterable: Iterable) -> bool:  # type: ignore # pypy
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


def first(f: Callable[[Any], bool], iterable: Iterable) -> Optional[Any]:  # type: ignore # pypy
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


def value_in_path_get(element: JsonElement, path: List[str], if_none: AnyT) -> AnyT:
    result = value_in_path(element, path)
    return result if result and isinstance(result, type(if_none)) else if_none


def value_in_path(element: JsonElement, path: List[str]) -> Optional[Any]:
    # implementation without allocations (path is not changed)
    def at_idx(current: JsonElement, idx: int) -> Optional[Any]:
        if len(path) == idx:
            return current
        elif current is None or not isinstance(current, dict) or path[idx] not in current:
            return None
        else:
            return at_idx(current[path[idx]], idx + 1)

    return at_idx(element, 0)


def set_value_in_path(element: JsonElement, path: List[str], json: Optional[Json] = None) -> Json:
    def at_idx(current: Json, idx: int) -> None:
        if len(path) - 1 == idx:
            current[path[-1]] = element
        else:
            value = current.get(path[idx])
            if not isinstance(value, dict):
                value = {}
                current[path[idx]] = value
            at_idx(value, idx + 1)

    js = json if json is not None else {}
    at_idx(js, 0)
    return js


async def force_gen(gen: AsyncGenerator[AnyT, None]) -> AsyncGenerator[AnyT, None]:
    async def with_first(elem: AnyT) -> AsyncGenerator[AnyT, None]:
        yield elem
        async for a in gen:
            yield a

    try:
        return with_first(await gen.__anext__())
    except StopAsyncIteration:
        return gen


def set_future_result(future: Future, result: Any) -> None:  # type: ignore # pypy
    if not future.done():
        if isinstance(result, Exception):
            future.set_exception(result)
        else:
            future.set_result(result)


def shutdown_process(exit_code: int) -> None:
    # Exceptions happening in the async loop during shutdown.
    def exception_handler(_: Any, context: Any) -> None:
        log.debug(f"Error from async loop during shutdown: {context}")

    log.info("Shutdown initiated for current process.")
    with suppress(Exception):
        asyncio.get_running_loop().set_exception_handler(exception_handler)
    sys.exit(exit_code)


class Periodic:
    """
    Periodic execution of a function based on a defined frequency that can be started and stopped.
    """

    def __init__(self, name: str, func: Callable[[], Any], frequency: timedelta):
        self.name = name
        self.func = func
        self.frequency = frequency
        self._task: Optional[Task] = None  # type: ignore # pypy

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
                log.error(f"Periodic function {self.name} caught an exception: {ex}", exc_info=ex)


class AccessNone:
    def __init__(self, not_existent: Any = None):
        self.__not_existent = not_existent

    def __getitem__(self, item: Any) -> Any:
        return self

    def __getattr__(self, name: Any) -> Any:
        return self

    def __str__(self) -> str:
        return str(self.__not_existent)

    def __eq__(self, other: Any) -> bool:
        return other is None or isinstance(other, AccessNone)


class AccessJson(Dict[Any, Any]):
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
