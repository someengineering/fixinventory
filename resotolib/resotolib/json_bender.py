from __future__ import annotations
import logging
from abc import ABC
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Type, Union, Optional, Callable

from resotolib.types import Json
from resotolib.units import parse

log = logging.getLogger("resoto." + __name__)


# General idea and basic implementation is taken from: https://github.com/Onyo/jsonbender
class Bender(ABC):
    """
    Base bending class.
    """

    def __call__(self, source: Any) -> Any:
        return self.raw_execute(source).value

    def raw_execute(self, source: Any) -> Any:
        transport = Transport.from_source(source)
        return Transport(self.execute(transport.value), transport.context)

    def execute(self, source: Any) -> Any:
        return source

    def or_else(self, other: Bender) -> Bender:
        return OrElse(self, other)

    def __eq__(self, other: Any) -> Bender:  # type: ignore
        return Eq(self, other)

    def __ne__(self, other: Any) -> Bender:  # type: ignore
        return Ne(self, other)

    def __and__(self, other: Any) -> Bender:
        return And(self, other)

    def __or__(self, other: Any) -> Bender:
        return Or(self, other)

    def __invert__(self: Any) -> Bender:
        return Invert(self)

    def __add__(self, other: Any) -> Bender:
        return Add(self, other)

    def __sub__(self, other: Any) -> Bender:
        return Sub(self, other)

    def __mul__(self, other: Any) -> Bender:
        return Mul(self, other)

    def __div__(self, other: Any) -> Bender:
        return Div(self, other)

    def __neg__(self) -> Bender:
        return Neg(self)

    def __truediv__(self, other: Any) -> Bender:
        return Div(self, other)

    def __floordiv__(self, other: Any) -> Bender:
        return Div(self, other)

    def __rshift__(self, other: Any) -> Bender:
        return Compose(self, other)

    def __lshift__(self, other: Any) -> Bender:
        return Compose(other, self)

    def __getitem__(self, index: Any) -> Bender:
        return self >> GetItem(index)


class BendingError(Exception):
    pass


Mapping = Union[Bender, Dict[str, Bender]]


class S(Bender):
    """
    Retrieve a value from a JSON object under given path.
    """

    def __init__(self, *path: str, default: Optional[Any] = None):
        if not path:
            raise ValueError("No path given")
        self._path = path
        self._default = default

    def execute(self, source: Any) -> Any:
        try:
            for key in self._path:
                source = source[key]
            return source
        except (KeyError, TypeError):
            return self._default


class K(Bender):
    """
    Selects a constant value.
    """

    def __init__(self, value: Any, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._val = value

    def execute(self, source: Any) -> Any:
        return self._val


class F(Bender):
    """
    Lifts a python callable into a Bender, so it can be composed.
    The extra positional and named parameters are passed to the function at
    bending time after the given value.

    Example:
    ```
    f = F(sorted, key=lambda d: d['id'])
    K([{'id': 3}, {'id': 1}]) >> f  #  -> [{'id': 1}, {'id': 3}]
    ```
    """

    def __init__(self, func: Callable[[Any], Any], *args: Any, **kwargs: Any):  # type: ignore
        super().__init__(*args, **kwargs)
        self._func = func
        self._args = args
        self._kwargs = kwargs

    def execute(self, value: Any) -> Any:
        # noinspection PyArgumentList
        return self._func(value, *self._args, **self._kwargs)


class OrElse(Bender):
    def __init__(self, source_bender: Bender, else_bender: Bender):
        super().__init__()
        self.source_bender = source_bender
        self.else_bender = else_bender

    def raw_execute(self, source: Any) -> Any:
        first = self.source_bender.raw_execute(source)
        if first.value is not None:
            return first
        else:
            return self.else_bender.raw_execute(source)


class GetItem(Bender):
    """
    Can be applied to a list or dict bender via `[index]`.
    List: GetItem(0) -> first element
    Dictionary: GetItem('key') -> value of key
    """

    def __init__(self, index: Union[str, int]):
        self._index = index

    def execute(self, source: Any) -> Any:
        if isinstance(source, list) and isinstance(self._index, int):
            return source[self._index] if len(source) > abs(self._index) else None
        elif isinstance(source, dict) and isinstance(self._index, str):
            return source.get(self._index)
        else:
            return None


class Compose(Bender):
    """
    Compose two benders.
    Use `>>` instead of calling `Compose` directly.
    """

    def __init__(self, first: Bender, second: Bender):
        self._first = first
        self._second = second

    def raw_execute(self, source: Any) -> Any:
        first = self._first.raw_execute(source)
        return self._second.raw_execute(first) if first is not None else None


class UnaryOperator(Bender):
    """
    Base class for unary bending operators.

    Whenever a unary op is activated, the op() method is called with the
    *value* (that is, the bender is implicitly activated).

    Subclasses must implement the op() method, which takes one value and
    should return the desired result.
    """

    def __init__(self, bender: Bender):
        self.bender = bender

    def op(self, v: Any) -> Any:
        raise NotImplementedError()

    def raw_execute(self, source: Any) -> Any:
        source = Transport.from_source(source)
        val = self.op(self.bender(source))
        return Transport(val, source.context)


class Neg(UnaryOperator):
    def op(self, v: Any) -> Any:
        return -v


class Invert(UnaryOperator):
    def op(self, v: Any) -> Any:
        return not v


class BinaryOperator(Bender):
    """
    Base class for binary bending operators.

    Whenever a bin op is activated, the op() method is called with both
    *values* (that is, the benders are implicitly activated).

    Subclasses must implement the op() method, which takes two values and
    should return the desired result.
    """

    def __init__(self, bender1: Bender, bender2: Bender):
        self._bender1 = bender1
        self._bender2 = bender2

    def op(self, v1: Any, v2: Any) -> Any:
        raise NotImplementedError()

    def raw_execute(self, source: Any) -> Any:
        source = Transport.from_source(source)
        val = self.op(self._bender1(source), self._bender2(source))
        return Transport(val, source.context)


class Add(BinaryOperator):
    def op(self, v1: Any, v2: Any) -> Any:
        return v1 + v2


class Sub(BinaryOperator):
    def op(self, v1: Any, v2: Any) -> Any:
        return v1 - v2


class Mul(BinaryOperator):
    def op(self, v1: Any, v2: Any) -> Any:
        return v1 * v2


class Div(BinaryOperator):
    def op(self, v1: Any, v2: Any) -> Any:
        return float(v1) / float(v2)


class Eq(BinaryOperator):
    def op(self, v1: Any, v2: Any) -> Any:
        return v1 == v2


class Ne(BinaryOperator):
    def op(self, v1: Any, v2: Any) -> Any:
        return v1 != v2


class And(BinaryOperator):
    def op(self, v1: Any, v2: Any) -> Any:
        return v1 and v2


class Or(BinaryOperator):
    def op(self, v1: Any, v2: Any) -> Any:
        return v1 or v2


class Context(Bender):
    def raw_execute(self, source: Any) -> Any:
        transport = Transport.from_source(source)
        return Transport(transport.context, transport.context)


class Transport:
    def __init__(self, value: Any, context: Dict[str, Any]):
        self.value = value
        self.context = context

    @classmethod
    def from_source(cls, source: Any) -> Transport:
        if isinstance(source, cls):
            return source
        else:
            return cls(source, {})


class Bend(Bender):
    def __init__(self, mappings: Mapping, **kwargs: Any):
        super().__init__(**kwargs)
        self._mappings = mappings

    def execute(self, value: Optional[Json]) -> Any:
        return bend(self._mappings, value) if value else None


class Sort(Bender):
    """
    Sort a list based on given extractor bender.
    """

    def __init__(self, extractor: Bender, **kwargs: Any):
        super().__init__(**kwargs)
        self._extractor = extractor

    def execute(self, source: Any) -> Any:
        if isinstance(source, list):
            return sorted(source, key=lambda x: bend(self._extractor, x))
        else:
            return source


class AsDate(Bender):
    """
    Parse a given input string as date.
    The format of the date needs to be defined.
    """

    def __init__(self, date_format: str = "%Y-%m-%dT%H:%M:%SZ", **kwargs: Any):
        super().__init__(**kwargs)
        self._format = date_format

    def execute(self, source: Any) -> Any:
        return datetime.strptime(source, self._format) if isinstance(source, str) else source


class ListOp(Bender, ABC):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._func: Callable[[Any], Any] = lambda x: x

    def op(self, func: Callable[[Any], Any], vals: Any) -> Any:
        raise NotImplementedError()

    def execute(self, source: Any) -> Any:
        return self.op(self._func, source)


class Forall(ListOp):
    """
    Similar to Python's map().
    Builds a new list by applying the given function to each element of the
    iterable.

    Example:
    ```
    Forall(lambda i: i * 2)(range(5))  # -> [0, 2, 4, 6, 8]
    ```
    """

    def op(self, func: Callable[[Any], Any], vals: Any) -> Any:
        return list(map(func, vals))

    @classmethod
    def bend(cls, mapping: Mapping, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Return a ForallBend instance that bends each element of the list with the
        given mapping.

        mapping: a JSONBender mapping as passed to the `bend()` function.
        context: optional. the context that will be passed to `bend()`.
                 Note that if context is not passed, it defaults at bend-time
                 to the one passed to the outer mapping.

        Example:
        ```
        source = [{'a': 23}, {'a': 27}]
        bender = Forall.bend({'b': S('a')})
        bender(source)  # -> [{'b': 23}, {'b': 27}]
        ```

        """
        return ForallBend(mapping, context)


class ForallBend(Forall):
    """
    Bends each element of the list with given mapping and context.

    mapping: a JSONBender mapping as passed to the `bend()` function.
    context: optional. the context that will be passed to `bend()`.
             Note that if context is not passed, it defaults at bend-time
             to the one passed to the outer mapping.
    """

    def __init__(self, mapping: Mapping, context: Optional[Dict[str, Any]] = None, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._mapping = mapping
        self._context = context

    def raw_execute(self, source: Any) -> Any:
        transport = Transport.from_source(source)
        context = self._context or transport.context
        # ListOp.execute assumes the func is saved on self._func
        self._func = lambda v: bend(self._mapping, v, context)
        return Transport(self.execute(transport.value), transport.context)


class MapDict(Bender):
    """
    If you have a dict and want to map either key or value.
    """

    def __init__(self, key_bender: Optional[Bender] = None, value_bender: Optional[Bender] = None, **kwargs: Any):
        super().__init__(**kwargs)
        self._key_bender = key_bender
        self._value_bender = value_bender

    def execute(self, value: Dict[Any, Any]) -> Dict[Any, Any]:
        def do_bend(v: Any, bender: Optional[Bender]) -> Any:
            return bender.raw_execute(v).value if bender else v

        return {do_bend(k, self._key_bender): do_bend(v, self._value_bender) for k, v in value.items()}


class StripNones(Bender):
    def execute(self, source: Any) -> Any:
        if isinstance(source, list):
            return [x for x in source if x is not None]
        else:
            return source


class MapValue(Bender):
    def __init__(self, lookup: Dict[str, Any], default: Any = None, **kwargs: Any):
        super().__init__(**kwargs)
        self._lookup = lookup
        self._default = default

    def execute(self, value: str) -> Any:
        return self._lookup.get(value, self._default)


class MapEnum(MapValue):
    def execute(self, value: str) -> Any:
        enum = super().execute(value)
        if isinstance(enum, Enum):
            return enum.value
        else:
            raise AttributeError(f"Mapping did not return an enumeration: in:{value} out:{enum}")


class StringToUnitNumber(Bender):
    def __init__(self, unit: str, expected: Type[Union[int, float]] = float, **kwargs: Any):
        super().__init__(**kwargs)
        self._unit = unit
        self._expected = expected

    def execute(self, value: str) -> Union[int, float]:
        return self._expected(parse(value).to(self._unit).magnitude)


class CPUCoresToNumber(Bender):
    def execute(self, source: str) -> float:
        return float(source[:-1]) / 1000 if isinstance(source, str) and source.endswith("m") else float(source)


def bend(mapping: Mapping, source: Any, context: Optional[Dict[str, Any]] = None) -> Any:
    """
    The main bending function.

    mapping: the map of benders
    source: a dict to be bent

    returns a new dict according to the provided map.
    """

    def bend_with_context(inner: Mapping, transport: Transport) -> Any:
        if isinstance(inner, list):
            return [bend_with_context(v, transport) for v in inner]

        elif isinstance(inner, dict):
            res = {}
            for k, v in inner.items():
                try:
                    value = bend_with_context(v, transport)
                    res[k] = value
                except Exception as e:
                    log.error(e, exc_info=True)
                    m = "Error for key {}: {}".format(k, str(e))
                    raise BendingError(m)
            return res

        elif isinstance(inner, Bender):
            return inner(transport)

        else:
            return inner

    context = {} if context is None else context
    return bend_with_context(mapping, Transport(source, context))
