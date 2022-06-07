import logging
from abc import ABC
from typing import Dict, Any, Type, Union, Optional

from resotolib.types import Json
from resotolib.units import parse

log = logging.getLogger("resoto." + __name__)


# Idea stolen from: https://github.com/Onyo/jsonbender
class Bender:

    """
    Base bending class. All selectors and transformations should directly or
    indirectly derive from this. Should not be instantiated.

    Whenever a bender is activated (by the bend() function), the execute()
    method is called with the source as it's single argument.
    All bending logic should be there.
    """

    def __call__(self, source):
        return self.raw_execute(source).value

    def raw_execute(self, source):
        transport = Transport.from_source(source)
        return Transport(self.execute(transport.value), transport.context)

    def execute(self, source):
        return source

    def __eq__(self, other):
        return Eq(self, other)

    def __ne__(self, other):
        return Ne(self, other)

    def __and__(self, other):
        return And(self, other)

    def __or__(self, other):
        return Or(self, other)

    def __invert__(self):
        return Invert(self)

    def __add__(self, other):
        return Add(self, other)

    def __sub__(self, other):
        return Sub(self, other)

    def __mul__(self, other):
        return Mul(self, other)

    def __div__(self, other):
        return Div(self, other)

    def __neg__(self):
        return Neg(self)

    def __truediv__(self, other):
        return Div(self, other)

    def __floordiv__(self, other):
        return Div(self, other)

    def __rshift__(self, other):
        return Compose(self, other)

    def __lshift__(self, other):
        return Compose(other, self)

    def __getitem__(self, index):
        if isinstance(index, int):
            return self >> GetItem(index)
        elif isinstance(index, str):
            return self >> S(index)
        else:
            raise AttributeError(f"Invalid index type: {index}")


class S(Bender):
    def __init__(self, *path, **kwargs):
        if not path:
            raise ValueError("No path given")
        self._path = path
        self._default = kwargs.get("default")

    def execute(self, source):
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

    def __init__(self, value, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._val = value

    def execute(self, source):
        return self._val


class F(Bender):
    """
    Lifts a python callable into a Bender, so it can be composed.
    The extra positional and named parameters are passed to the function at
    bending time after the given value.

    `func` is a callable

    Example:
    ```
    f = F(sorted, key=lambda d: d['id'])
    K([{'id': 3}, {'id': 1}]) >> f  #  -> [{'id': 1}, {'id': 3}]
    ```
    """

    def __init__(self, func, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._func = func
        self._args = args
        self._kwargs = kwargs

    def execute(self, value):
        return self._func(value, *self._args, **self._kwargs)


class GetItem(Bender):
    def __init__(self, index):
        self._index = index

    def execute(self, source):
        return source[self._index] if isinstance(source, list) and len(source) > abs(self._index) else None


class Compose(Bender):
    def __init__(self, first, second):
        self._first = first
        self._second = second

    def raw_execute(self, source):
        first = self._first.raw_execute(source)
        return self._second.raw_execute(first) if first is not None else None


class UnaryOperator(Bender):
    """
    Base class for unary bending operators. Should not be directly
    instantiated.

    Whenever a unary op is activated, the op() method is called with the
    *value* (that is, the bender is implicitly activated).

    Subclasses must implement the op() method, which takes one value and
    should return the desired result.
    """

    def __init__(self, bender):
        self.bender = bender

    def op(self, v):
        raise NotImplementedError()

    def raw_execute(self, source):
        source = Transport.from_source(source)
        val = self.op(self.bender(source))
        return Transport(val, source.context)


class Neg(UnaryOperator):
    def op(self, v):
        return -v


class Invert(UnaryOperator):
    def op(self, v):
        return not v


class BinaryOperator(Bender):
    """
    Base class for binary bending operators. Should not be directly
    instantiated.

    Whenever a bin op is activated, the op() method is called with both
    *values* (that is, the benders are implicitly activated).

    Subclasses must implement the op() method, which takes two values and
    should return the desired result.
    """

    def __init__(self, bender1, bender2):
        self._bender1 = bender1
        self._bender2 = bender2

    def op(self, v1, v2):
        raise NotImplementedError()

    def raw_execute(self, source):
        source = Transport.from_source(source)
        val = self.op(self._bender1(source), self._bender2(source))
        return Transport(val, source.context)


class Add(BinaryOperator):
    def op(self, v1, v2):
        return v1 + v2


class Sub(BinaryOperator):
    def op(self, v1, v2):
        return v1 - v2


class Mul(BinaryOperator):
    def op(self, v1, v2):
        return v1 * v2


class Div(BinaryOperator):
    def op(self, v1, v2):
        return float(v1) / float(v2)


class Eq(BinaryOperator):
    def op(self, v1, v2):
        return v1 == v2


class Ne(BinaryOperator):
    def op(self, v1, v2):
        return v1 != v2


class And(BinaryOperator):
    def op(self, v1, v2):
        return v1 and v2


class Or(BinaryOperator):
    def op(self, v1, v2):
        return v1 or v2


class Context(Bender):
    def raw_execute(self, source):
        transport = Transport.from_source(source)
        return Transport(transport.context, transport.context)


class BendingException(Exception):
    pass


class Transport:
    def __init__(self, value, context):
        self.value = value
        self.context = context

    @classmethod
    def from_source(cls, source):
        if isinstance(source, cls):
            return source
        else:
            return cls(source, {})


def bend(mapping: Dict[str, Bender], source: Any, context=None) -> Any:
    """
    The main bending function.

    mapping: the map of benders
    source: a dict to be bent

    returns a new dict according to the provided map.
    """
    context = {} if context is None else context
    transport = Transport(source, context)
    return _bend(mapping, transport)


def _bend(mapping, transport):
    if isinstance(mapping, list):
        return [_bend(v, transport) for v in mapping]

    elif isinstance(mapping, dict):
        res = {}
        for k, v in mapping.items():
            try:
                value = _bend(v, transport)
                res[k] = value
            except Exception as e:
                log.error(e, exc_info=True)
                m = "Error for key {}: {}".format(k, str(e))
                raise BendingException(m)
        return res

    elif isinstance(mapping, Bender):
        return mapping(transport)

    else:
        return mapping


class Bend(Bender):
    def __init__(self, mappings: Dict[str, Bender], **kwargs):
        super().__init__(**kwargs)
        self._mappings = mappings

    def execute(self, value: Optional[Json]) -> Any:
        return bend(self._mappings, value) if value else None


class ListOp(Bender, ABC):
    def __init__(self, *args, **kwargs):
        self._func = None

    def op(self, func, vals):
        raise NotImplementedError()

    def execute(self, source):
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

    def op(self, func, vals):
        return list(map(func, vals))

    @classmethod
    def bend(cls, mapping, context=None):
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

    def __init__(self, mapping, context=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._mapping = mapping
        self._context = context

    def raw_execute(self, source):
        transport = Transport.from_source(source)
        context = self._context or transport.context
        # ListOp.execute assumes the func is saved on self._func
        self._func = lambda v: bend(self._mapping, v, context)
        return Transport(self.execute(transport.value), transport.context)


class MapValue(Bender):
    def __init__(self, lookup: Dict[str, Any], default: Any = None, **kwargs):
        super().__init__(**kwargs)
        self._lookup = lookup
        self._default = default

    def execute(self, value: str) -> Any:
        return self._lookup.get(value, self._default)


class StringToUnitNumber(Bender):
    def __init__(self, unit: str, expected: Type[Union[int, float]] = float, **kwargs):
        super().__init__(**kwargs)
        self._unit = unit
        self._expected = expected

    def execute(self, value: str) -> Union[int, float]:
        return self._expected(parse(value).to(self._unit))


class CPUCoresToNumber(Bender):
    def execute(self, source: str) -> float:
        return float(source[:-1]) / 1000 if source.endswith("m") else float(source)
