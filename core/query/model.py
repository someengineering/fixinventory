from __future__ import annotations
import abc
import sys
from functools import reduce
from typing import List

from jsons import set_deserializer


class P:
    def __init__(self, name: str, **kwargs):
        self.name = name
        self.args = kwargs

    @staticmethod
    def single(name: str):
        return P(name)

    @staticmethod
    def array(name: str):
        return PArray(name)

    @staticmethod
    def with_id(uid: str):
        return IdTerm(uid)

    @staticmethod
    def of_kind(name: str):
        return IsInstanceTerm(name)

    @staticmethod
    def function(fn: str):
        return PFunction(fn)

    def __gt__(self, other: object):
        return self.gt(other)

    def __ge__(self, other: object):
        return self.ge(other)

    def __lt__(self, other: object):
        return self.lt(other)

    def __le__(self, other: object):
        return self.le(other)

    def __eq__(self, other: object):
        return self.eq(other)

    def __ne__(self, other: object):
        return self.ne(other)

    def gt(self, other: object):
        return Predicate(self.name, ">", other, self.args)

    def ge(self, other: object):
        return Predicate(self.name, ">=", other, self.args)

    def lt(self, other: object):
        return Predicate(self.name, "<", other, self.args)

    def le(self, other: object):
        return Predicate(self.name, "<=", other, self.args)

    def eq(self, other: object):
        return Predicate(self.name, "==", other, self.args)

    def ne(self, other: object):
        return Predicate(self.name, "!=", other, self.args)

    def matches(self, regex: str):
        return Predicate(self.name, "=~", regex, self.args)

    def not_matches(self, regex: str):
        return Predicate(self.name, "!~", regex, self.args)

    def is_in(self, other: List[object]):
        return Predicate(self.name, "in", other, self.args)

    def is_not_in(self, other: List[object]):
        return Predicate(self.name, "not in", other, self.args)


class PFunction:
    def __init__(self, fn: str):
        self.fn = fn

    def on(self, name: str, *args):
        return FunctionTerm(self.fn, name, list(args))


class PArray:
    def __init__(self, name: str):
        self.name = name

    def for_any(self):
        return P(self.name, array=True, filter='any')

    def for_none(self):
        return P(self.name, array=True, filter='none')

    def for_all(self):
        return P(self.name, array=True, filter='all')


class Term(abc.ABC):

    def __or__(self, other):
        return self.or_term(other)

    def __and__(self, other):
        return self.and_term(other)

    def __eq__(self, other):
        if isinstance(other, Term):
            return self.__dict__ == other.__dict__

    def or_term(self, other):
        if not isinstance(other, Term):
            raise AttributeError(f"Expected Term but got {other}")
        else:
            return CombinedTerm(self, "or", other)

    def and_term(self, other):
        if not isinstance(other, Term):
            raise AttributeError(f"Expected Term but got {other}")
        else:
            return CombinedTerm(self, "and", other)

    # noinspection PyTypeChecker
    @staticmethod
    def from_json(json: dict[str, object], _: type = object, **kwargs) -> Term:
        if isinstance(json.get("left"), dict) and isinstance(json.get("right"), dict) \
          and isinstance(json.get("op"), str):
            left = Term.from_json(json["left"])  # type: ignore
            right = Term.from_json(json["right"])  # type: ignore
            return CombinedTerm(left, json["op"], right)  # type: ignore
        elif isinstance(json.get("name"), str) and isinstance(json.get("op"), str):
            args = json["args"] if isinstance(json.get("args"), dict) else {}
            return Predicate(json["name"], json["op"], json["value"], args)  # type: ignore
        elif isinstance(json.get("fn"), str) and isinstance(json.get("property_path"), str):
            argv: list = json["args"] if isinstance(json.get("args"), list) else []  # type: ignore
            return FunctionTerm(json["fn"], json["property_path"], argv)  # type: ignore
        elif isinstance(json.get("kind"), str):
            return IsInstanceTerm(json["kind"])  # type: ignore
        elif isinstance(json.get("id"), str):
            return IdTerm(json.get("id"))  # type: ignore
        else:
            raise AttributeError(f"Can not parse json into query: {json}")


class Predicate(Term):
    def __init__(self, name: str, op: str, value: object, args: dict[str, object]):
        self.name = name
        self.op = op
        self.value = value
        self.args = args

    def __str__(self):
        return f"{self.name} {self.op} {self.value_str_rep(self.value)}"

    @staticmethod
    def value_str_rep(value) -> str:
        """
        This method is used to get a string representation of a value.
        :param value: the value to be represented.
        :return: the string representation.
        """
        if value is None:
            return "null"
        elif isinstance(value, str):
            return f'"{value}"'
        elif isinstance(value, bool):
            return "true" if value else "false"
        else:
            return str(value)


class CombinedTerm(Term):
    def __init__(self, left: Term, op: str, right: Term):
        self.left = left
        self.op = op
        self.right = right

    def __str__(self):
        return f"({self.left} {self.op} {self.right})"


class IdTerm(Term):
    def __init__(self, uid: str):
        self.id = uid

    def __str__(self):
        return f'id("{self.id}")'


class IsInstanceTerm(Term):
    def __init__(self, kind: str):
        self.kind = kind

    def __str__(self):
        return f'isinstance("{self.kind}")'


class FunctionTerm(Term):
    def __init__(self, fn: str, property_path: str, args: list):
        self.fn = fn
        self.property_path = property_path
        self.args = args

    def __str__(self):
        args = ", ".join((Predicate.value_str_rep(a) for a in self.args))
        sep = ", " if args else ""
        return f"{self.fn}({self.property_path}{sep}{args})"


class Navigation:
    # Define the maximum level of navigation
    Max = sys.maxsize

    def __init__(self, start: int = 0, until: int = 0, direction: str = "out"):
        self.start = start
        self.until = until
        self.direction = direction

    def is_out(self) -> bool:
        return self.direction == "out"

    def is_in(self) -> bool:
        return self.direction == "in"

    def __str__(self):
        d = "<" if self.is_in() else ">"
        if self.start == self.until:
            return d * 3 if self.start == 1 and self.until == 1 else f"{d}[{self.start}]{d}"
        else:
            return f"{d}[{self.start}:]{d}" if self.until == Navigation.Max else f"{d}[{self.start}:{self.until}]{d}"


class Part:
    def __init__(self, term: Term, pinned: bool = False, navigation: Navigation = None):
        self.term = term
        self.navigation = navigation
        self.pinned = pinned

    def __str__(self):
        nav = f" {self.navigation}" if self.navigation is not None else ""
        pin = "+" if self.pinned else ""
        return f"{self.term}{nav}{pin}"


class Query:
    def __init__(self, parts: List[Part] = None):
        if parts is None or len(parts) == 0:
            raise AttributeError(f"Expected non empty parts but got {parts}")
        self.parts = parts

    @staticmethod
    def by(term, *terms):
        res = Query.mk_term(term, terms)
        return Query([Part(res)])

    def __str__(self):
        or_terms = [str(a) for a in reversed(self.parts)]
        return " ".join(or_terms)

    def filter(self, term, *terms):
        res = Query.mk_term(term, terms)
        parts = self.parts.copy()
        first = parts[0]
        if first.navigation is None:
            # just add the filter to this query
            parts[0] = Part(CombinedTerm(first.term, "and", res))
        else:
            # put to the start
            parts.insert(0, Part(res))
        return Query(parts)

    def traverse_out(self, start: int = 1, until: int = 1):
        return self.traverse(start, until, "out")

    def traverse_in(self, start: int = 1, until: int = 1):
        return self.traverse(start, until, "out")

    def traverse(self, start: int, until: int, direction: str = "out"):
        parts = self.parts.copy()
        parts[0] = Part(parts[0].term, False, Navigation(start, until, direction))
        return Query(parts)

    def out_until_leaf(self):
        return self.traverse_out(1, 100)

    @staticmethod
    def mk_term(term, args: tuple) -> Term:
        def make_term(t):
            if isinstance(t, Term):
                return t
            elif isinstance(t, str):
                return IsInstanceTerm(t)
            else:
                raise AttributeError(f"Expected term or string, but got {t}")

        term_in = list(args)
        term_in.insert(0, term)
        terms = map(make_term, term_in)
        # noinspection PyTypeChecker
        return reduce(lambda l, r: CombinedTerm(l, "and", r), terms)


# register serializer for this class
set_deserializer(Term.from_json, Term)
