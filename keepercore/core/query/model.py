from __future__ import annotations
import abc
from functools import reduce
from typing import List, Mapping, Union, Optional

from jsons import set_deserializer

from core.model.graph_access import EdgeType


class P:
    def __init__(self, name: str, **kwargs: object):
        self.name = name
        self.args = kwargs

    @staticmethod
    def single(name: str) -> P:
        return P(name)

    @staticmethod
    def array(name: str) -> PArray:
        return PArray(name)

    @staticmethod
    def with_id(uid: str) -> Term:
        return IdTerm(uid)

    @staticmethod
    def of_kind(name: str) -> Term:
        return IsInstanceTerm(name)

    @staticmethod
    def function(fn: str) -> PFunction:
        return PFunction(fn)

    def __gt__(self, other: object) -> Predicate:
        return self.gt(other)

    def __ge__(self, other: object) -> Predicate:
        return self.ge(other)

    def __lt__(self, other: object) -> Predicate:
        return self.lt(other)

    def __le__(self, other: object) -> Predicate:
        return self.le(other)

    def __eq__(self, other: object) -> Predicate:  # type: ignore
        return self.eq(other)

    def __ne__(self, other: object) -> Predicate:  # type: ignore
        return self.ne(other)

    def gt(self, other: object) -> Predicate:
        return Predicate(self.name, ">", other, self.args)

    def ge(self, other: object) -> Predicate:
        return Predicate(self.name, ">=", other, self.args)

    def lt(self, other: object) -> Predicate:
        return Predicate(self.name, "<", other, self.args)

    def le(self, other: object) -> Predicate:
        return Predicate(self.name, "<=", other, self.args)

    def eq(self, other: object) -> Predicate:
        return Predicate(self.name, "==", other, self.args)

    def ne(self, other: object) -> Predicate:
        return Predicate(self.name, "!=", other, self.args)

    def matches(self, regex: str) -> Predicate:
        return Predicate(self.name, "=~", regex, self.args)

    def not_matches(self, regex: str) -> Predicate:
        return Predicate(self.name, "!~", regex, self.args)

    def is_in(self, other: List[object]) -> Predicate:
        return Predicate(self.name, "in", other, self.args)

    def is_not_in(self, other: List[object]) -> Predicate:
        return Predicate(self.name, "not in", other, self.args)


class PFunction:
    def __init__(self, fn: str):
        self.fn = fn

    def on(self, name: str, *args: object) -> FunctionTerm:
        return FunctionTerm(self.fn, name, list(args))


class PArray:
    def __init__(self, name: str):
        self.name = name

    def for_any(self) -> P:
        return P(self.name, array=True, filter="any")

    def for_none(self) -> P:
        return P(self.name, array=True, filter="none")

    def for_all(self) -> P:
        return P(self.name, array=True, filter="all")


class Term(abc.ABC):
    def __or__(self, other: Term) -> Term:
        return self.or_term(other)

    def __and__(self, other: Term) -> Term:
        return self.and_term(other)

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Term) else False

    def or_term(self, other: Term) -> CombinedTerm:
        if not isinstance(other, Term):
            raise AttributeError(f"Expected Term but got {other}")
        else:
            return CombinedTerm(self, "or", other)

    def and_term(self, other: Term) -> CombinedTerm:
        if not isinstance(other, Term):
            raise AttributeError(f"Expected Term but got {other}")
        else:
            return CombinedTerm(self, "and", other)

    def on_section(self, section: str) -> Term:
        def walk(term: Term) -> Term:
            if isinstance(term, CombinedTerm):
                return CombinedTerm(walk(term.left), term.op, walk(term.right))
            elif isinstance(term, Predicate):
                return Predicate(f"{section}.{term.name}", term.op, term.value, term.args)
            elif isinstance(term, FunctionTerm):
                return FunctionTerm(term.fn, f"{section}.{term.property_path}", term.args)
            else:
                return term

        return walk(self)

    def simplify(self) -> Term:
        def walk(term: Term) -> Term:
            if isinstance(term, CombinedTerm):
                left = walk(term.left)
                right = walk(term.right)
                left_all = isinstance(left, AllTerm)
                right_all = isinstance(right, AllTerm)
                if left_all or right_all:
                    if (left_all and term.op == "and") or (right_all and term.op == "or"):
                        return right
                    elif (right_all and term.op == "and") or (left_all and term.op == "or"):
                        return left
                return CombinedTerm(left, term.op, right)
            else:
                return term

        return walk(self)

    # noinspection PyTypeChecker
    @staticmethod
    def from_json(json: dict[str, object], _: type = object, **kwargs: object) -> Term:
        if (
            isinstance(json.get("left"), dict)
            and isinstance(json.get("right"), dict)
            and isinstance(json.get("op"), str)
        ):
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


class AllTerm(Term):
    def __str__(self) -> str:
        return "all"


class Predicate(Term):
    def __init__(self, name: str, op: str, value: object, args: Mapping[str, object]):
        self.name = name
        self.op = op
        self.value = value
        self.args = args

    def __str__(self) -> str:
        return f"{self.name} {self.op} {self.value_str_rep(self.value)}"

    @staticmethod
    def value_str_rep(value: object) -> str:
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

    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"


class IdTerm(Term):
    def __init__(self, uid: str):
        self.id = uid

    def __str__(self) -> str:
        return f'id("{self.id}")'


class IsInstanceTerm(Term):
    def __init__(self, kind: str):
        self.kind = kind

    def __str__(self) -> str:
        return f'isinstance("{self.kind}")'


class FunctionTerm(Term):
    def __init__(self, fn: str, property_path: str, args: List[object]):
        self.fn = fn
        self.property_path = property_path
        self.args = args

    def __str__(self) -> str:
        args = ", ".join((Predicate.value_str_rep(a) for a in self.args))
        sep = ", " if args else ""
        return f"{self.fn}({self.property_path}{sep}{args})"


class Navigation:
    # Define the maximum level of navigation
    Max = 10000

    def __init__(self, start: int = 1, until: int = 1, edge_type: str = EdgeType.default, direction: str = "out"):
        self.start = start
        self.until = until
        self.edge_type = edge_type
        self.direction = direction

    def is_out(self) -> bool:
        return self.direction == "out"

    def is_in(self) -> bool:
        return self.direction == "in"

    def __str__(self) -> str:
        start = self.start
        until = self.until
        until_str = "" if until == Navigation.Max else until
        depth = ("" if start == 1 else f"[{start}]") if start == until else f"[{start}:{until_str}]"
        nav = depth if self.edge_type == EdgeType.default else f"{self.edge_type}{depth}"
        if self.direction == "out":
            return f"-{nav}->"
        elif self.direction == "in":
            return f"<-{nav}-"
        else:
            return f"-{nav}-"


class Part:
    def __init__(self, term: Term, pinned: bool = False, navigation: Optional[Navigation] = None):
        self.term = term
        self.navigation = navigation
        self.pinned = pinned

    def __str__(self) -> str:
        nav = f" {self.navigation}" if self.navigation is not None else ""
        pin = "+" if self.pinned else ""
        return f"{self.term}{nav}{pin}"


class AggregateVariable:
    def __init__(self, name: str, as_name: Optional[str] = None):
        self.name = name
        self.as_name = as_name

    def __str__(self) -> str:
        with_as = f" as {self.as_name}" if self.as_name else ""
        return f"{self.name}{with_as}"

    def get_as_name(self) -> str:
        return self.as_name if self.as_name else self.name


class AggregateFunction:
    def __init__(
        self,
        function: str,
        name_or_value: Union[str, int],
        ops: Optional[list[tuple[str, Union[int, float]]]] = None,
        as_name: Optional[str] = None,
    ):
        self.function = function
        self.name = name_or_value
        self.ops: list[tuple[str, Union[int, float]]] = ops if ops else []
        self.as_name = as_name

    def __str__(self) -> str:
        with_as = f" as {self.as_name}" if self.as_name else ""
        with_ops = " " + self.combined_ops() if self.ops else ""
        return f"{self.function}({self.name}{with_ops}){with_as}"

    def combined_ops(self) -> str:
        return " ".join(f"{op} {value}" for op, value in self.ops)

    def get_as_name(self) -> str:
        return self.as_name if self.as_name else f"{self.function}_of_{self.name}"


class Aggregate:
    def __init__(self, group_by: List[AggregateVariable], group_func: List[AggregateFunction]):
        self.group_by = group_by
        self.group_func = group_func

    def __str__(self) -> str:
        group_by = ", ".join(str(a) for a in self.group_by)
        funcs = ", ".join(str(a) for a in self.group_func)
        return f"aggregate({group_by}: {funcs})"


SimpleValue = Union[str, int, float, bool]


class Query:
    def __init__(
        self,
        parts: List[Part],
        preamble: Optional[dict[str, SimpleValue]] = None,
        aggregate: Optional[Aggregate] = None,
    ):
        if parts is None or len(parts) == 0:
            raise AttributeError(f"Expected non empty parts but got {parts}")
        self.parts = parts
        self.preamble: dict[str, SimpleValue] = preamble if preamble else dict()
        self.aggregate = aggregate

    @staticmethod
    def by(
        term: Union[str, Term], *terms: Union[str, Term], preamble: Optional[dict[str, SimpleValue]] = None
    ) -> Query:
        res = Query.mk_term(term, *terms)
        return Query([Part(res)], preamble)

    def __str__(self) -> str:
        aggregate = str(self.aggregate) if self.aggregate else ""
        to_str = Predicate.value_str_rep
        preamble = "{" + ", ".join(f"{k}={to_str(v)}" for k, v in self.preamble.items()) + "}" if self.preamble else ""
        colon = ":" if self.preamble or self.aggregate else ""
        parts = " ".join(str(a) for a in reversed(self.parts))
        return f"{aggregate}{preamble}{colon}{parts}"

    def filter(self, term: Union[str, Term], *terms: Union[str, Term]) -> Query:
        res = Query.mk_term(term, *terms)
        parts = self.parts.copy()
        first = parts[0]
        if first.navigation is None:
            # just add the filter to this query
            parts[0] = Part(CombinedTerm(first.term, "and", res))
        else:
            # put to the start
            parts.insert(0, Part(res))
        return Query(parts, self.preamble, self.aggregate)

    def traverse_out(self, start: int = 1, until: int = 1, edge_type: str = EdgeType.default) -> Query:
        return self.traverse(start, until, edge_type, "out")

    def traverse_in(self, start: int = 1, until: int = 1, edge_type: str = EdgeType.default) -> Query:
        return self.traverse(start, until, edge_type, "in")

    def traverse(self, start: int, until: int, edge_type: str = EdgeType.default, direction: str = "out") -> Query:
        parts = self.parts.copy()
        p0 = parts[0]
        if p0.navigation:
            # we already traverse in this direction: add start and until
            if p0.navigation.edge_type == edge_type and p0.navigation.direction == direction:
                start_m = min(Navigation.Max, start + p0.navigation.start)
                until_m = min(Navigation.Max, until + p0.navigation.until)
                parts[0] = Part(p0.term, False, Navigation(start_m, until_m, edge_type, direction))
            # this is another traversal: so we need to start a new part
            else:
                parts.insert(0, Part(AllTerm(), False, Navigation(start, until, edge_type, direction)))
        else:
            parts[0] = Part(p0.term, False, Navigation(start, until, edge_type, direction))
        return Query(parts, self.preamble, self.aggregate)

    def group_by(self, group_by: List[AggregateVariable], funs: List[AggregateFunction]) -> Query:
        aggregate = Aggregate(group_by, funs)
        return Query(self.parts, self.preamble, aggregate)

    def simplify(self) -> Query:
        parts = [Part(part.term.simplify(), part.pinned, part.navigation) for part in self.parts]
        return Query(parts, self.preamble, self.aggregate)

    @staticmethod
    def mk_term(term: Union[str, Term], *args: Union[str, Term]) -> Term:
        def make_term(t: Union[str, Term]) -> Term:
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
