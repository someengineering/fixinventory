from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field, replace
from functools import reduce
from typing import Mapping, Union, Optional, Any, ClassVar, Dict, List, Tuple, Callable, Set

from jsons import set_deserializer

from core.model.graph_access import EdgeType
from core.model.typed_model import to_js
from core.util import combine_optional


class P:
    def __init__(self, name: str, **kwargs: Any):
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
        return IsTerm(name)

    @staticmethod
    def function(fn: str) -> PFunction:
        return PFunction(fn)

    def __gt__(self, other: Any) -> Predicate:
        return self.gt(other)

    def __ge__(self, other: Any) -> Predicate:
        return self.ge(other)

    def __lt__(self, other: Any) -> Predicate:
        return self.lt(other)

    def __le__(self, other: Any) -> Predicate:
        return self.le(other)

    def __eq__(self, other: Any) -> Predicate:  # type: ignore
        return self.eq(other)

    def __ne__(self, other: Any) -> Predicate:  # type: ignore
        return self.ne(other)

    def gt(self, other: Any) -> Predicate:
        return Predicate(self.name, ">", other, self.args)

    def ge(self, other: Any) -> Predicate:
        return Predicate(self.name, ">=", other, self.args)

    def lt(self, other: Any) -> Predicate:
        return Predicate(self.name, "<", other, self.args)

    def le(self, other: Any) -> Predicate:
        return Predicate(self.name, "<=", other, self.args)

    def eq(self, other: Any) -> Predicate:
        return Predicate(self.name, "==", other, self.args)

    def ne(self, other: Any) -> Predicate:
        return Predicate(self.name, "!=", other, self.args)

    def matches(self, regex: str) -> Predicate:
        return Predicate(self.name, "=~", regex, self.args)

    def not_matches(self, regex: str) -> Predicate:
        return Predicate(self.name, "!~", regex, self.args)

    def is_in(self, other: List[Any]) -> Predicate:
        return Predicate(self.name, "in", other, self.args)

    def is_not_in(self, other: List[Any]) -> Predicate:
        return Predicate(self.name, "not in", other, self.args)


class PFunction:
    def __init__(self, fn: str):
        self.fn = fn

    def on(self, name: str, *args: Any) -> FunctionTerm:
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


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Term(abc.ABC):
    def __or__(self, other: Term) -> Term:
        return self.or_term(other)

    def __and__(self, other: Term) -> Term:
        return self.and_term(other)

    def __eq__(self, other: Any) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Term) else False

    def not_term(self) -> NotTerm:
        return NotTerm(self)

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

    # noinspection PyUnusedLocal
    @staticmethod
    def from_json(js: Dict[str, Any], _: type = object, **kwargs: Any) -> Term:
        if isinstance(js.get("left"), dict) and isinstance(js.get("right"), dict) and isinstance(js.get("op"), str):
            left = Term.from_json(js["left"])
            right = Term.from_json(js["right"])
            return CombinedTerm(left, js["op"], right)
        elif isinstance(js.get("name"), str) and isinstance(js.get("op"), str):
            args = js["args"] if isinstance(js.get("args"), dict) else {}
            return Predicate(js["name"], js["op"], js["value"], args)
        elif isinstance(js.get("fn"), str) and isinstance(js.get("property_path"), str):
            argv: list = js["args"] if isinstance(js.get("args"), list) else []  # type: ignore
            return FunctionTerm(js["fn"], js["property_path"], argv)
        elif isinstance(js.get("kind"), str):
            return IsTerm(js["kind"])
        elif isinstance(js.get("id"), str):
            return IdTerm(js.get("id"))  # type: ignore
        else:
            raise AttributeError(f"Can not parse json into query: {js}")


class AllTerm(Term):
    def __str__(self) -> str:
        return "all"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class NotTerm(Term):
    term: Term

    def __str__(self) -> str:
        return f"not({self.term})"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Predicate(Term):
    name: str
    op: str
    value: Any
    args: Mapping[str, Any]

    def __str__(self) -> str:
        return f"{self.name} {self.op} {self.value_str_rep(self.value)}"

    @staticmethod
    def value_str_rep(value: Any) -> str:
        """
        This method is used to get a string representation of a value.
        :param value: the value to be represented.
        :return: the string representation.
        """
        return json.dumps(to_js(value))


@dataclass(order=True, unsafe_hash=True, frozen=True)
class CombinedTerm(Term):
    left: Term
    op: str
    right: Term

    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class IdTerm(Term):
    id: str

    def __str__(self) -> str:
        return f'id("{self.id}")'


@dataclass(order=True, unsafe_hash=True, frozen=True)
class IsTerm(Term):
    kind: str

    def __str__(self) -> str:
        return f'is("{self.kind}")'


@dataclass(order=True, unsafe_hash=True, frozen=True)
class FunctionTerm(Term):
    fn: str
    property_path: str
    args: List[Any]

    def __str__(self) -> str:
        args = ", ".join((Predicate.value_str_rep(a) for a in self.args))
        sep = ", " if args else ""
        return f"{self.fn}({self.property_path}{sep}{args})"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class MergeQuery(Term):
    name: str
    query: Query

    def __str__(self) -> str:
        return f"{self.name}: {self.query}"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class MergeTerm(Term):
    pre_filter: Term
    merge: List[MergeQuery]
    post_filter: Optional[Term] = None

    def __str__(self) -> str:
        merge = ", ".join(str(q) for q in self.merge)
        post = " " + str(self.post_filter) if self.post_filter else ""
        return f"{self.pre_filter} {{{merge}}}{post}"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Navigation:
    # Define the maximum level of navigation
    Max: ClassVar[int] = 10000

    start: int = 1
    until: int = 1
    edge_type: str = EdgeType.default
    direction: str = "out"

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
            return f"<-{nav}->"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class WithClauseFilter:
    op: str
    num: int

    def __str__(self) -> str:
        if self.op == "==" and self.num == 0:
            return "empty"
        elif self.op == ">" and self.num == 0:
            return "any"
        else:
            return f"count{self.op}{self.num}"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class WithClause:
    with_filter: WithClauseFilter
    navigation: Navigation
    term: Optional[Term] = None
    with_clause: Optional[WithClause] = None

    def on_section(self, section: str) -> WithClause:
        return replace(
            self,
            term=self.term.on_section(section) if self.term else None,
            with_clause=self.with_clause.on_section(section) if self.with_clause else None,
        )

    def __str__(self) -> str:
        term = " " + str(self.term) if self.term else ""
        with_clause = " " + str(self.with_clause) if self.with_clause else ""
        return f"with({self.with_filter}, {self.navigation}{term}{with_clause})"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Part:
    term: Term
    tag: Optional[str] = None
    with_clause: Optional[WithClause] = None
    sort: List[Sort] = field(default_factory=list)
    limit: Optional[int] = None
    navigation: Optional[Navigation] = None

    def __str__(self) -> str:
        with_clause = f" {self.with_clause}" if self.with_clause is not None else ""
        tag = f"#{self.tag}" if self.tag else ""
        sort = " sort " + (",".join(f"{a.name} {a.order}" for a in self.sort)) if self.sort else ""
        limit = f" limit {self.limit}" if self.limit else ""
        nav = f" {self.navigation}" if self.navigation is not None else ""
        return f"{self.term}{with_clause}{tag}{sort}{limit}{nav}"

    def on_section(self, section: str) -> Part:
        return replace(
            self,
            term=self.term.on_section(section),
            with_clause=self.with_clause.on_section(section) if self.with_clause else None,
            sort=[sort.on_section(section) for sort in self.sort],
        )


@dataclass(order=True, unsafe_hash=True, frozen=True)
class AggregateVariableName:
    name: str

    def __str__(self) -> str:
        return self.name

    def on_section(self, section: str) -> AggregateVariableName:
        return AggregateVariableName(f"{section}.{self.name}")


@dataclass(order=True, unsafe_hash=True, frozen=True)
class AggregateVariableCombined:
    parts: List[Union[str, AggregateVariableName]]

    def __str__(self) -> str:
        return "".join(p if isinstance(p, str) else f"{{{p}}}" for p in self.parts)

    def on_section(self, section: str) -> AggregateVariableCombined:
        return AggregateVariableCombined(
            [p.on_section(section) if isinstance(p, AggregateVariableName) else p for p in self.parts]
        )


@dataclass(order=True, unsafe_hash=True, frozen=True)
class AggregateVariable:
    # name is either a simple variable name or some combination of strings and variables like "foo_{var1}_{var2}_bla"
    name: Union[AggregateVariableName, AggregateVariableCombined]
    as_name: Optional[str] = None

    def __str__(self) -> str:
        with_as = f" as {self.as_name}" if self.as_name else ""
        return f"{self.name}{with_as}"

    def get_as_name(self) -> str:
        return self.as_name if self.as_name else str(self.name)

    def on_section(self, section: str) -> AggregateVariable:
        return replace(self, name=self.name.on_section(section))


@dataclass(order=True, unsafe_hash=True, frozen=True)
class AggregateFunction:
    function: str
    name: Union[str, int]
    ops: List[Tuple[str, Union[int, float]]] = field(default_factory=list)
    as_name: Optional[str] = None

    def __str__(self) -> str:
        with_as = f" as {self.as_name}" if self.as_name else ""
        with_ops = " " + self.combined_ops() if self.ops else ""
        return f"{self.function}({self.name}{with_ops}){with_as}"

    def combined_ops(self) -> str:
        return " ".join(f"{op} {value}" for op, value in self.ops)

    def get_as_name(self) -> str:
        return self.as_name if self.as_name else f"{self.function}_of_{self.name}"

    def on_section(self, section: str) -> AggregateFunction:
        return replace(self, name=f"{section}.{self.name}") if isinstance(self.name, str) else self


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Aggregate:
    group_by: List[AggregateVariable]
    group_func: List[AggregateFunction]

    def __str__(self) -> str:
        group_by = ", ".join(str(a) for a in self.group_by) + ": " if self.group_by else ""
        funcs = ", ".join(str(a) for a in self.group_func)
        return f"aggregate({group_by}{funcs})"

    def on_section(self, section: str) -> Aggregate:
        return Aggregate(
            [a.on_section(section) for a in self.group_by],
            [a.on_section(section) for a in self.group_func],
        )


SimpleValue = Union[str, int, float, bool]


class SortOrder:
    Asc = "asc"
    Desc = "desc"


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Sort:
    name: str
    order: str = SortOrder.Asc

    def __str__(self) -> str:
        return f"{self.name} {self.order}"

    def on_section(self, section: str) -> Sort:
        return replace(self, name=f"{section}.{self.name}")


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Query:
    parts: List[Part]
    preamble: Dict[str, SimpleValue] = field(default_factory=dict)
    aggregate: Optional[Aggregate] = None

    def __post_init__(self) -> None:
        if self.parts is None or len(self.parts) == 0:
            raise AttributeError(f"Expected non empty parts but got {self.parts}")

    @staticmethod
    def by(
        term: Union[str, Term], *terms: Union[str, Term], preamble: Optional[Dict[str, SimpleValue]] = None
    ) -> Query:
        res = Query.mk_term(term, *terms)
        return Query([Part(res)], preamble if preamble else {})

    def __str__(self) -> str:
        aggregate = str(self.aggregate) if self.aggregate else ""
        to_str = Predicate.value_str_rep
        preamble = "(" + ", ".join(f"{k}={to_str(v)}" for k, v in self.preamble.items()) + ")" if self.preamble else ""
        colon = ":" if self.preamble or self.aggregate else ""
        parts = " ".join(str(a) for a in reversed(self.parts))
        return f"{aggregate}{preamble}{colon}{parts}"

    @property
    def merge_names(self) -> Set[str]:
        return {mt.name for part in self.parts if isinstance(part.term, MergeTerm) for mt in part.term.merge}

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
        return replace(self, parts=parts)

    def filter_with(self, clause: WithClause) -> Query:
        first = replace(self.parts[0], with_clause=clause)
        return replace(self, parts=[first, *self.parts[1:]])

    def traverse_out(self, start: int = 1, until: int = 1, edge_type: str = EdgeType.default) -> Query:
        return self.traverse(start, until, edge_type, "out")

    def traverse_in(self, start: int = 1, until: int = 1, edge_type: str = EdgeType.default) -> Query:
        return self.traverse(start, until, edge_type, "in")

    def traverse_inout(self, start: int = 1, until: int = 1, edge_type: str = EdgeType.default) -> Query:
        return self.traverse(start, until, edge_type, "inout")

    def traverse(self, start: int, until: int, edge_type: str = EdgeType.default, direction: str = "out") -> Query:
        parts = self.parts.copy()
        p0 = parts[0]
        if p0.navigation:
            # we already traverse in this direction: add start and until
            if p0.navigation.edge_type == edge_type and p0.navigation.direction == direction:
                start_m = min(Navigation.Max, start + p0.navigation.start)
                until_m = min(Navigation.Max, until + p0.navigation.until)
                parts[0] = replace(p0, navigation=Navigation(start_m, until_m, edge_type, direction))
            # this is another traversal: so we need to start a new part
            else:
                parts.insert(0, Part(AllTerm(), navigation=Navigation(start, until, edge_type, direction)))
        else:
            parts[0] = replace(p0, navigation=Navigation(start, until, edge_type, direction))
        return replace(self, parts=parts)

    def group_by(self, group_by: List[AggregateVariable], funcs: List[AggregateFunction]) -> Query:
        aggregate = Aggregate(group_by, funcs)
        return replace(self, aggregate=aggregate)

    def simplify(self) -> Query:
        parts = [replace(part, term=part.term.simplify()) for part in self.parts]
        return replace(self, parts=parts)

    def add_sort(self, name: str, order: str = SortOrder.Asc) -> Query:
        return self.__change_current_part(lambda p: replace(p, sort=[*p.sort, Sort(name, order)]))

    def with_limit(self, num: int) -> Query:
        return self.__change_current_part(lambda p: replace(p, limit=num))

    def merge_preamble(self, preamble: Dict[str, SimpleValue]) -> Query:
        updated = {**self.preamble, **preamble} if self.preamble else preamble
        return replace(self, preamble=updated)

    def on_section(self, section: str) -> Query:
        aggregate = self.aggregate.on_section(section) if self.aggregate else None
        parts = [p.on_section(section) for p in self.parts]
        return replace(self, aggregate=aggregate, parts=parts)

    def tag(self, name: str) -> Query:
        return self.__change_current_part(lambda p: replace(p, tag=name))

    @property
    def current_part(self) -> Part:
        # remember: the order of parts is reversed
        return self.parts[0]

    def __change_current_part(self, fn: Callable[[Part], Part]) -> Query:
        parts = self.parts.copy()
        # if navigation is defined: the current part is already defined to the end
        if parts[0].navigation:
            part = Part(AllTerm())
            parts.insert(0, part)
        else:
            part = parts[0]
        parts[0] = fn(part)
        return replace(self, parts=parts)

    def combine(self, other: Query) -> Query:
        preamble = {**self.preamble, **other.preamble}
        if self.aggregate and other.aggregate:
            raise AttributeError("Can not combine 2 aggregations!")
        aggregate = self.aggregate if self.aggregate else other.aggregate
        left_last = self.parts[0]
        right_first = other.parts[-1]
        if left_last.navigation:
            parts = other.parts + self.parts
        else:
            if left_last.with_clause and right_first.with_clause:
                raise AttributeError("Can not combine 2 with clauses!")
            term = left_last.term & right_first.term
            if left_last.tag and right_first.tag:
                raise AttributeError("Can not combine 2 tag clauses!")
            tag = left_last.tag if left_last.tag else right_first.tag
            with_clause = left_last.with_clause if left_last.with_clause else right_first.with_clause
            sort = combine_optional(left_last.sort, right_first.sort, lambda l, r: l + r)
            limit = combine_optional(left_last.limit, right_first.limit, min)
            combined = Part(term, tag, with_clause, sort if sort else [], limit, right_first.navigation)
            parts = [*other.parts[0:-1], combined, *self.parts[1:]]
        return Query(parts, preamble, aggregate)

    @staticmethod
    def mk_term(term: Union[str, Term], *args: Union[str, Term]) -> Term:
        def make_term(t: Union[str, Term]) -> Term:
            if isinstance(t, Term):
                return t
            elif isinstance(t, str):
                return IsTerm(t)
            else:
                raise AttributeError(f"Expected term or string, but got {t}")

        term_in = list(args)
        term_in.insert(0, term)
        terms = map(make_term, term_in)
        # noinspection PyTypeChecker
        return reduce(lambda l, r: CombinedTerm(l, "and", r), terms)


# register serializer for this class
set_deserializer(Term.from_json, Term)
