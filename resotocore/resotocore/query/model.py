from __future__ import annotations

import abc
from collections import defaultdict
from attrs import define, field, evolve
from functools import reduce, partial, cached_property
from itertools import chain
from typing import Mapping, Union, Optional, Any, ClassVar, Dict, List, Tuple, Callable, Set, Iterable

from jsons import set_deserializer

from resotocore.model.graph_access import EdgeTypes, Direction
from resotocore.model.resolve_in_graph import GraphResolver
from resotocore.model.typed_model import to_js_str
from resotocore.types import Json, JsonElement, EdgeType
from resotocore.util import combine_optional

PathRoot = "/"


def variable_to_absolute(section: Optional[str], name: str) -> str:
    if name.startswith(PathRoot):
        return name[1:]
    elif section and section != PathRoot:
        return section + "." + name
    else:
        return name


def variable_to_relative(section: str, name: str) -> str:
    if name.startswith(PathRoot):
        return name
    elif name.startswith(f"{section}."):
        return name[len(section) + 1 :]  # noqa: E203a
    else:
        return PathRoot + name


def is_ancestor_descendant(name: str) -> bool:
    return name not in GraphResolver.resolved_property_names and (
        name.startswith("ancestors.") or name.startswith("descendants.")
    )


@define(order=True, hash=True, frozen=True)
class Template:
    """
    A template has a name and a template string.
    The template string might contain placeholder values.
    """

    name: str  # the name of the template
    template: str  # the template string with placeholders


@define(order=True, hash=True, frozen=True)
class Expandable:
    """
    An expandable refers to a template with a given name
    and has properties to render this template to a final string.
    """

    template: str  # the name of the template
    props: Json  # the properties to render this template


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
        return IsTerm([name])

    @staticmethod
    def all() -> Term:
        return AllTerm()

    @staticmethod
    def context(name: str, *terms: Term) -> Term:
        return ContextTerm(name, reduce(lambda a, b: a & b, terms, AllTerm()))  # type: ignore

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
        return P(self.name, filter="any")

    def for_none(self) -> P:
        return P(self.name, filter="none")

    def for_all(self) -> P:
        return P(self.name, filter="all")


@define(order=True, hash=True, frozen=True)
class Term(abc.ABC):
    """
    @startuml
    class Term
    Term <|-- CombinedTerm
    Term <|-- NotTerm
    Term <|-- MergeTerm
    Term <|--- AllTerm
    Term <|--- FulltextTerm
    Term <|--- Predicate
    Term <|--- ContextTerm
    Term <|--- IdTerm
    Term <|--- IsTerm
    Term <|--- FunctionTerm
    NotTerm --> Term: not
    CombinedTerm --> Term: left
    CombinedTerm --> Term: right
    MergeTerm --> Term: pre_filter
    MergeTerm --> Term: post_filter
    ContextTerm *--> Term: term
    @enduml
    """

    def __or__(self, other: Term) -> Term:
        return self.or_term(other)

    def __and__(self, other: Term) -> Term:
        return self.and_term(other)

    def not_term(self) -> NotTerm:
        return NotTerm(self)

    def combine(self, op: str, other: Term) -> Term:
        if op == "or":
            return self.or_term(other)
        elif op == "and":
            return self.and_term(other)
        else:
            raise AttributeError(f"Don't know how to combine with {op}")

    def or_term(self, other: Term) -> Term:
        if isinstance(self, AllTerm):
            return self
        elif isinstance(other, AllTerm):
            return other
        else:
            return CombinedTerm(self, "or", other)

    def and_term(self, other: Term) -> Term:
        if isinstance(self, AllTerm):
            return other
        elif isinstance(other, AllTerm):
            return self
        else:
            return CombinedTerm(self, "and", other)

    def change_variable(self, fn: Callable[[str], str]) -> Term:
        def walk(term: Term) -> Term:
            if isinstance(term, CombinedTerm):
                return CombinedTerm(walk(term.left), term.op, walk(term.right))
            if isinstance(term, ContextTerm):
                return ContextTerm(fn(term.name), term.term)
            elif isinstance(term, Predicate):
                return Predicate(fn(term.name), term.op, term.value, term.args)
            elif isinstance(term, FunctionTerm):
                return FunctionTerm(term.fn, fn(term.property_path), term.args)
            elif isinstance(term, MergeTerm):
                post = walk(term.post_filter) if term.post_filter else None
                return MergeTerm(walk(term.pre_filter), [mq.change_variable(fn) for mq in term.merge], post)
            elif isinstance(term, NotTerm):
                return NotTerm(walk(term.term))
            else:
                return term

        return walk(self)

    def find_term(self, fn: Callable[[Term], bool]) -> Optional[Term]:
        if fn(self):
            return self
        if isinstance(self, CombinedTerm):
            return self.left.find_term(fn) or self.right.find_term(fn)
        elif isinstance(self, NotTerm):
            return self.term.find_term(fn)
        elif isinstance(self, ContextTerm):
            return self.term.find_term(fn)
        elif isinstance(self, MergeTerm):

            def walk_merge_queries(mt: MergeTerm) -> Optional[Term]:
                for mq in mt.merge:
                    for p in mq.query.parts:
                        if (term := p.term.find_term(fn)) is not None:
                            return term
                return None

            return (
                self.pre_filter.find_term(fn)
                or (self.post_filter.find_term(fn) if self.post_filter else None)
                or walk_merge_queries(self)
            )
        else:
            return None

    def find_terms(self, fn: Callable[[Term], bool], **kwargs: bool) -> List[Term]:
        if fn(self):
            return [self]
        elif isinstance(self, CombinedTerm):
            return self.left.find_terms(fn, **kwargs) + self.right.find_terms(fn, **kwargs)
        elif isinstance(self, ContextTerm) and kwargs.get("in_context_term", True):
            return self.term.find_terms(fn, **kwargs)
        elif isinstance(self, NotTerm):
            return self.term.find_terms(fn, **kwargs)
        elif isinstance(self, MergeTerm):
            result = self.pre_filter.find_terms(fn, **kwargs)
            if self.post_filter:
                result.extend(self.post_filter.find_terms(fn, **kwargs))
            result.extend(r for mq in self.merge for p in mq.query.parts for r in p.term.find_terms(fn, **kwargs))
            return result
        else:
            return []

    def contains_term_type(self, clazz: type) -> bool:
        return self.find_term(lambda x: isinstance(x, clazz)) is not None

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
        elif isinstance(js.get("name"), str) and isinstance(js.get("predicates"), list):
            return ContextTerm(js["name"], js["predicates"])
        elif isinstance(js.get("fn"), str) and isinstance(js.get("property_path"), str):
            argv: list = js["args"] if isinstance(js.get("args"), list) else []  # type: ignore
            return FunctionTerm(js["fn"], js["property_path"], argv)
        elif isinstance(js.get("kind"), str):
            return IsTerm(js["kind"])
        elif isinstance(js.get("id"), str):
            return IdTerm(js.get("id"))  # type: ignore
        else:
            raise AttributeError(f"Can not parse json into query: {js}")


@define(order=True, hash=True, frozen=True)
class AllTerm(Term):
    _instance = None

    def __new__(cls) -> AllTerm:
        if cls._instance is None:
            cls._instance = super(AllTerm, cls).__new__(cls)
        return cls._instance

    def __str__(self) -> str:
        return "all"


@define(order=True, hash=True, frozen=True)
class NotTerm(Term):
    term: Term

    def __str__(self) -> str:
        return f"not({self.term})"


@define(order=True, hash=True, frozen=True)
class FulltextTerm(Term):
    text: str

    def __str__(self) -> str:
        return f'"{self.text}"'


@define(order=True, hash=True, frozen=True)
class Predicate(Term):
    name: str
    op: str
    value: JsonElement
    args: Mapping[str, JsonElement]

    def __str__(self) -> str:
        modifier = f'{self.args["filter"]} ' if "filter" in self.args else ""
        return f"{self.name} {modifier}{self.op} {self.value_str_rep(self.value)}"

    @staticmethod
    def value_str_rep(value: Any) -> str:
        """
        This method is used to get a string representation of a value.
        :param value: the value to be represented.
        :return: the string representation.
        """
        return to_js_str(value)


@define(order=True, hash=True, frozen=True)
class ContextTerm(Term):
    name: str
    term: Term

    def __str__(self) -> str:
        return f"{self.name}.{{{str(self.term)}}}"

    def visible_predicates(self) -> List[Predicate]:
        """
        This method is not used to render a query, but to get a list of predicates that are visible in the query.
        All predicates have the complete path without any contextual information.
        Idea: a.b[*].{ c=1 and d=2 and e[*].{f=1}} should return [a.b[*].c = 1, a.b[*].d = 2, a.b[*].e[*].f = 1]
        """

        def with_context(path: str, ctx: ContextTerm) -> List[Predicate]:
            result: List[Predicate] = []
            for p in ctx.term.find_terms(lambda x: isinstance(x, Predicate), in_context_term=False):
                result.append(evolve(p, name=f"{path}.{p.name}" if path else p.name))  # type: ignore
            for c in ctx.term.find_terms(lambda x: isinstance(x, ContextTerm)):
                result.extend(with_context(f"{path}.{c.name}" if path else c.name, c))  # type: ignore
            return result

        return with_context(self.name, self)


@define(order=True, hash=True, frozen=True)
class CombinedTerm(Term):
    left: Term
    op: str
    right: Term

    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"


@define(order=True, hash=True, frozen=True)
class IdTerm(Term):
    id: str

    def __str__(self) -> str:
        return f'id("{self.id}")'


@define(order=True, hash=True, frozen=True)
class IsTerm(Term):
    kinds: List[str]

    def __str__(self) -> str:
        kind_string = ", ".join(f'"{a}"' for a in self.kinds)
        kinds = kind_string if len(self.kinds) == 1 else f"[{kind_string}]"
        return f"is({kinds})"


@define(order=True, hash=True, frozen=True)
class FunctionTerm(Term):
    fn: str
    property_path: str
    args: List[Any]

    def __str__(self) -> str:
        args = ", ".join((Predicate.value_str_rep(a) for a in self.args))
        sep = ", " if args else ""
        return f"{self.fn}({self.property_path}{sep}{args})"


@define(order=True, hash=True, frozen=True)
class MergeQuery:
    name: str
    query: Query
    only_first: bool = True

    def __str__(self) -> str:
        arr = "" if self.only_first else "[]"
        return f"{self.name}{arr}: {self.query}"

    def change_variable(self, fn: Callable[[str], str]) -> MergeQuery:
        return evolve(self, name=fn(self.name), query=self.query.change_variable(fn))


@define(order=True, hash=True, frozen=True)
class MergeTerm(Term):
    pre_filter: Term
    merge: List[MergeQuery]
    post_filter: Optional[Term] = None

    def __str__(self) -> str:
        merge = ", ".join(str(q) for q in self.merge)
        post = " " + str(self.post_filter) if self.post_filter else ""
        return f"{self.pre_filter} {{{merge}}}{post}"


@define(order=True, hash=True, frozen=True)
class Navigation:
    # Define the maximum level of navigation
    Max: ClassVar[int] = 250

    start: int = 1
    until: int = 1
    maybe_edge_types: Optional[List[EdgeType]] = None
    direction: str = Direction.outbound
    maybe_two_directional_outbound_edge_type: Optional[List[EdgeType]] = None

    @property
    def edge_types(self) -> List[EdgeType]:
        return self.maybe_edge_types or [EdgeTypes.default]

    def __str__(self) -> str:
        start = self.start
        until = self.until
        until_str = "" if until == Navigation.Max else until
        mo = self.maybe_two_directional_outbound_edge_type
        depth = ("" if start == 1 else f"[{start}]") if start == until and not mo else f"[{start}:{until_str}]"
        out_nav = ",".join(mo) if mo else ""
        nav = f'{",".join(self.edge_types)}{depth}{out_nav}'
        if self.direction == Direction.outbound:
            return f"-{nav}->"
        elif self.direction == Direction.inbound:
            return f"<-{nav}-"
        else:
            return f"<-{nav}->"


NavigateUntilRoot = Navigation(
    start=1, until=Navigation.Max, maybe_edge_types=[EdgeTypes.default], direction=Direction.inbound
)
NavigateUntilLeaf = Navigation(
    start=1, until=Navigation.Max, maybe_edge_types=[EdgeTypes.default], direction=Direction.outbound
)


@define(order=True, hash=True, frozen=True)
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


@define(order=True, hash=True, frozen=True)
class WithClause:
    with_filter: WithClauseFilter
    navigation: Navigation
    term: Optional[Term] = None
    with_clause: Optional[WithClause] = None

    def change_variable(self, fn: Callable[[str], str]) -> WithClause:
        return evolve(
            self,
            term=self.term.change_variable(fn) if self.term else None,
            with_clause=self.with_clause.change_variable(fn) if self.with_clause else None,
        )

    def __str__(self) -> str:
        term = " " + str(self.term) if self.term else ""
        with_clause = " " + str(self.with_clause) if self.with_clause else ""
        return f"with({self.with_filter}, {self.navigation}{term}{with_clause})"


@define(order=True, hash=True, frozen=True)
class Limit:
    offset: int
    length: int

    def __str__(self) -> str:
        return f" limit {self.length}" if self.offset == 0 else f" limit {self.offset}, {self.length}"


# pylint: disable=not-an-iterable
@define(order=True, hash=True, frozen=True)
class Part:
    term: Term
    tag: Optional[str] = None
    with_clause: Optional[WithClause] = None
    sort: List[Sort] = field(factory=list)
    limit: Optional[Limit] = None
    navigation: Optional[Navigation] = None
    reverse_result: bool = False

    def __str__(self) -> str:
        with_clause = f" {self.with_clause}" if self.with_clause is not None else ""
        tag = f"#{self.tag}" if self.tag else ""
        sort = " sort " + (", ".join(f"{a.name} {a.order}" for a in self.sort)) if self.sort else ""
        limit = str(self.limit) if self.limit else ""
        nav = f" {self.navigation}" if self.navigation is not None else ""
        reverse = " reversed " if self.reverse_result else ""
        return f"{self.term}{with_clause}{tag}{sort}{limit}{reverse}{nav}"

    def change_variable(self, fn: Callable[[str], str]) -> Part:
        return evolve(
            self,
            term=self.term.change_variable(fn),
            with_clause=self.with_clause.change_variable(fn) if self.with_clause else None,
            sort=[sort.change_variable(fn) for sort in self.sort],
        )

    # ancestor.some_type.reported.prop -> MergeQuery
    def merge_queries_for(self, property_paths: Iterable[str]) -> List[MergeQuery]:
        def with_query_for(property_path: str) -> MergeQuery:
            try:
                assert is_ancestor_descendant(property_path)
                anc_dec, kind, _ = property_path.split(".", 2)
                direction = Direction.inbound if anc_dec == "ancestors" else Direction.outbound
                navigation = Navigation(1, Navigation.Max, direction=direction)
                subquery = Query([Part(IsTerm([kind])), Part(AllTerm(), navigation=navigation)])
                return MergeQuery(f"{anc_dec}.{kind}", subquery)
            except Exception as ex:
                raise AttributeError(
                    "The name of an ancestor variable has to follow the format: ancestors.<kind>.<path.to.variable>. "
                    "The kind defines the type of the ancestor to look for.\n"
                    "Example: ancestors.account.reported.name=test\n"
                    "Example: descendant..reported.name=test\n"
                ) from ex

        existing = {a.name: a for a in (self.term.merge if isinstance(self.term, MergeTerm) else [])}
        created = {a.name: a for a in [with_query_for(name) for name in property_paths]}
        queries = list({**created, **existing}.values())
        return queries

    def rewrite_for_ancestors_descendants(self) -> Part:
        """
        This function rewrites this part if predicates in the "magic" sections ancestors or descendants are used.
        Intention: a merge is performed by traversing the graph either inbound (ancestors) or outbound (descendants).

        Important: the merge node is found by kind only! The first matching node with correct type is merged with
        this node. The filter then is applied _after_ the node has been merged. So the filter can effectively
        filter the current node, based on properties of the merged node.

        The ancestors or descendants predicate has this form and will create a merge query:
        ancestors.<kind>.<path.to.prop> creates a merge query: {ancestors.<kind> <-[0:]- is(<kind>)}
        descendants.<kind>.<path.to.prop> creates a merge query: {descendants.<kind> -[0:]-> is(<kind>)}

        The query is rewritten in order to create a prefilter with all terms that do not depend on the merge.
        A MergeTerm is either created if not existent or the existing one will be extended with all merge query
        additions. All merge relevant parts will be performed as merge term post filter.
        Even if the query is rewritten, the logic of the query is not changed and stays the same.

        :return: the rewritten part with resolved merge parts if ancestor or descendant predicates are found.
        """
        before_merge: Term = AllTerm()
        after_merge: Term = AllTerm()

        def has_ancestor_descendant(t: Term) -> bool:
            return t.find_term(lambda trm: isinstance(trm, Predicate) and is_ancestor_descendant(trm.name)) is not None

        def ancestor_descendant_predicates(t: Term) -> List[Predicate]:
            return t.find_terms(lambda t: isinstance(t, Predicate) and is_ancestor_descendant(t.name), in_context_term=False)  # type: ignore # noqa: E501

        def walk_term(term: Term) -> None:
            # precondition: this method is only called with a term that has ancestor/descendant
            nonlocal before_merge
            nonlocal after_merge
            if isinstance(term, CombinedTerm):
                left_has_ad = has_ancestor_descendant(term.left)
                right_has_ad = has_ancestor_descendant(term.right)
                if term.op == "or":
                    after_merge = after_merge & term
                elif left_has_ad and right_has_ad:
                    walk_term(term.left)
                    walk_term(term.right)
                elif left_has_ad:
                    before_merge = before_merge & term.right
                    walk_term(term.left)
                elif right_has_ad:
                    before_merge = before_merge & term.left
                    walk_term(term.right)
                else:
                    raise NotImplementedError("Logic unsound. This case should not happen!")
            elif isinstance(term, MergeTerm):
                # in case pre- and post- filter are defined, handle it as AND combined term
                # background: pre- and post- filter will be applied on the result
                #             that effectively reflects an and combination.
                #             The merge part only merges data to the existing values.
                if term.post_filter:
                    walk_term(CombinedTerm(term.pre_filter, "and", term.post_filter))
                else:
                    walk_term(term.pre_filter)
            else:
                after_merge = after_merge & term

        if has_ancestor_descendant(self.term):
            walk_term(self.term)
            # Create a dict here instead of a set only to ensure ordering (dict remembers order, set is not)'b
            queries = self.merge_queries_for({p.name: 1 for p in ancestor_descendant_predicates(after_merge)})
            return evolve(self, term=MergeTerm(before_merge, queries, after_merge))
        else:
            return self

    @property
    def visible_predicates(self) -> List[Predicate]:
        result: List[Predicate] = self.term.find_terms(lambda x: isinstance(x, Predicate), in_context_term=False)  # type: ignore # noqa: E501
        for ctx in self.term.find_terms(lambda x: isinstance(x, ContextTerm)):
            result.extend(ctx.visible_predicates())  # type: ignore
        return result


@define(order=True, hash=True, frozen=True)
class AggregateVariableName:
    name: str

    def __str__(self) -> str:
        return self.name

    def change_variable(self, fn: Callable[[str], str]) -> AggregateVariableName:
        return AggregateVariableName(fn(self.name))


@define(order=True, hash=True, frozen=True)
class AggregateVariableCombined:
    parts: List[Union[str, AggregateVariableName]]

    def __str__(self) -> str:
        combined = "".join(p if isinstance(p, str) else f"{{{p}}}" for p in self.parts)
        return f'"{combined}"'

    def change_variable(self, fn: Callable[[str], str]) -> AggregateVariableCombined:
        return AggregateVariableCombined(
            [p.change_variable(fn) if isinstance(p, AggregateVariableName) else p for p in self.parts]
        )


@define(order=True, hash=True, frozen=True)
class AggregateVariable:
    # name is either a simple variable name or some combination of strings and variables like "foo_{var1}_{var2}_bla"
    name: Union[AggregateVariableName, AggregateVariableCombined]
    as_name: Optional[str] = None

    def __str__(self) -> str:
        with_as = f" as {self.as_name}" if self.as_name else ""
        return f"{self.name}{with_as}"

    def get_as_name(self) -> str:
        def from_name() -> str:
            return self.name.name.rsplit(".", 1)[-1] if isinstance(self.name, AggregateVariableName) else str(self.name)

        return self.as_name if self.as_name else from_name()

    def change_variable(self, fn: Callable[[str], str]) -> AggregateVariable:
        return evolve(self, name=self.name.change_variable(fn))

    def property_paths(self) -> Set[str]:
        if isinstance(self.name, AggregateVariableName):
            return {self.name.name}
        else:
            return {name.name for name in self.name.parts if isinstance(name, AggregateVariableName)}


@define(order=True, hash=True, frozen=True)
class AggregateFunction:
    function: str
    name: Union[str, int]
    ops: List[Tuple[str, Union[int, float]]] = field(factory=list)
    as_name: Optional[str] = None

    def __str__(self) -> str:
        with_as = f" as {self.as_name}" if self.as_name else ""
        with_ops = " " + self.combined_ops() if self.ops else ""
        return f"{self.function}({self.name}{with_ops}){with_as}"

    def combined_ops(self) -> str:
        return " ".join(f"{op} {value}" for op, value in self.ops)

    def get_as_name(self) -> str:
        return self.as_name if self.as_name else f"{self.function}_of_{self.name}"

    def change_variable(self, fn: Callable[[str], str]) -> AggregateFunction:
        return evolve(self, name=fn(self.name)) if isinstance(self.name, str) else self

    def property_paths(self) -> Set[str]:
        return {self.name} if isinstance(self.name, str) else set()


@define(order=True, hash=True, frozen=True)
class Aggregate:
    group_by: List[AggregateVariable]
    group_func: List[AggregateFunction]

    def __str__(self) -> str:
        grouped = ", ".join(str(a) for a in self.group_by) + ": " if self.group_by else ""
        funcs = ", ".join(str(a) for a in self.group_func)
        return f"aggregate({grouped}{funcs})"

    def change_variable(self, fn: Callable[[str], str]) -> Aggregate:
        return Aggregate(
            [a.change_variable(fn) for a in self.group_by], [a.change_variable(fn) for a in self.group_func]
        )

    def property_paths(self) -> Set[str]:
        result = set()
        for agg in chain(self.group_by, self.group_func):
            result.update(agg.property_paths())  # type: ignore
        return result


SimpleValue = Union[str, int, float, bool]


class SortOrder:
    Asc = "asc"
    Desc = "desc"

    all = [Asc, Desc]

    @classmethod
    def reverse(cls, order: str) -> str:
        return cls.Asc if order == cls.Desc else cls.Desc


@define(order=True, hash=True, frozen=True)
class Sort:
    name: str
    order: str = SortOrder.Asc

    def __str__(self) -> str:
        return f"{self.name} {self.order}"

    def change_variable(self, fn: Callable[[str], str]) -> Sort:
        return evolve(self, name=fn(self.name))

    def reversed(self) -> Sort:
        return Sort(self.name, SortOrder.Asc if self.order == SortOrder.Desc else SortOrder.Desc)


@define(order=True, hash=True, frozen=True, slots=False)
class Query:
    parts: List[Part]
    preamble: Dict[str, SimpleValue] = field(factory=dict)
    aggregate: Optional[Aggregate] = None

    def __attrs_post_init__(self) -> None:
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

    @cached_property
    def merge_names(self) -> Set[str]:
        return {mt.name for part in self.parts if isinstance(part.term, MergeTerm) for mt in part.term.merge}

    @cached_property
    def merge_query_by_name(self) -> List[MergeQuery]:
        return [mt for part in self.parts if isinstance(part.term, MergeTerm) for mt in part.term.merge]

    def filter(self, term: Union[str, Term], *terms: Union[str, Term]) -> Query:
        res = Query.mk_term(term, *terms)
        parts = self.parts.copy()
        first_part = parts[0]
        if first_part.navigation is None:
            # just add the filter to this query
            parts[0] = Part(CombinedTerm(first_part.term, "and", res))
        else:
            # put to the start
            parts.insert(0, Part(res))
        return evolve(self, parts=parts)

    def filter_with(self, clause: WithClause) -> Query:
        first_part = evolve(self.parts[0], with_clause=clause)
        return evolve(self, parts=[first_part, *self.parts[1:]])

    def traverse_out(self, start: int = 1, until: int = 1, edge_type: EdgeType = EdgeTypes.default) -> Query:
        return self.traverse(start, until, edge_type, Direction.outbound)

    def traverse_in(self, start: int = 1, until: int = 1, edge_type: EdgeType = EdgeTypes.default) -> Query:
        return self.traverse(start, until, edge_type, Direction.inbound)

    def traverse_inout(self, start: int = 1, until: int = 1, edge_type: EdgeType = EdgeTypes.default) -> Query:
        return self.traverse(start, until, edge_type, Direction.any)

    def traverse(
        self, start: int, until: int, edge_type: EdgeType = EdgeTypes.default, direction: str = Direction.outbound
    ) -> Query:
        parts = self.parts.copy()
        p0 = parts[0]
        if p0.navigation:
            # we already traverse in this direction: add start and until
            if edge_type in p0.navigation.edge_types and p0.navigation.direction == direction:
                start_m = min(Navigation.Max, start + p0.navigation.start)
                until_m = min(Navigation.Max, until + p0.navigation.until)
                parts[0] = evolve(p0, navigation=evolve(p0.navigation, start=start_m, until=until_m))
            # this is another traversal: so we need to start a new part
            else:
                parts.insert(0, Part(AllTerm(), navigation=Navigation(start, until, [edge_type], direction)))
        else:
            parts[0] = evolve(p0, navigation=Navigation(start, until, [edge_type], direction))
        return evolve(self, parts=parts)

    def group_by(self, variables: List[AggregateVariable], funcs: List[AggregateFunction]) -> Query:
        aggregate = Aggregate(variables, funcs)
        return evolve(self, aggregate=aggregate)

    def set_sort(self, *sort: Sort) -> Query:
        return self.__change_current_part(lambda p: evolve(p, sort=list(sort)))

    def add_sort(self, *sort: Sort) -> Query:
        return self.__change_current_part(lambda p: evolve(p, sort=[*p.sort, *sort]))

    def with_limit(self, num: Union[Limit, int]) -> Query:
        limit = num if isinstance(num, Limit) else Limit(0, num)
        return self.__change_current_part(lambda p: evolve(p, limit=limit))

    def merge_preamble(self, preamble: Dict[str, SimpleValue]) -> Query:
        updated = {**self.preamble, **preamble} if self.preamble else preamble
        return evolve(self, preamble=updated)

    def merge_with(self, path: str, navigation: Navigation, term: Term) -> Query:
        parts = self.parts.copy()
        first_part = parts[0]
        merge = MergeQuery(path, Query([Part(term), Part(AllTerm(), navigation=navigation)]))
        term = (
            evolve(first_part.term, merge=[*first_part.term.merge, merge])
            if isinstance(first_part.term, MergeTerm)
            else MergeTerm(first_part.term, [merge])
        )
        parts[0] = evolve(first_part, term=term)
        return evolve(self, parts=parts)

    def change_variable(self, fn: Callable[[str], str]) -> Query:
        aggregate = self.aggregate.change_variable(fn) if self.aggregate else None
        parts = [p.change_variable(fn) for p in self.parts]
        return evolve(self, aggregate=aggregate, parts=parts)

    def rewrite_for_ancestors_descendants(self, additional_paths_to_select: Optional[Iterable[str]] = None) -> Query:
        def rewrite_for_additional_paths(parts: List[Part]) -> None:
            paths: Set[str] = self.aggregate.property_paths() if self.aggregate else set()
            paths.update(additional_paths_to_select or set())
            anc_desc = {path: 1 for path in paths if is_ancestor_descendant(path)}
            if anc_desc:
                current = parts[0]
                queries = current.merge_queries_for(anc_desc)
                merge_term = (
                    MergeTerm(current.term.pre_filter, queries, current.term.post_filter)
                    if isinstance(current.term, MergeTerm)
                    else MergeTerm(current.term, queries)
                )
                parts[0] = evolve(current, term=merge_term)

        adapted = [part.rewrite_for_ancestors_descendants() for part in self.parts]
        if self.aggregate or additional_paths_to_select:
            rewrite_for_additional_paths(adapted)
        return evolve(self, parts=adapted)

    def on_section(self, section: Optional[str] = PathRoot) -> Query:
        root_or_section = None if section is None or section == PathRoot else section
        absolute_section = self.change_variable(partial(variable_to_absolute, root_or_section))
        return absolute_section.rewrite_for_ancestors_descendants()

    def relative_to_section(self, section: str) -> Query:
        return self.change_variable(partial(variable_to_relative, section)) if section != PathRoot else self

    def tag(self, name: str) -> Query:
        return self.__change_current_part(lambda p: evolve(p, tag=name))

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
        return evolve(self, parts=parts)

    def combine(self, other: Query) -> Query:
        preamble = {**self.preamble, **other.preamble}
        if self.aggregate and other.aggregate:
            raise AttributeError("Can not combine 2 aggregations!")
        aggregate = self.aggregate if self.aggregate else other.aggregate
        left_last = self.parts[0]
        right_first = other.parts[-1]

        def combine_limit(left: Limit, right: Limit) -> Limit:
            return Limit(max(left.offset, right.offset), min(left.length, right.length))

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
            limit = combine_optional(left_last.limit, right_first.limit, combine_limit)
            combined = Part(term, tag, with_clause, sort if sort else [], limit, right_first.navigation)
            parts = [*other.parts[0:-1], combined, *self.parts[1:]]
        return Query(parts, preamble, aggregate)

    @property
    def visible_predicates(self) -> List[Predicate]:
        """
        Returns a list of all predicates in this query.
        """
        return [pred for part in self.parts for pred in part.visible_predicates]

    def find_terms(self, fn: Callable[[Term], bool], **kwargs: bool) -> List[Term]:
        return [t for p in self.parts for t in p.term.find_terms(fn, **kwargs)]

    def analytics(self) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
        counters: Dict[str, int] = defaultdict(lambda: 0)
        names: Dict[str, List[str]] = defaultdict(list)

        def term_analytics(term: Term) -> None:
            name = type(term).__name__
            counters[f"term_{name.lower()}"] += 1
            if isinstance(term, Predicate):
                counters[f"op_{term.op}"] += 1
                names["predicate_names"].append(term.name)
            elif isinstance(term, CombinedTerm):
                term_analytics(term.left)
                term_analytics(term.right)

        def with_clause_analytics(clause: WithClause) -> None:
            counters["with_clause"] += 1
            if clause.term:
                term_analytics(clause.term)
            if clause.navigation:
                navigation_analytics(clause.navigation)
            if clause.with_clause:
                with_clause_analytics(clause.with_clause)

        def navigation_analytics(navigation: Navigation) -> None:
            counters["navigation"] += 1
            counters[f"navigation_{navigation.direction}"] += 1
            counters[f"navigation_{navigation.edge_types}"] += 1
            counters["navigation_until_max"] = max(counters["navigation_until_max"], navigation.until)

        def is_ancestor_merge(q: Query) -> bool:
            return (
                len(q.parts) == 2
                and q.aggregate is None
                and q.parts[1].navigation is not None
                and q.parts[1].navigation.direction == "in"
                and q.parts[1].navigation.until > 1
                and isinstance(q.parts[0].term, IsTerm)
            )

        def query_analytics(q: Query) -> None:
            if q.preamble:
                names["preamble_keys"].extend(q.preamble.keys())
            if q.aggregate:
                if q.aggregate.group_by:
                    names["aggregate_by"].extend(str(gb.name) for gb in q.aggregate.group_by)
                    counters["aggregate_by"] += len(q.aggregate.group_by)
                if q.aggregate.group_func:
                    names["aggregate_func"].extend(str(gb.name) for gb in q.aggregate.group_func)
                    counters["aggregate_func"] += len(q.aggregate.group_func)
            for part in q.parts:
                if isinstance(part.term, MergeTerm):
                    term_analytics(part.term.pre_filter)
                    counters["merge_terms"] += 1
                    for merge in part.term.merge:
                        names["merge_names"].append(merge.name)
                        counter_name = "merge_ancestors_by_kind" if is_ancestor_merge(merge.query) else "merge_other"
                        query_analytics(merge.query)
                        counters[counter_name] += 1
                    if part.term.post_filter:
                        term_analytics(part.term.post_filter)
                else:
                    term_analytics(part.term)
                if part.limit:
                    counters["limits"] += 1
                if part.sort:
                    counters["sorts"] += 1
                    names["sort_names"].extend(sort.name for sort in part.sort)
                if part.navigation:
                    navigation_analytics(part.navigation)
                if part.with_clause:
                    with_clause_analytics(part.with_clause)

        query_analytics(self)

        return counters, names

    @staticmethod
    def mk_term(term: Union[str, Term], *args: Union[str, Term]) -> Term:
        def make_term(t: Union[str, Term]) -> Term:
            if isinstance(t, Term):
                return t
            elif isinstance(t, str):
                return IsTerm([t])
            else:
                raise AttributeError(f"Expected term or string, but got {t}")

        term_in = list(args)
        term_in.insert(0, term)
        terms = map(make_term, term_in)
        # noinspection PyTypeChecker
        return reduce(lambda l, r: CombinedTerm(l, "and", r), terms)


# register serializer for this class
set_deserializer(Term.from_json, Term)
