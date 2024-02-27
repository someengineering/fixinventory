from hypothesis.strategies import (
    composite,
    SearchStrategy,
    lists,
    sampled_from,
    builds,
    just,
    integers,
    booleans,
    tuples,
)

from fixcore.model.graph_access import EdgeTypes, Direction
from tests.fixcore.hypothesis_extension import Drawer, optional, UD, any_string, any_datetime
from fixcore.query.model import (
    IsTerm,
    Predicate,
    Term,
    Part,
    Query,
    CombinedTerm,
    Navigation,
    WithClause,
    WithClauseFilter,
    SortOrder,
    Sort,
    MergeTerm,
    MergeQuery,
    AllTerm,
    Aggregate,
    AggregateVariableName,
    AggregateVariableCombined,
    AggregateVariable,
    AggregateFunction,
    Limit,
    WithUsage,
)


query_property = sampled_from(["reported.name", "reported.cpu_count"])
kind = sampled_from(["bucket", "volume", "certificate", "cloud", "database", "endpoint"])
query_operations = sampled_from(["==", ">=", "<=", ">", "<"])
query_values = sampled_from(["test", 23, True, False, None])
combine_term = sampled_from(["and", "or"])
edge_direction = sampled_from(list(Direction.all))
edge_type = sampled_from(list(EdgeTypes.all))
sort_order = sampled_from([SortOrder.Asc, SortOrder.Desc])
aggregate_functions = sampled_from(["sum", "count", "min", "max", "avg"])
is_term = builds(IsTerm, lists(kind, min_size=1, max_size=2))
predicate_term = builds(Predicate, query_property, query_operations, query_values, just({}))
leaf_term: SearchStrategy[Term] = is_term | predicate_term
limit_gen = builds(Limit, integers(min_value=0), integers(min_value=1))


@composite
def composite_term(ud: UD) -> CombinedTerm:
    d = Drawer(ud)
    trm = leaf_term | composite_term()
    return CombinedTerm(d.draw(trm), d.draw(combine_term), d.draw(trm))


term: SearchStrategy[Term] = leaf_term | composite_term()
sort = builds(Sort, query_property, sort_order)


@composite
def merge_term(ud: UD) -> MergeTerm:
    d = Drawer(ud)
    pre = d.draw(term)
    queries = d.draw(lists(merge_query, min_size=1, max_size=1))
    pst = d.optional(term)
    return MergeTerm(pre, queries, pst)


@composite
def navigation(ud: UD) -> Navigation:
    d = Drawer(ud)
    start = d.draw(integers(min_value=0, max_value=1))
    length = d.draw(integers(min_value=0, max_value=100))
    ed = d.draw(edge_type)
    direction = d.draw(edge_direction)
    return Navigation(start, length + start, [ed], direction)


@composite
def with_clause(ud: UD) -> WithClause:
    d = Drawer(ud)
    op = d.draw(query_operations)
    num = d.draw(integers(min_value=0))
    nav = d.draw(navigation())
    trm = d.optional(term)
    wc = d.optional(with_clause())
    return WithClause(WithClauseFilter(op, num), nav, trm, wc)


@composite
def with_usage(ud: UD) -> WithUsage:
    d = Drawer(ud)
    start = d.draw(any_datetime)
    end = d.optional(any_datetime)
    metrics = d.draw(lists(any_string, min_size=1, max_size=3))
    return WithUsage(start, end, metrics)


part = builds(
    Part,
    term | merge_term(),
    optional(any_string),
    with_clause(),
    with_usage(),
    lists(sort, min_size=0, max_size=3),
    optional(limit_gen),
    navigation(),
)

only_filter_part = builds(
    Part, term, just(None), just(None), just(None), lists(sort, min_size=0, max_size=1), optional(limit_gen)
)


@composite
def merge_query_query(ud: UD) -> Query:
    d = Drawer(ud)
    nav = d.draw(navigation())
    trm = d.draw(term)
    # merge query need to start with navigation part without additional props
    parts = [Part(trm), Part(AllTerm(), navigation=nav)]
    return Query(parts)


merge_query = builds(MergeQuery, any_string, merge_query_query(), booleans())


@composite
def aggregate_variable_combined(ud: UD) -> AggregateVariableCombined:
    d = Drawer(ud)
    return AggregateVariableCombined([d.draw(any_string), d.draw(aggregate_variable_name), d.draw(any_string)])


aggregate_variable_name = builds(AggregateVariableName, any_string)
aggregate_variable = builds(AggregateVariable, aggregate_variable_name | aggregate_variable_combined())
aggregate_op = sampled_from(["+", "-", "*", "/"])
aggregate_function = builds(
    AggregateFunction, aggregate_functions, any_string | integers(), lists(tuples(aggregate_op, integers())), any_string
)
aggregate = builds(Aggregate, lists(aggregate_variable, min_size=1), lists(aggregate_function, min_size=1))
query = builds(
    Query,
    # test a more complex query with multiple parts and navigation or one simple part without navigation
    lists(part, min_size=1, max_size=3) | lists(only_filter_part, min_size=1, max_size=1),
    just({}),
    optional(aggregate),
)
