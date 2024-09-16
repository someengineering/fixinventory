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
    DrawFn,
)

from fixcore.model.graph_access import EdgeTypes, Direction
from tests.fixcore.hypothesis_extension import optional, any_string, any_datetime
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
    ContextTerm,
    IdTerm,
    FulltextTerm,
)


@composite
def composite_predicate_term(draw: DrawFn) -> CombinedTerm:
    trm = leaf_term | composite_predicate_term()
    return CombinedTerm(draw(trm), draw(combine_term), draw(trm))


@composite
def context_term(draw: DrawFn) -> ContextTerm:
    prop = query_property | query_arr_property
    trm = predicate_term | composite_predicate_term()
    return ContextTerm(draw(prop), draw(trm))


@composite
def composite_term(draw: DrawFn) -> CombinedTerm:
    trm = leaf_term | composite_term()
    return CombinedTerm(draw(trm), draw(combine_term), draw(trm))


query_property = sampled_from(["reported.name", "reported.cpu_count"])
query_arr_property = sampled_from(["reported.arr[*]", "reported.arr[*].inner[*]"])
kind = sampled_from(["bucket", "volume", "certificate", "cloud", "database", "endpoint"])
query_operations = sampled_from(["==", ">=", "<=", ">", "<"])
query_values = sampled_from(["test", 23, True, False, None])
combine_term = sampled_from(["and", "or"])
edge_direction = sampled_from(list(Direction.all))
edge_type = sampled_from(list(EdgeTypes.all))
sort_order = sampled_from([SortOrder.Asc, SortOrder.Desc])
aggregate_functions = sampled_from(["sum", "count", "min", "max", "avg"])
is_term = builds(IsTerm, lists(kind, min_size=1, max_size=2))
id_term = builds(IdTerm, lists(any_string, min_size=1, max_size=2))
predicate_term = builds(Predicate, query_property, query_operations, query_values, just({}))
fulltext_term = builds(FulltextTerm, any_string)
leaf_term: SearchStrategy[Term] = is_term | id_term | predicate_term | fulltext_term | context_term() | just(AllTerm())
edge_term: SearchStrategy[Term] = predicate_term | context_term() | just(AllTerm())
limit_gen = builds(Limit, integers(min_value=0), integers(min_value=1))
term: SearchStrategy[Term] = leaf_term | composite_term()
sort = builds(Sort, query_property, sort_order)


@composite
def merge_term(draw: DrawFn) -> MergeTerm:
    pre = draw(term)
    queries = draw(lists(merge_query, min_size=1, max_size=1))
    pst = draw(optional(term))
    return MergeTerm(pre, queries, pst)


@composite
def navigation(draw: DrawFn) -> Navigation:
    start = draw(integers(min_value=0, max_value=1))
    length = draw(integers(min_value=0, max_value=100))
    ed = draw(edge_type)
    direction = draw(edge_direction)
    edge_filter = draw(optional(edge_term))
    return Navigation(start, length + start, [ed], direction, edge_filter=edge_filter)


@composite
def with_clause(draw: DrawFn) -> WithClause:
    op = draw(query_operations)
    num = draw(integers(min_value=0))
    nav = draw(navigation())
    trm = draw(optional(term))
    wc = draw(optional(with_clause()))
    return WithClause(WithClauseFilter(op, num), nav, trm, wc)


@composite
def with_usage(draw: DrawFn) -> WithUsage:
    start = draw(any_datetime)
    end = draw(optional(any_datetime))
    metrics = draw(lists(any_string, min_size=1, max_size=3))
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
def merge_query_query(draw: DrawFn) -> Query:
    nav = draw(navigation())
    trm = draw(term)
    # merge query need to start with navigation part without additional props
    parts = [Part(trm), Part(AllTerm(), navigation=nav)]
    return Query(parts)


merge_query = builds(MergeQuery, any_string, merge_query_query(), booleans())


@composite
def aggregate_variable_combined(draw: DrawFn) -> AggregateVariableCombined:
    return AggregateVariableCombined([draw(any_string), draw(aggregate_variable_name), draw(any_string)])


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
