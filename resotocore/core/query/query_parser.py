from dataclasses import replace
from functools import reduce
from typing import List

import parsy
from parsy import string, Parser, regex

from core.error import ParseError
from core.model.graph_access import EdgeType, Direction
from core.parse_util import (
    lparen_p,
    lexeme,
    rparen_p,
    l_bracket_p,
    r_bracket_p,
    colon_p,
    comma_p,
    equals_p,
    true_p,
    false_p,
    dot_dot_p,
    float_p,
    integer_dp,
    variable_dp,
    literal_p,
    make_parser,
    whitespace,
    quoted_string_p,
    space_dp,
    json_value_p,
    variable_p,
    variable_no_array_p,
    integer_p,
    double_quote_dp,
    l_curly_dp,
    r_curly_dp,
    l_curly_p,
    r_curly_p,
)
from core.query.model import (
    Predicate,
    CombinedTerm,
    IsTerm,
    Part,
    Navigation,
    Query,
    FunctionTerm,
    IdTerm,
    AggregateVariable,
    AggregateFunction,
    Aggregate,
    AllTerm,
    Sort,
    SortOrder,
    WithClauseFilter,
    WithClause,
    AggregateVariableName,
    AggregateVariableCombined,
    NotTerm,
    MergeTerm,
    MergeQuery,
)

operation_p = (
    reduce(
        lambda x, y: x | y, [lexeme(string(a)) for a in ["<=", ">=", ">", "<", "==", "!=", "=~", "!~", "in", "not in"]]
    )
    | lexeme(string("=")).result("==")
    | lexeme(string("~")).result("=~")
)

array_modifier_p = reduce(lambda x, y: x | y, [lexeme(string(a)) for a in ["all", "any", "none"]])

function_p = reduce(lambda x, y: x | y, [lexeme(string(a)) for a in ["in_subnet", "has_desired_change", "has_key"]])


preamble_prop_p = reduce(lambda x, y: x | y, [lexeme(string(a)) for a in ["edge_type", "merge_with_ancestors"]])


@make_parser
def predicate_term() -> Parser:
    name = yield variable_p
    modifier = yield array_modifier_p.optional()
    opts = {"filter": modifier} if modifier else {}
    op = yield operation_p
    value = yield json_value_p
    return Predicate(name, op, value, opts)


@make_parser
def function_term() -> Parser:
    fn = yield function_p
    yield lparen_p
    name = yield variable_p
    args = yield (comma_p >> json_value_p).many()
    yield rparen_p
    return FunctionTerm(fn, name, args)


@make_parser
def not_term() -> Parser:
    yield not_p
    yield lparen_p
    term = yield simple_term_p
    yield rparen_p
    return NotTerm(term)


literal_list_comma_separated_p = (quoted_string_p | literal_p).sep_by(comma_p, min=1)
literal_list_in_square_brackets = l_bracket_p >> literal_list_comma_separated_p << r_bracket_p
literal_list_optional_brackets = literal_list_in_square_brackets | literal_list_comma_separated_p
is_term = lexeme(string("is") >> lparen_p >> literal_list_optional_brackets << rparen_p).map(IsTerm)
id_term = lexeme(string("id") >> lparen_p >> (quoted_string_p | literal_p) << rparen_p).map(IdTerm)
match_all_term = lexeme(string("all")).map(lambda _: AllTerm())
leaf_term_p = is_term | id_term | match_all_term | function_term | predicate_term | not_term
bool_op_p = lexeme(string("and") | string("or"))
not_p = lexeme(string("not"))


@make_parser
def combined_term() -> Parser:
    left = yield simple_term_p
    result = left
    while True:
        op = yield bool_op_p.optional()
        if op is None:
            break
        right = yield simple_term_p
        result = CombinedTerm(result, op, right)
    return result


simple_term_p = (lparen_p >> combined_term << rparen_p) | leaf_term_p

# This can parse a complete term
filter_term_parser = combined_term | simple_term_p


square_brackets_p = lexeme(string("[]"))


@make_parser
def merge_query_parser() -> Parser:
    name = yield variable_no_array_p
    is_array = yield square_brackets_p.optional()

    yield colon_p
    query = yield query_parser
    return MergeQuery(name, query, not (query.aggregate or is_array))


@make_parser
def merge_parser() -> Parser:
    yield l_curly_p
    queries = yield merge_query_parser.sep_by(comma_p, min=1)
    yield r_curly_p
    return queries


@make_parser
def term_parser() -> Parser:
    filter_term = yield filter_term_parser
    merge = yield merge_parser.optional()
    if merge:
        post_filter = yield filter_term_parser.optional()
        return MergeTerm(filter_term, merge, post_filter)
    else:
        return filter_term


@make_parser
def range_parser() -> Parser:
    yield l_bracket_p
    start = yield integer_p
    has_end = yield (colon_p | comma_p | dot_dot_p).optional()
    maybe_end = yield integer_p.optional()
    yield r_bracket_p
    end = start if has_end is None else maybe_end if maybe_end is not None else Navigation.Max
    return start, end


edge_type_p = lexeme(regex("[A-Za-z][A-Za-z0-9_]*"))


@make_parser
def edge_type_parser() -> Parser:
    edge_types = yield edge_type_p.sep_by(comma_p).map(set)
    edge_types = EdgeType.all if "all" in edge_types else edge_types
    for et in edge_types:
        if et not in EdgeType.all:
            raise AttributeError(f"Given EdgeType is not known: {et}")
    return list(edge_types)


@make_parser
def edge_definition_parser() -> Parser:
    edge_types = yield edge_type_parser
    maybe_range = yield range_parser.optional()
    start, until = maybe_range if maybe_range else (1, 1)
    return start, until, edge_types


@make_parser
def two_directional_edge_definition_parser() -> Parser:
    start, until, edge_types = yield edge_definition_parser
    outbound_edge_types = yield edge_type_parser
    return start, until, edge_types, outbound_edge_types


out_p = lexeme(string("-") >> edge_definition_parser << string("->")).map(
    lambda nav: Navigation(nav[0], nav[1], nav[2], Direction.outbound)
)
in_p = lexeme(string("<-") >> edge_definition_parser << string("-")).map(
    lambda nav: Navigation(nav[0], nav[1], nav[2], Direction.inbound)
)
in_out_p = lexeme(string("<-") >> two_directional_edge_definition_parser << string("->")).map(
    lambda nav: Navigation(nav[0], nav[1], nav[2], Direction.any, nav[3])
)
navigation_parser = in_out_p | out_p | in_p

tag_parser = lexeme(string("#") >> literal_p).optional()
with_p = lexeme(string("with"))
count_p = lexeme(string("count"))

len_empty = lexeme(string("empty")).result(WithClauseFilter("==", 0))
len_any = lexeme(string("any")).result(WithClauseFilter(">", 0))


@make_parser
def with_count_parser() -> Parser:
    yield count_p
    op = yield operation_p
    num = yield integer_p
    return WithClauseFilter(op, num)


@make_parser
def with_clause_parser() -> Parser:
    yield with_p
    yield lparen_p
    with_filter = yield len_empty | len_any | with_count_parser
    yield comma_p
    nav = yield navigation_parser
    term = yield filter_term_parser.optional()
    with_clause = yield with_clause_parser.optional()
    yield rparen_p
    assert 0 <= nav.start <= 1, "with traversal need to start from 0 or 1"
    return WithClause(with_filter, nav, term, with_clause)


sort_order_p = string("asc") | string("desc")
sort_dp = string("sort")


@make_parser
def single_sort_arg_parser() -> Parser:
    name = yield variable_dp
    order = yield (space_dp >> sort_order_p).optional()
    return Sort(name, order if order else SortOrder.Asc)


@make_parser
def sort_parser() -> Parser:
    yield sort_dp
    yield space_dp
    attributes = yield single_sort_arg_parser.sep_by(comma_p, min=1)
    yield whitespace
    return attributes


limit_p = string("limit")
limit_parser = limit_p + space_dp >> integer_dp


@make_parser
def part_parser() -> Parser:
    term = yield term_parser.optional()
    yield whitespace
    with_clause = yield with_clause_parser.optional()
    tag = yield tag_parser
    sort = yield sort_parser.optional()
    limit = yield limit_parser.optional()
    nav = yield navigation_parser.optional() if term or sort or limit else navigation_parser
    term = term if term else AllTerm()
    return Part(term, tag, with_clause, sort if sort else [], limit, nav)


@make_parser
def key_value_preamble_parser() -> Parser:
    key = yield preamble_prop_p
    yield equals_p
    value = yield quoted_string_p | true_p | false_p | float_p | integer_p | literal_p
    return key, value


@make_parser
def preamble_tags_parser() -> Parser:
    yield lparen_p
    key_values = yield key_value_preamble_parser.sep_by(comma_p)
    yield rparen_p
    return dict(key_values)


as_p = lexeme(string("as"))
aggregate_p = lexeme(string("aggregate"))
aggregate_func_p = reduce(lambda x, y: x | y, [lexeme(string(a)) for a in ["sum", "count", "min", "max", "avg"]])
match_p = lexeme(string("match"))
aggregate_variable_name_p = variable_p.map(AggregateVariableName)
no_curly_dp = regex(r'[^{"]+')
var_in_curly = (l_curly_dp >> variable_p << r_curly_dp).map(AggregateVariableName)
aggregate_group_variable_name_combined_p = (
    double_quote_dp >> (no_curly_dp | var_in_curly).at_least(1).map(AggregateVariableCombined) << double_quote_dp
)


@make_parser
def aggregate_group_variable_parser() -> Parser:
    name = yield aggregate_variable_name_p | aggregate_group_variable_name_combined_p
    as_name = yield (as_p >> literal_p).optional()
    return AggregateVariable(name, as_name)


@make_parser
def merge_ancestors_parser() -> Parser:
    # parses foo as bla -> "foo", "bla"
    # parses foo        -> "foo", "foo"
    name = yield variable_p
    as_name = yield (as_p >> literal_p).optional()
    return name, as_name if as_name else name


math_op_p = reduce(lambda x, y: x | y, [lexeme(string(a)) for a in ["+", "-", "*", "/", "%"]])


@make_parser
def op_with_val_parser() -> Parser:
    op = yield math_op_p
    value = yield float_p | integer_p
    return op, value


@make_parser
def aggregate_group_function_parser() -> Parser:
    func = yield aggregate_func_p
    yield lparen_p
    term_or_int = yield variable_p | integer_p
    ops_list = yield op_with_val_parser.many()
    yield rparen_p
    with_as = yield as_p.optional()
    as_name = None
    if with_as:
        as_name = yield literal_p
    return AggregateFunction(func, term_or_int, ops_list, as_name)


@make_parser
def aggregate_parameter_parser() -> Parser:
    group_vars = yield (aggregate_group_variable_parser.sep_by(comma_p, min=1) << colon_p).optional()
    group_function_vars = yield aggregate_group_function_parser.sep_by(comma_p, min=1)
    return group_vars if group_vars else [], group_function_vars


@make_parser
def aggregate_parser() -> Parser:
    yield aggregate_p
    yield lparen_p
    group_vars, group_function_vars = yield aggregate_parameter_parser
    yield rparen_p
    return Aggregate(group_vars, group_function_vars)


@make_parser
def preamble_parser() -> Parser:
    maybe_aggregate = yield aggregate_parser.optional()
    maybe_preamble = yield preamble_tags_parser.optional()
    preamble = maybe_preamble if maybe_preamble else {}
    yield colon_p if maybe_aggregate or maybe_preamble else colon_p.optional()
    return maybe_aggregate, preamble


@make_parser
def query_parser() -> Parser:
    maybe_aggregate, preamble = yield preamble_parser
    parts = yield part_parser.at_least(1)
    return Query(parts[::-1], preamble, maybe_aggregate)


def parse_query(query: str, **env: str) -> Query:
    def set_edge_type_if_not_set(part: Part, edge_types: List[str]) -> Part:
        def set_in_with_clause(wc: WithClause) -> WithClause:
            nav = wc.navigation
            if wc.navigation and not wc.navigation.maybe_edge_types:
                nav = replace(nav, maybe_edge_types=edge_types)
            inner = set_in_with_clause(wc.with_clause) if wc.with_clause else wc.with_clause
            return replace(wc, navigation=nav, with_clause=inner)

        nav = part.navigation
        if part.navigation and not part.navigation.maybe_edge_types:
            nav = replace(nav, maybe_edge_types=edge_types)
        adapted_wc = set_in_with_clause(part.with_clause) if part.with_clause else part.with_clause
        return replace(part, navigation=nav, with_clause=adapted_wc)

    try:
        parsed: Query = query_parser.parse(query.strip())
        pre = parsed.preamble
        ets: List[str] = pre.get("edge_type", env.get("edge_type", EdgeType.default)).split(",")  # type: ignore
        for et in ets:
            if et not in EdgeType.all:
                raise AttributeError(f"Given edge_type {et} is not available. Use one of {EdgeType.all}")

        adapted = [set_edge_type_if_not_set(part, ets) for part in parsed.parts]
        # remove values from preamble, that are only used at parsing time
        preamble = parsed.preamble.copy()
        preamble.pop("edge_type", None)
        return Query(adapted, preamble, parsed.aggregate)
    except parsy.ParseError as ex:
        raise ParseError(f"Can not parse query: {query}\n" + str(ex)) from ex
