from typing import Callable, Optional, Any

import pytest

from core.query.model import Navigation, Part, Query, P, AggregateVariable, Aggregate, AggregateFunction, IsTerm, IdTerm
from core.model.graph_access import EdgeType
from parsy import Parser
from core.query.query_parser import (
    predicate_term,
    is_term,
    function_term,
    combined_term,
    term_parser,
    navigation_parser,
    part_parser,
    query_parser,
    preamble_parser,
    preamble_tags_parser,
    aggregate_group_variable_parser,
    aggregate_group_function_parser,
    aggregate_parser,
    id_term,
)


def test_parse_is_term() -> None:
    assert is_term.parse('is("test")') == IsTerm("test")
    assert is_term.parse("is(test)") == IsTerm("test")


def test_parse_id_term() -> None:
    assert id_term.parse('id("test")') == IdTerm("test")
    assert id_term.parse("id(test)") == IdTerm("test")


def test_parse_predicate() -> None:
    assert_round_trip(predicate_term, P("mem") < 23)
    assert_round_trip(predicate_term, P("simple") == "hallo")
    assert_round_trip(predicate_term, P("simple") != "hallo")
    assert_round_trip(predicate_term, P("simple").matches("^some.regex[a-d]+$"))
    assert_round_trip(predicate_term, P("simple").not_matches("^some.regex[a-d]+$"))
    assert_round_trip(predicate_term, P("num") > 23)
    assert_round_trip(predicate_term, P("num") >= 23)
    assert_round_trip(predicate_term, P("num") == 23)
    assert_round_trip(predicate_term, P("num") <= 23)
    assert_round_trip(predicate_term, P("num") < 23)
    assert_round_trip(predicate_term, P("num").is_in([1, 2, 5]))
    assert_round_trip(predicate_term, P("num").is_not_in([1, 2, 5]))


# noinspection PyTypeChecker
def test_parse_predicate_array() -> None:
    # TODO: array params are not working
    assert_round_trip(predicate_term, P.array("mem").for_any() < 23)


def test_kind() -> None:
    assert_round_trip(is_term, P.of_kind("foo"))


# noinspection PyTypeChecker
def test_function() -> None:
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", 1, "2", True))
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", "in_subnet"))
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", "in_subnet", "1000"))


# noinspection PyTypeChecker
def test_combined() -> None:
    assert_round_trip(combined_term, P.of_kind("foo") | P.of_kind("bla"))


def test_term() -> None:
    assert_round_trip(term_parser, P("mem") < 23)
    assert_round_trip(term_parser, P.with_id("foo"))
    assert_round_trip(term_parser, P.of_kind("foo"))
    assert_round_trip(term_parser, P.of_kind("foo") | P.of_kind("bla"))
    assert_round_trip(term_parser, ((P.of_kind("foo") | P.of_kind("bla")) & (P("a") > 23)) & (P("b") <= 12))


def test_navigation_default() -> None:
    assert str(Navigation(1, 1)) == "-->"
    assert str(Navigation(1, Navigation.Max)) == "-[1:]->"


def test_navigation() -> None:
    def make_default(nav: Navigation) -> Navigation:
        return Navigation(nav.start, nav.until, EdgeType.default, nav.direction)

    for edge_type in EdgeType.allowed_edge_types:
        # the default edge type is not rendered, so we set it explicitly to make the mapping homogeneous
        fn = make_default if edge_type == EdgeType.default else None
        for direction in ["in", "out", "inout"]:
            for start, until in [(0, 0), (1, 1), (5, 5), (1, 10), (1, Navigation.Max), (10, Navigation.Max)]:
                assert_round_trip(navigation_parser, Navigation(start, until, edge_type, direction), fn)


# noinspection PyTypeChecker
def test_part() -> None:
    assert_round_trip(part_parser, Part(P.of_kind("test")))
    assert_round_trip(part_parser, Part(P.of_kind("test"), False, Navigation(1, 10, EdgeType.delete)))
    assert_round_trip(part_parser, Part(P.of_kind("test"), True, Navigation(1, 10, EdgeType.delete)))


def test_query() -> None:
    query = (
        Query.by("ec2", P("cpu") > 4, (P("mem") < 23) | (P("mem") < 59), preamble={"edge_type": EdgeType.default})
        .traverse_out()
        .filter(P("some.int.value") < 1, P("some.other") == 23)
        .traverse_out()
        .filter(P("active") == 12, P.function("in_subnet").on("ip", "1.2.3.4/96"))
        .group_by([AggregateVariable("foo")], [AggregateFunction("sum", "cpu")])
    )
    assert_round_trip(query_parser, query)


def test_query_with_preamble() -> None:
    query_parser.parse('id("root")')  # no preamble
    query_parser.parse('match: id("root")')  # match preamble
    query_parser.parse('match(): id("root")')  # match preamble
    query = query_parser.parse('(edge_type=delete): id("root") -[0:1]->')
    assert query.parts[0].navigation.edge_type == "delete"
    query = query_parser.parse('aggregate(region: sum(cpu))(edge_type=delete): id("root") -[0:1]->')
    assert query.aggregate.group_by[0].name == "region"
    assert query.aggregate.group_func[0].name == "cpu"


def test_preamble_tags() -> None:
    assert preamble_tags_parser.parse("(edge_type=foo)") == {"edge_type": "foo"}
    assert preamble_tags_parser.parse("(edge_type=23)") == {"edge_type": 23}
    assert preamble_tags_parser.parse("(edge_type=23.123)") == {"edge_type": 23.123}
    assert preamble_tags_parser.parse("(edge_type=true)") == {"edge_type": True}
    assert preamble_tags_parser.parse("(edge_type=false)") == {"edge_type": False}
    assert preamble_tags_parser.parse('(edge_type="!@#*(&$({{:::")') == {"edge_type": "!@#*(&$({{:::"}
    assert preamble_parser.parse("") == (None, {})


def test_aggregate_group_variable() -> None:
    foo = aggregate_group_variable_parser.parse("foo")
    assert foo.name == "foo"
    assert foo.as_name is None
    bla = aggregate_group_variable_parser.parse("bla as bar")
    assert bla.name == "bla"
    assert bla.as_name == "bar"


def test_aggregate_group_function() -> None:
    foo = aggregate_group_function_parser.parse("sum(foo)")
    assert foo.function == "sum"
    assert foo.name == "foo"
    assert foo.as_name is None
    bla = aggregate_group_function_parser.parse("sum(bla) as bar")
    assert foo.function == "sum"
    assert bla.name == "bla"
    assert bla.as_name == "bar"
    boo = aggregate_group_function_parser.parse("sum(boo * 1024.12 + 1) as bar")
    assert boo.ops == [("*", 1024.12), ("+", 1)]
    with pytest.raises(Exception):
        assert aggregate_group_function_parser.parse("sum(test / 3 +)")


def test_aggregate() -> None:
    agg: Aggregate = aggregate_parser.parse("aggregate(region: sum(cpu) as cpus, count(id) as instances)")
    assert len(agg.group_by) == 1
    assert agg.group_by[0].name == "region"
    assert len(agg.group_func) == 2
    assert agg.group_func[0].function == "sum"
    assert agg.group_func[0].name == "cpu"
    assert agg.group_func[0].as_name == "cpus"
    assert agg.group_func[1].function == "count"
    assert agg.group_func[1].name == "id"
    assert agg.group_func[1].as_name == "instances"


def assert_round_trip(parser: Parser, obj: object, after_parsed: Optional[Callable[[Any], Any]] = None) -> None:
    str_rep = str(obj)
    parsed = parser.parse(str_rep)
    post = after_parsed(parsed) if after_parsed else parsed
    assert str(post) == str_rep, f"Expected: {str(post)} but got {str_rep}"
