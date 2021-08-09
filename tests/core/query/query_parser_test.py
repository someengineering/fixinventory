from typing import Callable, Optional, Any

from core.query.model import Navigation, Part, Query, P
from core.model.graph_access import EdgeType
from parsy import Parser
from core.query.query_parser import (
    predicate_term,
    isinstance_term,
    function_term,
    combined_term,
    term_parser,
    navigation_parser,
    part_parser,
    query_parser,
    preambleP,
)


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
    assert_round_trip(isinstance_term, P.of_kind("foo"))


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
        Query.by("ec2", P("cpu") > 4, (P("mem") < 23) | (P("mem") < 59))
        .traverse_out()
        .filter(P("some.int.value") < 1, P("some.other") == 23)
        .traverse_out()
        .filter(P("active") == 12, P.function("in_subnet").on("ip", "1.2.3.4/96"))
    )
    assert_round_trip(query_parser, query)


def test_query_with_preamble() -> None:
    query = query_parser.parse('edge_type=delete: id("root") -[0:1]->')
    assert query.parts[0].navigation.edge_type == "delete"


def test_preamble() -> None:
    assert preambleP.parse("edge_type=foo:") == {"edge_type": "foo"}
    assert preambleP.parse('edge_type="!@#*(&$({{:::":') == {"edge_type": "!@#*(&$({{:::"}


def assert_round_trip(parser: Parser, obj: object, after_parsed: Optional[Callable[[Any], Any]] = None) -> None:
    str_rep = str(obj)
    parsed = parser.parse(str_rep)
    post = after_parsed(parsed) if after_parsed else parsed
    assert str(post) == str_rep, f"Expected: {str(post)} but got {str_rep}"
