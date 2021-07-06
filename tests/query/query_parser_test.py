from core.query.model import P
from core.query.query_parser import *


# noinspection PyTypeChecker
def test_parse_predicate():
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
def test_parse_predicate_array():
    # TODO: array params are not working
    assert_round_trip(predicate_term, P.array("mem").for_any() < 23)


def test_kind():
    assert_round_trip(isinstance_term, P.of_kind("foo"))


# noinspection PyTypeChecker
def test_function():
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", 1, "2", True))
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", "in_subnet"))
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", "in_subnet", "1000"))


# noinspection PyTypeChecker
def test_combined():
    assert_round_trip(combined_term, P.of_kind("foo") | P.of_kind("bla"))


def test_term():
    assert_round_trip(term_parser, P("mem") < 23)
    assert_round_trip(term_parser, P.with_id("foo"))
    assert_round_trip(term_parser, P.of_kind("foo"))
    assert_round_trip(term_parser, P.of_kind("foo") | P.of_kind("bla"))
    assert_round_trip(term_parser, ((P.of_kind("foo") | P.of_kind("bla")) & (P("a") > 23)) & (P("b") <= 12))


def test_navigation():
    assert_round_trip(navigation_parser, Navigation())
    assert_round_trip(navigation_parser, Navigation(1, 1, "in"))
    assert_round_trip(navigation_parser, Navigation(1, 1, "out"))
    assert_round_trip(navigation_parser, Navigation(1, 10, "in"))
    assert_round_trip(navigation_parser, Navigation(1, 10, "out"))
    assert_round_trip(navigation_parser, Navigation(1, Navigation.Max, "out"))


# noinspection PyTypeChecker
def test_part():
    assert_round_trip(part_parser, Part(P.of_kind("test")))
    assert_round_trip(part_parser, Part(P.of_kind("test"), False, Navigation(1, 10)))
    assert_round_trip(part_parser, Part(P.of_kind("test"), True, Navigation(1, 10)))


def test_query():
    query = Query.by("ec2", P("cpu") > 4, (P("mem") < 23) | (P("mem") < 59)) \
        .traverse_out() \
        .filter(P("some.int.value") < 1, P("some.other") == 23) \
        .traverse_out() \
        .filter(P("active") == 12, P.function("in_subnet").on("ip", "1.2.3.4/96"))
    assert_round_trip(query_parser, query)


def assert_round_trip(parser: Parser, obj: object):
    str_rep = str(obj)
    parsed = parser.parse(str_rep)
    assert str(parsed) == str_rep, f"Expected: {str(parsed)} but got {str_rep}"
