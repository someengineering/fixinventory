from datetime import datetime, timedelta
from functools import partial
from typing import Callable, Optional, Any, List

import pytest
from attrs import evolve
from deepdiff import DeepDiff
from hypothesis import given, settings, HealthCheck
from parsy import Parser, ParseError
from pytest import approx

from fixcore import error
from fixcore.model.graph_access import EdgeTypes, Direction
from fixcore.query.model import (
    Navigation,
    Part,
    Query,
    P,
    AggregateVariable,
    Aggregate,
    AggregateFunction,
    IsTerm,
    IdTerm,
    Sort,
    WithClause,
    WithClauseFilter,
    AggregateVariableName,
    AggregateVariableCombined,
    AllTerm,
    MergeTerm,
    MergeQuery,
    FulltextTerm,
    CombinedTerm,
    Predicate,
    Limit,
    NotTerm,
    WithUsage,
)
from fixcore.query.query_parser import (
    predicate_term,
    is_term,
    function_term,
    combined_term,
    navigation_parser,
    part_parser,
    query_parser,
    preamble_parser,
    preamble_tags_parser,
    aggregate_group_variable_parser,
    aggregate_group_function_parser,
    aggregate_parser,
    id_term,
    sort_parser,
    limit_parser,
    with_clause_parser,
    not_term,
    term_parser,
    parse_query,
    context_term,
    with_usage_parser,
)
from fixcore.util import utc, parse_utc
from tests.fixcore.query import query


def test_parse_is_term() -> None:
    assert is_term.parse("is(test)") == IsTerm(["test"])
    assert is_term.parse("is(a, b, c)") == IsTerm(["a", "b", "c"])
    assert is_term.parse("is([a,b,c])") == IsTerm(["a", "b", "c"])
    assert is_term.parse("is(volume, instance)") == IsTerm(["volume", "instance"])
    assert_round_trip(is_term, IsTerm(["volume", "instance"]))
    assert_round_trip(is_term, IsTerm(["test"]))


def test_parse_id_term() -> None:
    assert id_term.parse('id("test")') == IdTerm(["test"])
    assert id_term.parse("id(test)") == IdTerm(["test"])
    assert id_term.parse("id(a,b,c)") == IdTerm(["a", "b", "c"])
    assert id_term.parse("id([a,b,c])") == IdTerm(["a", "b", "c"])


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


def test_all_term() -> None:
    assert_round_trip(query_parser, Query.by(AllTerm()))
    assert_round_trip(query_parser, Query.by(Query.mk_term(P("allow_users_to_change_password").eq(True))))


def test_parse_predicate_array() -> None:
    assert_round_trip(predicate_term, P.array("mem").for_any < 23)
    assert_round_trip(predicate_term, P.array("mem").for_all >= 23)
    assert_round_trip(predicate_term, P.array("mem").for_none.matches("foo.*"))
    assert_round_trip(predicate_term, P.array("num").for_any.is_in([1, 2, 5]))
    assert_round_trip(predicate_term, P.array("num").for_all.is_in([1, 2, 5]))
    assert_round_trip(predicate_term, P.array("num").for_none.is_in([1, 2, 5]))


def test_parse_context() -> None:
    assert context_term.parse("a.b[*].{ c<1 and d>2 }") == P.context("a.b[*]", P.single("c") < 1, P.single("d") > 2)
    assert_element = partial(assert_round_trip, context_term)
    assert_element(P.context("foo", P.single("mem") < 23))
    assert_element(P.context("foo", P.array("mem").for_all < 23, P.single("cpu") > 2))
    assert_element(P.context("foo", P.single("core") > 2, P.context("inner", P.array("c").for_any < 23)))


def test_kind() -> None:
    assert_round_trip(is_term, P.of_kind("foo"))


def test_function() -> None:
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", 1, "2", True))
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", "in_subnet"))
    assert_round_trip(function_term, P.function("in_subnet").on("foo.bla.bar", "in_subnet", "1000"))
    assert_round_trip(function_term, P.function("has_key").on("foo.bla.bar", "a", "b", "c"))
    assert_round_trip(function_term, P.function("has_key").on("foo.bla.bar", "a"))


def test_combined() -> None:
    assert_round_trip(combined_term, P.of_kind("foo") | P.of_kind("bla"))


def test_not() -> None:
    assert_round_trip(not_term, (P.with_id("foo") | P.of_kind("bla")).not_term())
    assert_round_trip(not_term, P.of_kind("bla").not_term())
    assert_round_trip(not_term, term_parser.parse("not(is(a) or not is(b) and not a>1 or not b<2 or not(a>1))"))
    # make sure not only negates the simple term, not the combined term
    assert term_parser.parse("not a==b and b==c") == CombinedTerm(NotTerm(P("a").eq("b")), "and", P("b").eq("c"))


def test_filter_term() -> None:
    assert_round_trip(term_parser, P("mem") < 23)
    assert_round_trip(term_parser, P.with_id("foo"))
    assert_round_trip(term_parser, P.of_kind("foo"))
    assert_round_trip(term_parser, P.of_kind("foo") | P.of_kind("bla"))
    assert_round_trip(
        term_parser,
        ((P.of_kind("foo") | P.of_kind("bla")) & (P("a") > 23)) & (P("b").is_in([1, 2, 3])) & (P("c").eq({"a": 123})),
    )


def test_fulltext_term() -> None:
    assert_round_trip(term_parser, FulltextTerm("test"))
    assert term_parser.parse('"foo"') == FulltextTerm("foo")
    # multiple strings are not allowed
    with pytest.raises(ParseError):
        term_parser.parse("foo bla bar")
    # multiple strings in quotes are allowed
    assert term_parser.parse('"foo bla bar"') == FulltextTerm("foo bla bar")
    # combined term can be parsed
    assert term_parser.parse('"foo" and test>3') == CombinedTerm(
        FulltextTerm("foo"), "and", Predicate("test", ">", 3, {})
    )
    assert term_parser.parse('a>1 and ("b" and (c<1 or "d") and "e") or "f" and g==2')


def test_merge_term() -> None:
    next_foo = Query.by(AllTerm()).traverse_in(until=Navigation.Max).filter("foo")
    query = Query.by(MergeTerm(Query.mk_term("bla"), [MergeQuery("foo123", next_foo)], Query.mk_term("bla")))
    assert_round_trip(term_parser, query)


def test_navigation_default() -> None:
    assert str(Navigation(1, 1)) == "-default->"
    assert str(Navigation(1, Navigation.Max)) == "-default[1:]->"


def test_navigation() -> None:
    for edge_type in EdgeTypes.all:
        # the default edge type is not rendered, so we set it explicitly to make the mapping homogeneous
        for start, until in [(0, 0), (1, 1), (5, 5), (1, 10), (1, Navigation.Max), (10, Navigation.Max)]:
            assert_round_trip(navigation_parser, Navigation(start, until, [edge_type], Direction.any, [edge_type]))
            for direction in Direction.all:
                assert_round_trip(navigation_parser, Navigation(start, until, [edge_type], direction))


def test_part() -> None:
    assert_round_trip(part_parser, Part(P.of_kind("test")))
    assert_round_trip(part_parser, Part(P.of_kind("test"), navigation=Navigation(1, 10, [EdgeTypes.delete])))
    assert_round_trip(part_parser, Part(P.of_kind("test"), "red", navigation=Navigation(1, 10, [EdgeTypes.delete])))
    with_clause = WithClause(WithClauseFilter("==", 0), Navigation(maybe_edge_types=[EdgeTypes.delete]))
    assert_round_trip(
        part_parser, Part(P.of_kind("test"), "green", with_clause, navigation=Navigation(1, 10, [EdgeTypes.delete]))
    )


def test_query() -> None:
    query = (
        Query.by(
            "ec2",
            P("cpu") > 4,
            (P("mem") < 23) | (P("mem") < 59) | P.context("foo[*]", P.single("mem") < 23, P.single("core") > 2),
        )
        .merge_with("cloud", Navigation(1, Navigation.Max, direction=Direction.inbound), Query.mk_term("cloud"))
        .traverse_out()
        .filter(P("some.int.value") < 1, P("some.other").eq(23))
        .traverse_out()
        .filter(P("active").eq(12), P.function("in_subnet").on("ip", "1.2.3.4/96"))
        .filter_with(WithClause(WithClauseFilter("==", 0), Navigation()))
        .group_by([AggregateVariable(AggregateVariableName("foo"))], [AggregateFunction("sum", "cpu")])
        .add_sort(Sort("test", "asc"))
        .with_limit(10)
    )
    assert str(query) == (
        'aggregate(foo: sum(cpu)):((is("ec2") and cpu > 4) and '
        "((mem < 23 or mem < 59) or foo[*].{(mem < 23 and core > 2)}))"
        ' {cloud: all <-default[1:]- is("cloud")} -default-> '
        "(some.int.value < 1 and some.other == 23) -default-> "
        '(active == 12 and in_subnet(ip, "1.2.3.4/96")) '
        "with(empty, -default->) sort test asc limit 10"
    )
    assert_round_trip(query_parser, query)


def test_special_queries() -> None:
    # unquoted date like test_date < @YESTERDAY
    assert str(parse_query("test_date < 2021-12-09")) == 'test_date < "2021-12-09"'


def test_query_with_preamble() -> None:
    parse_query('id("root")')  # no preamble
    # edge type can be defined in preamble
    q1 = parse_query('(edge_type=delete): id("root") -[0:1]->')
    assert q1.parts[0].navigation.edge_types == ["delete"]  # type: ignore
    # edge type can be defined via kwargs
    q2 = parse_query('id("root") -[0:1]->', dict(edge_type="delete"))
    assert q2.parts[0].navigation.edge_types == ["delete"]  # type: ignore
    # aggregation and preamble
    q3 = parse_query('aggregate(region: sum(cpu))(edge_type=delete): id("root") -[0:1]->')
    assert q3.aggregate.group_by[0].name == AggregateVariableName("region")  # type: ignore
    assert q3.aggregate.group_func[0].name == "cpu"  # type: ignore


def test_preamble_tags() -> None:
    assert preamble_tags_parser.parse("(edge_type=foo)") == {"edge_type": "foo"}
    assert preamble_tags_parser.parse("(edge_type=23)") == {"edge_type": 23}
    assert preamble_tags_parser.parse("(edge_type=23.123)") == {"edge_type": 23.123}
    assert preamble_tags_parser.parse("(edge_type=true)") == {"edge_type": True}
    assert preamble_tags_parser.parse("(edge_type=false)") == {"edge_type": False}
    assert preamble_tags_parser.parse('(edge_type="!@#*(&$({{:::")') == {"edge_type": "!@#*(&$({{:::"}
    assert preamble_parser.parse("") == (None, {})


def test_aggregate_group_variable() -> None:
    foo_var = AggregateVariableName("foo")
    bla_var = AggregateVariableName("bla")

    foo = aggregate_group_variable_parser.parse("foo")
    assert foo.name == foo_var
    assert foo.as_name is None

    bla = aggregate_group_variable_parser.parse("bla as bar")
    assert bla.name == bla_var
    assert bla.as_name == "bar"

    combined = aggregate_group_variable_parser.parse('"some_{foo}_{bla}_test" as foo_bar')
    assert combined.name == AggregateVariableCombined(["some_", foo_var, "_", bla_var, "_test"])
    assert combined.as_name == "foo_bar"


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
    assert boo.ops == (("*", 1024.12), ("+", 1))
    with pytest.raises(Exception):
        assert aggregate_group_function_parser.parse("sum(test / 3 +)")


def test_aggregate() -> None:
    agg: Aggregate = aggregate_parser.parse("aggregate(region: sum(cpu) as cpus, count(id) as instances)")
    assert len(agg.group_by) == 1
    assert agg.group_by[0].name == AggregateVariableName("region")
    assert len(agg.group_func) == 2
    assert agg.group_func[0].function == "sum"
    assert agg.group_func[0].name == "cpu"
    assert agg.group_func[0].as_name == "cpus"
    assert agg.group_func[1].function == "count"
    assert agg.group_func[1].name == "id"
    assert agg.group_func[1].as_name == "instances"
    agg2: Aggregate = aggregate_parser.parse("aggregate(count(id) as length)")
    assert agg2.group_by == []
    assert len(agg2.group_func) == 1


def test_sort_order() -> None:
    assert sort_parser.parse("sort foo") == [Sort("foo", "asc")]
    assert sort_parser.parse("sort foo asc") == [Sort("foo", "asc")]
    parsed = sort_parser.parse("sort foo asc, bla desc, bar")
    assert parsed == [Sort("foo", "asc"), Sort("bla", "desc"), Sort("bar", "asc")]
    assert_round_trip(query_parser, Query.by("test").add_sort(Sort("test")).add_sort(Sort("goo")))


def test_limit() -> None:
    assert limit_parser.parse("limit 23") == Limit(0, 23)
    assert limit_parser.parse("limit 3, 23") == Limit(3, 23)
    assert_round_trip(query_parser, Query.by("test").with_limit(23))


def test_with_clause() -> None:
    predicate_term.parse("foo == bla")
    wc: WithClause = with_clause_parser.parse("with(empty, -delete-> foo == bla and test > 23 with(any, -delete->))")
    assert wc.with_filter == WithClauseFilter("==", 0)
    assert wc.navigation == Navigation(maybe_edge_types=["delete"])
    assert str(wc.term) == '(foo == "bla" and test > 23)'
    assert str(wc.with_clause) == "with(any, -delete->)"
    term = Query.mk_term("foo", P("test").eq(23))
    clause_filter = WithClauseFilter(">", 23)
    nav = Navigation()

    def edge(wc: WithClause) -> WithClause:
        wcr = evolve(wc, with_clause=edge(wc.with_clause)) if wc.with_clause else wc
        return evolve(wcr, navigation=evolve(wcr.navigation, maybe_edge_types=[EdgeTypes.default]))

    assert_round_trip(with_clause_parser, WithClause(clause_filter, nav, term, WithClause(clause_filter, nav)), edge)
    assert_round_trip(with_clause_parser, WithClause(clause_filter, nav), edge)


def test_special_cases() -> None:
    with pytest.raises(error.ParseError):
        # parser was able to read: is(instance) and sort in "stance_cores"
        parse_query("is(instance) and sort instance_cores")

    # parser read the reversed option as separate part, so following query became 3 parts
    q = parse_query("all sort kind desc limit 1 reversed -default-> all sort kind asc")
    assert len(q.parts) == 2


def test_usage_parser() -> None:
    def test_usage(s: str, start: datetime, end: Optional[datetime], metrics: List[str]) -> None:
        usage: WithUsage = with_usage_parser.parse(s)
        assert usage.start_from_now().timestamp() == approx(start.timestamp(), abs=1)
        if end:
            assert usage.end is not None
            assert usage.end_from_now().timestamp() == approx(end.timestamp(), abs=1)
        assert usage.metrics == metrics

    oneweekago = utc() - timedelta(weeks=1)
    twoweekago = utc() - timedelta(weeks=2)
    at = parse_utc("2023-06-10T12:23:21Z")
    test_usage("with_usage(1w, a,b,c)", oneweekago, None, ["a", "b", "c"])
    test_usage("with_usage(2w::1w, a,b,c)", twoweekago, oneweekago, ["a", "b", "c"])
    test_usage("with_usage(2w::1w, [a,b,c])", twoweekago, oneweekago, ["a", "b", "c"])
    test_usage("with_usage(2023-06-10T12:23:21Z::1w, [a,b,c])", at, oneweekago, ["a", "b", "c"])
    test_usage("with_usage(2023-06-10T12:23:21Z::2023-06-10T12:23:21Z, [a,b,c])", at, at, ["a", "b", "c"])


@given(query)
@settings(max_examples=200, suppress_health_check=list(HealthCheck))
def test_generated_query(q: Query) -> None:
    assert str(q) == str(parse_query(str(q)))


def assert_round_trip(parser: Parser, obj: object, after_parsed: Optional[Callable[[Any], Any]] = None) -> None:
    str_rep = str(obj)
    parsed = parser.parse(str_rep)
    post = after_parsed(parsed) if after_parsed else parsed
    assert str(post) == str_rep, f"Expected: {str(post)} but got {str_rep}.\nDifference: {DeepDiff(obj, post)}"


def test_merge_query() -> None:
    # /ancestors syntax creates a merge query
    q = parse_query("is(bla) and /ancestors.foo.reported.name=test").on_section()
    assert str(q) == 'is("bla") {ancestors.foo: all <-default[1:]- is("foo")} ancestors.foo.reported.name == "test"'
    # defining an explicit merge overrides the created one
    q = parse_query('is("bla") {ancestors.foo: all <-default[2:]- is("boo")} ancestors.foo.reported.name == "test"').on_section()  # fmt: skip # noqa
    assert str(q) == 'is("bla") {ancestors.foo: all <-default[2:]- is("boo")} ancestors.foo.reported.name == "test"'
    # merge parts are optimized to be defined (and executed) as late as possible
    q = parse_query(
        'is(aws_s3_bucket) {account_setting: <-[0:]- is(aws_account) --> is(aws_s3_account_settings)} (account_setting.reported.bucket_public_access_block_configuration.{block_public_acls != true or ignore_public_acls != true or block_public_policy != true or restrict_public_buckets != true} and bucket_public_access_block_configuration.{block_public_acls != true or ignore_public_acls != true or block_public_policy != true or restrict_public_buckets != true}) and ((bucket_acl.grants[*].{permission in [READ, READ_ACP, WRITE, WRITE_ACP, FULL_CONTROL] and grantee.uri = "http://acs.amazonaws.com/groups/global/AllUsers"}) or (bucket_policy.Statement[*].{Effect = Allow and (Principal = "*" or Principal.AWS = "*" or Principal.CanonicalUser = "*") and (Action in ["s3:GetObject", "s3:PutObject", "s3:Get*", "s3:Put*", "s3:*", "*"] or Action[*] in ["s3:GetObject", "s3:PutObject", "s3:Get*", "s3:Put*", "s3:*", "*"])}))'  # noqa
    ).on_section()
    # the merge part is moved to the end of the query where it is required
    assert str(q) == '((is("aws_s3_bucket") and (bucket_acl.grants[*].{(permission in ["READ", "READ_ACP", "WRITE", "WRITE_ACP", "FULL_CONTROL"] and grantee.uri == "http://acs.amazonaws.com/groups/global/AllUsers")} or bucket_policy.Statement[*].{((Effect == "Allow" and ((Principal == "*" or Principal.AWS == "*") or Principal.CanonicalUser == "*")) and (Action in ["s3:GetObject", "s3:PutObject", "s3:Get*", "s3:Put*", "s3:*", "*"] or Action[*] in ["s3:GetObject", "s3:PutObject", "s3:Get*", "s3:Put*", "s3:*", "*"]))})) and bucket_public_access_block_configuration.{(((block_public_acls != true or ignore_public_acls != true) or block_public_policy != true) or restrict_public_buckets != true)}) {account_setting: all <-default[0:]- is("aws_account") -default-> is("aws_s3_account_settings")} account_setting.reported.bucket_public_access_block_configuration.{(((block_public_acls != true or ignore_public_acls != true) or block_public_policy != true) or restrict_public_buckets != true)}'  # fmt: skip # noqa
