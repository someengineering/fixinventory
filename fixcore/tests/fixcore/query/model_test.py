import pytest
from hypothesis import given, settings, HealthCheck

from fixcore.model.graph_access import Direction
from fixcore.query.model import (
    P,
    Query,
    AllTerm,
    IsTerm,
    PathRoot,
    Part,
    MergeQuery,
    Navigation,
    MergeTerm,
    NavigateUntilRoot,
    IdTerm,
    FulltextTerm,
    Predicate,
    NotTerm,
    FunctionTerm,
    Limit,
)
from fixcore.query.query_parser import parse_query
from tests.fixcore.query import query


def simple_reference() -> None:
    # only kind
    Query.by("ec2")

    # equality
    Query.by(P.of_kind("ec2") & (P("simple") == "hallo"))
    Query.by(P.of_kind("ec2") & (P("simple") != "hallo"))

    # regex
    Query.by(P.of_kind("ec2") & P("simple").matches("^some.regex[a-d]+$"))
    Query.by(P.of_kind("ec2") & P("simple").not_matches("^some.regex[a-d]+$"))

    # comparator
    Query.by(P.of_kind("ec2") & (P("num") > 23))
    Query.by(P.of_kind("ec2") & (P("num") >= 23))
    Query.by(P.of_kind("ec2") & (P("num") == 23))
    Query.by(P.of_kind("ec2") & (P("num") <= 23))
    Query.by(P.of_kind("ec2") & (P("num") < 23))

    # in set
    Query.by(P.of_kind("ec2") & P("num").is_in([1, 2, 5]))
    Query.by(P.of_kind("ec2") & P("num").is_not_in([1, 2, 5]))

    # array: all above operators are available
    Query.by(P.of_kind("ec2") & (P.array("some.array").for_all > 12.23))
    Query.by(P.of_kind("ec2") & (P.array("some.array").for_any.is_in([1, 2, 3])))
    Query.by(P.of_kind("ec2") & (P.array("some.array").for_none == 5))

    # call a function
    Query.by(P.function("in_subnet").on("ip", "1.2.3.4/16"))

    # refine with multiple predicates (all predicates have to match)
    Query.by(P.of_kind("ec2") & P("a").ge(1), P("b") == 2, P("c").matches("aaa"))


def test_simple_query() -> None:
    a = (
        Query.by("ec2", P("cpu") > 4, (P("mem") < 23) | (P("mem") < 59))
        .traverse_out()
        .filter(P("some.int.value") < 1, P("some.other") == 23)
        .traverse_out()
        .filter(P("active") == 12, P.function("in_subnet").on("ip", "1.2.3.4/32"))
    )

    assert (
        str(a) == '((is("ec2") and cpu > 4) and (mem < 23 or mem < 59)) -default-> '
        "(some.int.value < 1 and some.other == 23) -default-> "
        '(active == 12 and in_subnet(ip, "1.2.3.4/32"))'
    )


def test_simplify() -> None:
    # some_criteria | all => all
    assert str((IsTerm(["test"]) | AllTerm())) == "all"
    # some_criteria & all => some_criteria
    assert str((IsTerm(["test"]) & AllTerm())) == 'is("test")'
    # also works in nested setup
    q = Query.by(AllTerm() & ((P("test") == True) & (IsTerm(["test"]) | AllTerm())))
    assert (str(q)) == "test == true"


def test_combine() -> None:
    query1 = Query.by(P("test") == True).traverse_out().combine(Query.by("foo")).combine(Query.by("bla"))
    assert str(query1) == 'test == true -default-> (is("foo") and is("bla"))'
    query2 = (
        Query.by(P("test") == True)
        .traverse_out()
        .combine(Query.by("foo").traverse_out())
        .combine(Query.by("bla").traverse_out())
    )
    assert str(query2) == 'test == true -default-> is("foo") -default-> is("bla") -default->'
    query3 = (
        Query.by(P("test") == True)
        .traverse_out()
        .filter("boo")
        .traverse_out()
        .filter("bar")
        .combine(Query.by("foo"))
        .combine(Query.by("bla"))
    )
    assert str(query3) == 'test == true -default-> is("boo") -default-> ((is("bar") and is("foo")) and is("bla"))'
    query4 = Query.by("a").with_limit(10).combine(Query.by("b").with_limit(2))
    assert query4.current_part.limit == Limit(0, 2)  # minimum is taken
    with pytest.raises(AttributeError):
        # can not combine 2 aggregations
        parse_query("aggregate(sum(1)): is(a)").combine(parse_query("aggregate(sum(1)): is(a)"))
    with pytest.raises(AttributeError):
        # can not combine 2 with statements
        parse_query("is(foo) with(empty, -default->)").combine(parse_query("is(bla) with(empty, -default->)"))
    # combining merge term queries needs special handling
    sq1 = parse_query("age > 23h").on_section()
    mq1 = parse_query("is(foo) {bla: --> is(bla)} bla.test=2").on_section()
    mq2 = parse_query("name==test {foo: --> is(foo)} foo.test=3").on_section()
    assert str(mq1.combine(mq2)) == (
        '(is("foo") and name == "test") '
        '{bla: all -default-> is("bla"), foo: all -default-> is("foo")} '
        "(bla.test == 2 and foo.test == 3)"
    )
    assert str(mq2.combine(mq1)) == (
        '(name == "test" and is("foo")) '
        '{foo: all -default-> is("foo"), bla: all -default-> is("bla")} '
        "(foo.test == 3 and bla.test == 2)"
    )
    assert str(mq1.combine(sq1)) == '(is("foo") and age > "23h") {bla: all -default-> is("bla")} bla.test == 2'
    assert str(sq1.combine(mq1)) == '(is("foo") and age > "23h") {bla: all -default-> is("bla")} bla.test == 2'
    assert str(mq2.combine(sq1)) == '(name == "test" and age > "23h") {foo: all -default-> is("foo")} foo.test == 3'
    assert str(sq1.combine(mq2)) == '(name == "test" and age > "23h") {foo: all -default-> is("foo")} foo.test == 3'


def test_on_section() -> None:
    query = parse_query(
        "aggregate(foo, bla, bar: sum(a) as a, sum(b) as b, sum(1) as c):"
        '(cpu > 4 and (mem < 23 or mem < 59)) with(any, <-- name == "test") sort mem asc --> '
        "(a < 1 and /metadata.b == 23) sort foo asc"
    )
    on_section = (
        "aggregate(r.foo, r.bla, r.bar: sum(r.a) as a, sum(r.b) as b, sum(1) as c):"
        '(r.cpu > 4 and (r.mem < 23 or r.mem < 59)) with(any, <-default- r.name == "test") sort r.mem asc -default-> '
        "(r.a < 1 and metadata.b == 23) sort r.foo asc"
    )
    with_section_r = query.on_section("r")
    # all variables are now prefixed with the section name
    assert str(with_section_r) == on_section
    # all variables that are prefixed with the section name have the section name removed -> reverse operation
    assert str(with_section_r.relative_to_section("r")) == str(query)
    # a query on section root does not change the query
    assert str(with_section_r.on_section(PathRoot)) == on_section
    # a query relative to section root does not change the query
    assert str(with_section_r.relative_to_section(PathRoot)) == on_section


def test_rewrite_usage() -> None:
    def check(query_str: str, expect_before: str, expect_after: str) -> None:
        before, after = parse_query(query_str).current_part.term.split_by_usage()
        assert str(before) == expect_before
        assert str(after) == expect_after

    # filter on a,b,c before the usage is evaluated
    check("usage.cpu.max>3 and ((a<1 and b>1) or c==3)", "((a < 1 and b > 1) or c == 3)", "usage.cpu.max > 3")
    # same query, but different order
    check("((a<1 and b>1) or c==3) and usage.cpu.max>3", "((a < 1 and b > 1) or c == 3)", "usage.cpu.max > 3")
    # usage on top level in combination with or can not be optimized
    check("usage.cpu.max>3 or ((a<1 and b>1) or c==3)", "all", "(usage.cpu.max > 3 or ((a < 1 and b > 1) or c == 3))")


def test_rewrite_ancestors_descendants() -> None:
    # a query without ancestor/descendants is not changed
    assert str(parse_query("(a<1 and b>1) or c==3")) == "((a < 1 and b > 1) or c == 3)"
    # a query with resolved ancestor is not changed
    assert (
        str(parse_query('a<1 and ancestors.cloud.reported.name=="test"').on_section())
        == '(a < 1 and ancestors.cloud.reported.name == "test")'
    )
    # the merge name is interpreted relative to the section
    assert (
        str(parse_query("a<1 {test: <-[1:]- is(account)}").on_section("reported"))
        == 'reported.a < 1 {reported.test: all <-default[1:]- is("account")}'
    )
    # the merge name is not interpreted relative to the section, when defined absolute
    assert (
        str(parse_query("a<1 {/test: <-[1:]- is(account)}").on_section("reported"))
        == 'reported.a < 1 {test: all <-default[1:]- is("account")}'
    )
    # a query with unknown ancestor creates a merge query
    assert (
        str(parse_query('a<1 and ancestors.cloud.reported.kind=="cloud"').on_section())
        == 'a < 1 {ancestors.cloud: all <-default[1:]- is("cloud")} ancestors.cloud.reported.kind == "cloud"'
    )
    # multiple ancestors are put into one merge query
    assert (
        str(
            parse_query(
                'a<1 and ancestors.cloud.reported.kind=="c" and ancestors.account.reported.kind=="a"'
            ).on_section()
        )
        == 'a < 1 {ancestors.cloud: all <-default[1:]- is("cloud"), '
        'ancestors.account: all <-default[1:]- is("account")} '
        '(ancestors.cloud.reported.kind == "c" and ancestors.account.reported.kind == "a")'
    )
    # existing merge queries are preserved
    assert (
        str(parse_query('a<1 {children[]: --> all} ancestors.cloud.reported.kind=="c"').on_section())
        == 'a < 1 {ancestors.cloud: all <-default[1:]- is("cloud"), children[]: all -default-> all} '
        'ancestors.cloud.reported.kind == "c"'
    )
    # predefined merge queries are preserved
    assert (
        str(parse_query('a<1 {ancestors.cloud: --> is(region)} ancestors.cloud.reported.kind=="c"').on_section())
        == 'a < 1 {ancestors.cloud: all -default-> is("region")} ancestors.cloud.reported.kind == "c"'
    )
    # This is an example of a horrible query: all entries have to be merged, before a filter can be applied
    assert (
        str(parse_query("(a<1 and b>1) or ancestors.d.c<1").on_section())
        == 'all {ancestors.d: all <-default[1:]- is("d")} ((a < 1 and b > 1) or ancestors.d.c < 1)'
    )
    # Test some special examples
    assert (
        str(parse_query("ancestors.d.c<1 and (a<1 or b>1) and /ancestors.a.b>1").on_section())
        == '(a < 1 or b > 1) {ancestors.d: all <-default[1:]- is("d"), ancestors.a: all <-default[1:]- is("a")} '
        "(ancestors.d.c < 1 and ancestors.a.b > 1)"
    )
    # the independent query terms are always in the pre-filter before the merge is applied
    assert (
        str(parse_query("(a<1 and b>1) and (c<d or /ancestors.d.c<1)").on_section())
        == str(parse_query("(c<d or /ancestors.d.c<1) and (a<1 and b>1)").on_section())
        == '(a < 1 and b > 1) {ancestors.d: all <-default[1:]- is("d")} (c < "d" or ancestors.d.c < 1)'
    )
    # multiple filters to the same kind only create one merge query
    assert (
        str(
            parse_query(
                "/ancestors.a.b<1 and ancestors.a.c>1 and ancestors.a.d=3 and ancestors.b.c>1 and a==1"
            ).on_section()
        )
        == 'a == 1 {ancestors.a: all <-default[1:]- is("a"), ancestors.b: all <-default[1:]- is("b")} '
        "(((ancestors.a.b < 1 and ancestors.a.c > 1) and ancestors.a.d == 3) and ancestors.b.c > 1)"
    )
    # aggregation queries with ancestors in the group variable trigger a merge
    assert (
        str(parse_query("aggregate(/ancestors.a.reported.name as a: sum(1)): is(volume)").on_section())
        == 'aggregate(ancestors.a.reported.name as a: sum(1)):is("volume") {ancestors.a: all <-default[1:]- is("a")}'
    )


def test_aggregation() -> None:
    q = parse_query('aggregate("{a.a}_{a.b}" as a, a.c.d as v: sum(a.c.e) as c): all')
    assert q.aggregate.property_paths() == {"a.a", "a.b", "a.c.d", "a.c.e"}  # type: ignore


def test_merge_query_creation() -> None:
    inbound = Navigation(1, Navigation.Max, direction=Direction.inbound)
    for_foo = Query([Part(IsTerm(["foo"])), Part(AllTerm(), navigation=inbound)])
    merge_foo = [MergeQuery("ancestors.foo", for_foo)]

    # merge_foo is created automatically
    assert Part(AllTerm()).merge_queries_for(["ancestors.foo.reported.bla"]) == merge_foo
    # merge_foo is already included and not added
    assert Part(MergeTerm(AllTerm(), merge_foo)).merge_queries_for(["ancestors.foo.reported.bla"]) == merge_foo
    # neither ancestors/descendants
    with pytest.raises(Exception):
        Part(AllTerm()).merge_queries_for(["unknown.foo.reported.bla"])
    # no path is given
    with pytest.raises(Exception):
        Part(AllTerm()).merge_queries_for(["ancestors.foo"])

    # rewrite for ancestors/descendants also work with additional properties
    assert (
        str(Query.by("test").rewrite_for_ancestors_descendants(["ancestors.kind.reported.prop", "test", "a"]))
        == 'is("test") {ancestors.kind: all <-default[1:]- is("kind")}'
    )
    assert (
        str(
            Query.by("test")
            .merge_with("ancestors.cloud", NavigateUntilRoot, IsTerm(["cloud"]))
            .rewrite_for_ancestors_descendants(["ancestors.kind.reported.prop", "test", "a"])
        )
        == 'is("test") {ancestors.kind: all <-default[1:]- is("kind"), ancestors.cloud: all <-default[1:]- is("cloud")}'
    )


def test_term_contains() -> None:
    term = parse_query('("test" or "fest") and (p>1 or p<2) {a: <-- is(foo)} not(a>23)').parts[0].term
    assert term.contains_term_type(IdTerm) is False
    assert term.contains_term_type(IsTerm) is True
    assert term.contains_term_type(FulltextTerm) is True
    assert term.contains_term_type(Predicate) is True
    assert term.contains_term_type(NotTerm) is True
    assert term.contains_term_type(FunctionTerm) is False


def test_context_predicates() -> None:
    query: Query = parse_query("a.b[*].{ a=2 and b[1].bla=3 and c.d[*].{ e=4 and f=5 } }")
    expected = ["a.b[*].a", "a.b[*].b[1].bla", "a.b[*].c.d[*].e", "a.b[*].c.d[*].f"]
    assert [str(a.name) for a in query.visible_predicates] == expected


def test_merge_term_combination() -> None:
    sq1 = parse_query("age > 23h").on_section().parts[0].term
    mq1 = parse_query("is(foo) {bla: --> is(bla)} bla.test=2").on_section().parts[0].term
    mq2 = parse_query("name==test {foo: --> is(foo)} foo.test=3").on_section().parts[0].term
    assert (
        str(mq1 | mq2) == '(is("foo") or name == "test") '
        '{bla: all -default-> is("bla"), foo: all -default-> is("foo")} '
        "(bla.test == 2 or foo.test == 3)"
    )
    assert (
        str(mq2 | mq1) == '(name == "test" or is("foo")) '
        '{foo: all -default-> is("foo"), bla: all -default-> is("bla")} '
        "(foo.test == 3 or bla.test == 2)"
    )
    assert (
        str(mq1 & mq2) == '(is("foo") and name == "test") '
        '{bla: all -default-> is("bla"), foo: all -default-> is("foo")} '
        "(bla.test == 2 and foo.test == 3)"
    )
    assert (
        str(mq2 & mq1) == '(name == "test" and is("foo")) '
        '{foo: all -default-> is("foo"), bla: all -default-> is("bla")} '
        "(foo.test == 3 and bla.test == 2)"
    )
    assert str(mq1 | sq1) == '(is("foo") or age > "23h") {bla: all -default-> is("bla")} bla.test == 2'
    assert str(sq1 | mq1) == '(is("foo") or age > "23h") {bla: all -default-> is("bla")} bla.test == 2'
    assert str(mq1 & sq1) == '(is("foo") and age > "23h") {bla: all -default-> is("bla")} bla.test == 2'
    assert str(sq1 & mq1) == '(is("foo") and age > "23h") {bla: all -default-> is("bla")} bla.test == 2'


@given(query)
@settings(max_examples=200, suppress_health_check=list(HealthCheck))
def test_generated_query(q: Query) -> None:
    assert q.structure()
