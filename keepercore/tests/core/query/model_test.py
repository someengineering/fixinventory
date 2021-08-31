from core.query.model import P, Query, AllTerm, IsInstanceTerm


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
    Query.by(P.of_kind("ec2") & (P.array("some.array").for_all() > 12.23))
    Query.by(P.of_kind("ec2") & (P.array("some.array").for_any().is_in([1, 2, 3])))
    Query.by(P.of_kind("ec2") & (P.array("some.array").for_none() == 5))

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
        str(a) == '((isinstance("ec2") and cpu > 4) and (mem < 23 or mem < 59)) --> '
        "(some.int.value < 1 and some.other == 23) --> "
        '(active == 12 and in_subnet(ip, "1.2.3.4/32"))'
    )


def test_simplify() -> None:
    # some_criteria | all => all
    assert str((IsInstanceTerm("test") | AllTerm()).simplify()) == "all"
    # some_criteria & all => some_criteria
    assert str((IsInstanceTerm("test") & AllTerm()).simplify()) == 'isinstance("test")'
    # also works in nested setup
    q = Query.by(AllTerm() & ((P("test") == True) & (IsInstanceTerm("test") | AllTerm()))).simplify()
    assert (str(q)) == "test == true"
