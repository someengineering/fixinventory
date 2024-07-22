from fixcore.db.arango_query_rewrite import rewrite_query
from fixcore.db.model import QueryModel
from fixcore.model.model import Model
from fixcore.query.query_parser import parse_query


def test_is_rewrite(person_model: Model) -> None:
    q = rewrite_query(QueryModel(parse_query("reported.city = Gotham"), person_model))
    assert str(q) == '(is("Address") and reported.city == "Gotham")'
    q = rewrite_query(QueryModel(parse_query("reported.city=Gotham or reported.name=Batman"), person_model))
    assert str(q) == '((is("Address") and reported.city == "Gotham") or (is("Person") and reported.name == "Batman"))'
    # Further improvement: check if the kinds have a relationship: if not blow up like this case
    q = rewrite_query(QueryModel(parse_query("reported.city=Gotham and reported.name=Batman"), person_model))
    assert str(q) == '(is(["Address", "Person"]) and (reported.city == "Gotham" and reported.name == "Batman"))'


def test_no_rewrite(person_model: Model) -> None:
    # if an is clause is defined, accept it as is
    q = rewrite_query(QueryModel(parse_query("is(graph_root) and reported.city = Gotham"), person_model))
    assert str(q) == '(is("graph_root") and reported.city == "Gotham")'
    # first term has an is clause, second term does not
    q = rewrite_query(
        QueryModel(parse_query("(is(graph_root) and reported.city=Gotham) or reported.name=Batman"), person_model)
    )
    assert (
        str(q) == '((is("graph_root") and reported.city == "Gotham") or (is("Person") and reported.name == "Batman"))'
    )
    # all terms have an is clause, do not change
    q = rewrite_query(
        QueryModel(
            parse_query("(is(graph_root) and reported.city=Gotham) and (is(graph_root) and reported.name=Batman)"),
            person_model,
        )
    )
    assert (
        str(q)
        == '((is("graph_root") and reported.city == "Gotham") and (is("graph_root") and reported.name == "Batman"))'
    )
