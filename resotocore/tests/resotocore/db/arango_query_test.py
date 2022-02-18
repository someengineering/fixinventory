import pytest

from resotocore.db import EstimatedSearchCost, EstimatedQueryCostRating
from resotocore.db.arango_query import to_query, query_cost, fulltext_term_combine
from resotocore.db.graphdb import GraphDB
from resotocore.db.model import QueryModel
from resotocore.model.model import Model
from resotocore.query.model import Query

from resotocore.query.query_parser import parse_query

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import foo_kinds, foo_model, test_db, graph_db, system_db, local_client


def test_sort_order_for_synthetic_prop(foo_model: Model, graph_db: GraphDB) -> None:
    def check_sort_in_query(q: Query, expected_sort: str) -> None:
        query_str, _ = to_query(graph_db, QueryModel(q, foo_model))
        assert f"SORT {expected_sort}" in query_str, f"Expected {expected_sort} in {query_str}"

    check_sort_in_query(Query.by("foo").add_sort("reported.age"), "m0.reported.ctime desc")
    check_sort_in_query(Query.by("foo").add_sort("some.age"), "m0.some.age asc")
    check_sort_in_query(Query.by("foo").add_sort("reported.ctime"), "m0.reported.ctime asc")
    check_sort_in_query(Query.by("foo").add_sort("metadata.expired"), "m0.metadata.expired asc")


@pytest.mark.asyncio
async def test_query_cost(foo_model: Model, graph_db: GraphDB) -> None:
    async def cost(query_str: str) -> EstimatedSearchCost:
        query = parse_query(query_str)
        return await query_cost(graph_db, QueryModel(query, foo_model), False)

    c1 = await cost("aggregate(sum(1) as count):is(base) sort count asc")
    assert c1.full_collection_scan is False
    assert c1.rating is EstimatedQueryCostRating.simple

    c2 = await cost("is(base) sort count asc")
    assert c2.full_collection_scan is False
    assert c2.rating is EstimatedQueryCostRating.simple

    c3 = await cost("all sort reported.name asc")
    assert c3.full_collection_scan is True
    assert c3.rating is EstimatedQueryCostRating.complex

    c4 = await cost("all {parents: <-[0:]-} sort reported.name asc")
    assert c4.full_collection_scan is True
    assert c4.rating is EstimatedQueryCostRating.bad


def test_fulltext_term() -> None:
    part = parse_query("(a>0 and (foo and (b>1 and c>2 and d)))").parts[0]
    ft, remaining = fulltext_term_combine(part.term)
    assert str(remaining) == "((b > 1 and c > 2) and a > 0)"
    assert str(ft) == '("foo" and "d")'
    with pytest.raises(Exception):  # there are 2 fulltext terms or combined with something else
        fulltext_term_combine(parse_query("(a>0 and b) or (c and d)").parts[0].term)
    with pytest.raises(Exception):  # fulltext query after merge
        fulltext_term_combine(parse_query("a>0 {c: <--} fulltext").parts[0].term)
    with pytest.raises(Exception):  # fulltext in merge query
        fulltext_term_combine(parse_query("a>0 {c: <-- fulltext }").parts[0].term)
