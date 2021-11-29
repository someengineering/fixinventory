from core.db.arango_query import to_query
from core.db.graphdb import GraphDB
from core.db.model import QueryModel
from core.model.model import Model
from core.query.model import Query

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import foo_kinds, foo_model, test_db, graph_db


def test_sort_order_for_synthetic_prop(foo_model: Model, graph_db: GraphDB) -> None:
    def check_sort_in_query(q: Query, expected_sort: str) -> None:
        query_str, _ = to_query(graph_db, QueryModel(q, foo_model))
        assert f"SORT {expected_sort}" in query_str, f"Expected {expected_sort} in {query_str}"

    check_sort_in_query(Query.by("foo").add_sort("reported.age"), "m0.reported.ctime desc")
    check_sort_in_query(Query.by("foo").add_sort("some.age"), "m0.some.age asc")
    check_sort_in_query(Query.by("foo").add_sort("reported.ctime"), "m0.reported.ctime asc")
    check_sort_in_query(Query.by("foo").add_sort("metadata.expired"), "m0.metadata.expired asc")
